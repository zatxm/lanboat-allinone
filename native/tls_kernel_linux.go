//go:build linux

package native

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"unsafe"
)

func kernelSocket(conn net.Conn) (syscall.RawConn, error) {
	for {
		switch c := conn.(type) {
		case *net.TCPConn:
			return c.SyscallConn()
		case *ownedConn:
			conn = c.Conn
		case *controllerWireConn:
			conn = c.Conn
		case *tlsFragmentConn:
			conn = c.Conn
		case *tlsRecordFragmentConn:
			conn = c.Conn
		default:
			return nil, errors.New("kernel TLS requires an unbuffered TCP socket")
		}
	}
}

func installKernelTLS(conn net.Conn, tls *stTLS13, tx, rx bool) (*kernelTLS, error) {
	raw, err := kernelSocket(conn)
	if err != nil {
		return nil, err
	}
	k := &kernelTLS{raw: raw, tx: tx, rx: rx}
collect:
	for c := conn; ; {
		switch wire := c.(type) {
		case *controllerWireConn:
			k.controllers = append(k.controllers, wire.c)
			c = wire.Conn
		case *ownedConn:
			c = wire.Conn
		case *tlsFragmentConn:
			c = wire.Conn
		case *tlsRecordFragmentConn:
			c = wire.Conn
		default:
			break collect
		}
	}
	var cause error
	err = raw.Control(func(fd uintptr) { cause = syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, 31, "tls\x00") })
	if err != nil {
		return nil, err
	}
	if cause != nil {
		return nil, fmt.Errorf("enable kernel TLS: %w", cause)
	}
	if tx {
		if err = k.setKey(tls, true); err != nil {
			return nil, err
		}
	}
	if rx {
		if err = k.setKey(tls, false); err != nil {
			return nil, err
		}
	}
	return k, nil
}

func (k *kernelTLS) setKey(tls *stTLS13, tx bool) error {
	var secret []byte
	var cipher *stRecordCipher
	direction := 2
	if tx {
		secret, cipher, direction = tls.clientSecret, tls.clientApp, 1
	} else {
		secret, cipher = tls.serverSecret, tls.serverApp
	}
	var keyType uint16
	switch tls.suite.id {
	case 0x1301:
		keyType = 51
	case 0x1302:
		keyType = 52
	case 0x1303:
		keyType = 54
	default:
		return errors.New("unsupported kernel TLS cipher")
	}
	key := tls.suite.expand(secret, "key", nil, tls.suite.keySize)
	defer clear(key)
	info := make([]byte, 4, 4+12+len(key)+8)
	binary.NativeEndian.PutUint16(info, 0x0304)
	binary.NativeEndian.PutUint16(info[2:], keyType)
	if keyType == 54 {
		info = append(info, cipher.iv...)
		info = append(info, key...)
	} else {
		info = append(info, cipher.iv[4:]...)
		info = append(info, key...)
		info = append(info, cipher.iv[:4]...)
	}
	info = binary.BigEndian.AppendUint64(info, cipher.sequence)
	defer clear(info)
	var cause error
	err := k.raw.Control(func(fd uintptr) {
		_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, fd, 282, uintptr(direction), uintptr(unsafe.Pointer(&info[0])), uintptr(len(info)), 0)
		if errno != 0 {
			cause = errno
		}
	})
	if err != nil {
		return err
	}
	if cause != nil {
		return fmt.Errorf("install kernel TLS key: %w", cause)
	}
	return nil
}

func (k *kernelTLS) send(kind byte, data []byte) (uint64, error) {
	control := make([]byte, syscall.CmsgSpace(1))
	header := (*syscall.Cmsghdr)(unsafe.Pointer(&control[0]))
	header.Level, header.Type = 282, 1
	header.SetLen(syscall.CmsgLen(1))
	control[syscall.CmsgLen(0)] = kind
	var records uint64
	for len(data) > 0 {
		var n int
		var cause error
		err := k.raw.Write(func(fd uintptr) bool {
			for {
				n, cause = syscall.SendmsgN(int(fd), data, control, nil, syscall.MSG_NOSIGNAL)
				if cause != syscall.EINTR {
					break
				}
			}
			return cause != syscall.EAGAIN && cause != syscall.EWOULDBLOCK
		})
		if err != nil {
			return records, err
		}
		if cause != nil {
			return records, cause
		}
		if n == 0 {
			return records, io.ErrShortWrite
		}
		for _, c := range k.controllers {
			c.wireDown.Add(int64(n))
		}
		records++
		data = data[n:]
	}
	return records, nil
}

func (k *kernelTLS) receive(data []byte) (byte, int, error) {
	control := make([]byte, syscall.CmsgSpace(1))
	var n, oob, flags int
	var cause error
	err := k.raw.Read(func(fd uintptr) bool {
		for {
			n, oob, flags, _, cause = syscall.Recvmsg(int(fd), data, control, 0)
			if cause != syscall.EINTR {
				break
			}
		}
		return cause != syscall.EAGAIN && cause != syscall.EWOULDBLOCK
	})
	if err != nil {
		return 0, 0, err
	}
	if cause != nil {
		return 0, 0, cause
	}
	if n == 0 {
		return 0, 0, io.EOF
	}
	if flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
		return 0, 0, errors.New("truncated kernel TLS record")
	}
	// Offloaded I/O bypasses wrapper Read/Write; count its plaintext bytes.
	for _, c := range k.controllers {
		c.wireUp.Add(int64(n))
	}
	kind := byte(23)
	messages, err := syscall.ParseSocketControlMessage(control[:oob])
	if err != nil {
		return 0, 0, err
	}
	for _, message := range messages {
		if message.Header.Level == 282 && message.Header.Type == 2 {
			if len(message.Data) != 1 {
				return 0, 0, errors.New("invalid kernel TLS record type")
			}
			kind = message.Data[0]
		}
	}
	return kind, n, nil
}
