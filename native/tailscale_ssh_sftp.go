package native

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

type tsSFTPHandle struct {
	file      *os.File
	append    bool
	directory bool
}
type tsSFTPAttrs struct {
	flags                        uint32
	size                         uint64
	uid, gid, mode, atime, mtime uint32
}

func tsSFTPReadAttrs(r *sshReader) tsSFTPAttrs {
	a := tsSFTPAttrs{flags: r.u32()}
	if a.flags&^uint32(15) != 0 {
		r.err = errors.New("unsupported SFTP attributes")
		return a
	}
	if a.flags&1 != 0 {
		a.size = uint64(r.u32())<<32 | uint64(r.u32())
		if a.size > 1<<63-1 {
			r.err = errors.New("invalid SFTP file size")
		}
	}
	if a.flags&2 != 0 {
		a.uid, a.gid = r.u32(), r.u32()
	}
	if a.flags&4 != 0 {
		a.mode = r.u32()
	}
	if a.flags&8 != 0 {
		a.atime, a.mtime = r.u32(), r.u32()
	}
	return a
}
func tsSFTPMode(bits uint32) os.FileMode {
	mode := os.FileMode(bits & 0777)
	if bits&04000 != 0 {
		mode |= os.ModeSetuid
	}
	if bits&02000 != 0 {
		mode |= os.ModeSetgid
	}
	if bits&01000 != 0 {
		mode |= os.ModeSticky
	}
	return mode
}
func tsSFTPWriteAttrs(b []byte, info os.FileInfo) []byte {
	b = sshInt(b, 15)
	b = binary.BigEndian.AppendUint64(b, uint64(info.Size()))
	uid, gid, atime := tsSFTPMetadata(info)
	b = sshInt(sshInt(b, uid), gid)
	mode := uint32(info.Mode().Perm())
	switch {
	case info.IsDir():
		mode |= 040000
	case info.Mode()&os.ModeSymlink != 0:
		mode |= 0120000
	default:
		mode |= 0100000
	}
	if info.Mode()&os.ModeSetuid != 0 {
		mode |= 04000
	}
	if info.Mode()&os.ModeSetgid != 0 {
		mode |= 02000
	}
	if info.Mode()&os.ModeSticky != 0 {
		mode |= 01000
	}
	return sshInt(sshInt(sshInt(b, mode), atime), uint32(info.ModTime().Unix()))
}
func tsSFTPApplyAttrs(name string, f *os.File, a tsSFTPAttrs) error {
	if a.flags&2 != 0 {
		var e error
		if f != nil {
			e = f.Chown(int(a.uid), int(a.gid))
		} else {
			e = os.Chown(name, int(a.uid), int(a.gid))
		}
		if e != nil {
			return e
		}
	}
	if a.flags&4 != 0 {
		var e error
		if f != nil {
			e = f.Chmod(tsSFTPMode(a.mode))
		} else {
			e = os.Chmod(name, tsSFTPMode(a.mode))
		}
		if e != nil {
			return e
		}
	}
	if a.flags&1 != 0 {
		var e error
		if f != nil {
			e = f.Truncate(int64(a.size))
		} else {
			e = os.Truncate(name, int64(a.size))
		}
		if e != nil {
			return e
		}
	}
	if a.flags&8 != 0 {
		if f != nil {
			return tsSFTPChtimes(f, time.Unix(int64(a.atime), 0), time.Unix(int64(a.mtime), 0))
		}
		return os.Chtimes(name, time.Unix(int64(a.atime), 0), time.Unix(int64(a.mtime), 0))
	}
	return nil
}
func tsSFTP(input io.Reader, output io.Writer, audit io.Writer) error {
	handles := map[string]tsSFTPHandle{}
	defer func() {
		for _, h := range handles {
			h.file.Close()
		}
	}()
	write := func(b []byte) error { return writeAll(output, append(sshInt(nil, uint32(len(b))), b...)) }
	read := func() ([]byte, error) {
		var n [4]byte
		if _, e := io.ReadFull(input, n[:]); e != nil {
			return nil, e
		}
		size := binary.BigEndian.Uint32(n[:])
		if size < 1 || size > 256<<10 {
			return nil, errors.New("invalid SFTP packet length")
		}
		b := make([]byte, size)
		_, e := io.ReadFull(input, b)
		return b, e
	}
	b, e := read()
	if e != nil {
		return e
	}
	if len(b) < 5 || b[0] != 1 || binary.BigEndian.Uint32(b[1:]) < 3 {
		return errors.New("SFTP version3 required")
	}
	version := sshInt([]byte{2}, 3)
	for _, ext := range []string{"posix-rename@openssh.com", "fsync@openssh.com"} {
		version = sshText(sshText(version, ext), "1")
	}
	if e = write(version); e != nil {
		return e
	}
	for {
		b, e = read()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		if len(b) < 5 {
			return errors.New("short SFTP request")
		}
		kind, id := b[0], binary.BigEndian.Uint32(b[1:])
		if e = tsSFTPAudit(audit, kind, id, b[5:], handles); e != nil {
			return e
		}
		r := sshReader{b: b[5:]}
		result := []byte(nil)
		var operation error
		status := uint32(0)
		switch kind {
		case 3, 11: // OPEN / OPENDIR
			name := string(r.str())
			flags := uint32(0)
			attrs := tsSFTPAttrs{}
			if kind == 3 {
				flags = r.u32()
				attrs = tsSFTPReadAttrs(&r)
			}
			if r.err != nil || len(r.b) != 0 || len(handles) >= 128 || flags&^uint32(63) != 0 || kind == 3 && flags&3 == 0 {
				status = 5
				break
			}
			var f *os.File
			if kind == 11 {
				f, operation = os.Open(name)
			} else {
				mode := os.FileMode(0666)
				if attrs.flags&4 != 0 {
					mode = tsSFTPMode(attrs.mode)
				}
				open := os.O_RDONLY
				if flags&3 == 3 {
					open = os.O_RDWR
				} else if flags&2 != 0 {
					open = os.O_WRONLY
				}
				if flags&4 != 0 {
					open |= os.O_APPEND
				}
				if flags&8 != 0 {
					open |= os.O_CREATE
				}
				if flags&16 != 0 {
					open |= os.O_TRUNC
				}
				if flags&32 != 0 {
					open |= os.O_EXCL
				}
				f, operation = os.OpenFile(name, open, mode)
			}
			if operation != nil {
				break
			}
			if kind == 11 {
				info, err := f.Stat()
				if err != nil || !info.IsDir() {
					f.Close()
					operation = os.ErrInvalid
					break
				}
			}
			var key [16]byte
			if _, operation = rand.Read(key[:]); operation != nil {
				f.Close()
				break
			}
			handles[string(key[:])] = tsSFTPHandle{file: f, append: flags&4 != 0, directory: kind == 11}
			result = sshString(sshInt([]byte{102}, id), key[:])
		case 4, 5, 6, 8, 10, 12: // handle operations
			key := string(r.str())
			h, ok := handles[key]
			if !ok || r.err != nil {
				status = 9
				break
			}
			switch kind {
			case 4:
				if len(r.b) != 0 {
					status = 5
					break
				}
				delete(handles, key)
				operation = h.file.Close()
			case 5:
				offset := uint64(r.u32())<<32 | uint64(r.u32())
				length := r.u32()
				if r.err != nil || len(r.b) != 0 || offset > 1<<63-1 || length > 65536 || h.directory {
					status = 5
					break
				}
				data := make([]byte, length)
				n, err := h.file.ReadAt(data, int64(offset))
				if n == 0 && err != nil {
					operation = err
					break
				}
				result = sshString(sshInt([]byte{103}, id), data[:n])
			case 6:
				offset := uint64(r.u32())<<32 | uint64(r.u32())
				data := r.str()
				if r.err != nil || len(r.b) != 0 || offset > 1<<63-1 || h.directory {
					status = 5
					break
				}
				if h.append {
					_, operation = h.file.Write(data)
				} else {
					_, operation = h.file.WriteAt(data, int64(offset))
				}
			case 8:
				if len(r.b) != 0 {
					status = 5
					break
				}
				info, err := h.file.Stat()
				operation = err
				if err == nil {
					result = tsSFTPWriteAttrs(sshInt([]byte{105}, id), info)
				}
			case 10:
				a := tsSFTPReadAttrs(&r)
				if r.err != nil || len(r.b) != 0 {
					status = 5
					break
				}
				operation = tsSFTPApplyAttrs("", h.file, a)
			case 12:
				if len(r.b) != 0 || !h.directory {
					status = 5
					break
				}
				items, err := h.file.Readdir(64)
				if len(items) == 0 {
					operation = err
					break
				}
				result = sshInt(sshInt([]byte{104}, id), uint32(len(items)))
				for _, item := range items {
					result = tsSFTPWriteAttrs(sshText(sshText(result, item.Name()), item.Name()), item)
				}
			}
		case 7, 9, 13, 14, 15, 16, 17, 18, 19, 20:
			name := string(r.str())
			attrs := tsSFTPAttrs{}
			target := ""
			if kind == 9 || kind == 14 {
				attrs = tsSFTPReadAttrs(&r)
			}
			if kind == 18 || kind == 20 {
				target = string(r.str())
			}
			if r.err != nil || len(r.b) != 0 {
				status = 5
				break
			}
			switch kind {
			case 7, 17:
				var info os.FileInfo
				if kind == 7 {
					info, operation = os.Lstat(name)
				} else {
					info, operation = os.Stat(name)
				}
				if operation == nil {
					result = tsSFTPWriteAttrs(sshInt([]byte{105}, id), info)
				}
			case 9:
				operation = tsSFTPApplyAttrs(name, nil, attrs)
			case 13:
				operation = tsSFTPRemove(name, false)
			case 14:
				mode := os.FileMode(0777)
				if attrs.flags&4 != 0 {
					mode = tsSFTPMode(attrs.mode)
				}
				operation = os.Mkdir(name, mode)
			case 15:
				operation = tsSFTPRemove(name, true)
			case 16, 19:
				value := ""
				if kind == 16 {
					value, operation = filepath.Abs(name)
					if operation == nil {
						value, operation = filepath.EvalSymlinks(value)
					}
				} else {
					value, operation = os.Readlink(name)
				}
				if operation == nil {
					result = sshInt(sshInt([]byte{104}, id), 1)
					result = sshInt(sshText(sshText(result, value), value), 0)
				}
			case 18:
				// SFTPv3 RENAME must not overwrite an existing destination.
				if _, err := os.Lstat(target); err == nil {
					operation = os.ErrExist
				} else if !errors.Is(err, os.ErrNotExist) {
					operation = err
				} else {
					operation = tsSFTPRename(name, target, false)
				}
			case 20:
				operation = os.Symlink(name, target) // OpenSSH's deployed argument order.
			}
		case 200:
			extension := string(r.str())
			switch extension {
			case "posix-rename@openssh.com":
				name, target := string(r.str()), string(r.str())
				if r.err != nil || len(r.b) != 0 {
					status = 5
					break
				}
				operation = tsSFTPRename(name, target, true)
			case "fsync@openssh.com":
				h, ok := handles[string(r.str())]
				if r.err != nil || len(r.b) != 0 {
					status = 5
					break
				}
				if !ok {
					status = 9
					break
				}
				operation = h.file.Sync()
			default:
				status = 8
			}
		default:
			status = 8
		}
		if operation != nil {
			switch {
			case errors.Is(operation, io.EOF):
				status = 1
			case errors.Is(operation, os.ErrNotExist):
				status = 2
			case errors.Is(operation, os.ErrPermission):
				status = 3
			default:
				status = 4
			}
		}
		if r.err != nil {
			status = 5
		}
		if result == nil || status != 0 {
			result = sshText(sshText(sshInt(sshInt([]byte{101}, id), status), tsSFTPStatus(status)), "")
		}
		if audit != nil {
			if e = json.NewEncoder(audit).Encode(map[string]any{"id": id, "status": status}); e != nil {
				return e
			}
		}
		if e = write(result); e != nil {
			return e
		}
	}
}
func tsSFTPAudit(writer io.Writer, kind byte, id uint32, b []byte, handles map[string]tsSFTPHandle) error {
	if writer == nil {
		return nil
	}
	r := sshReader{b: b}
	row := map[string]any{"id": id, "operation": kind}
	logPath := func(value string) string { return value[:min(len(value), 4096)] }
	switch kind {
	case 4, 5, 6, 8, 10, 12:
		key := r.str()
		row["handle"] = hex.EncodeToString(key[:min(len(key), 32)])
		if h, ok := handles[string(key)]; ok {
			row["path"] = logPath(h.file.Name())
		}
		if kind == 5 || kind == 6 {
			row["offset"] = uint64(r.u32())<<32 | uint64(r.u32())
			if kind == 5 {
				row["bytes"] = r.u32()
			} else {
				row["bytes"] = len(r.str())
			}
		}
	case 3, 7, 9, 11, 13, 14, 15, 16, 17, 18, 19, 20:
		row["path"] = logPath(string(r.str()))
		if kind == 18 || kind == 20 {
			row["target"] = logPath(string(r.str()))
		}
	case 200:
		extension := string(r.str())
		row["extension"] = logPath(extension)
		if extension == "posix-rename@openssh.com" {
			row["path"] = logPath(string(r.str()))
			row["target"] = logPath(string(r.str()))
		}
	}
	if r.err != nil {
		row["malformed"] = true
	}
	return json.NewEncoder(writer).Encode(row)
}
func tsSFTPStatus(code uint32) string {
	switch code {
	case 0:
		return "OK"
	case 1:
		return "EOF"
	case 2:
		return "no such file"
	case 3:
		return "permission denied"
	case 5:
		return "invalid request"
	case 8:
		return "unsupported operation"
	case 9:
		return "invalid handle"
	default:
		return "file operation failed"
	}
}
func tsSFTPRemove(name string, directory bool) error {
	info, e := os.Lstat(name)
	if e != nil {
		return e
	}
	if info.IsDir() != directory {
		return os.ErrInvalid
	}
	return os.Remove(name)
}
