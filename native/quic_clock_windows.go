package native

import (
	"syscall"
	"time"
	"unsafe"
)

var quicCounter = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryPerformanceCounter").Addr()

// Go's Windows clock uses coarse interrupt ticks; BBR needs precise intervals.
var quicClock = func() struct {
	at               time.Time
	ticks, frequency int64
} {
	var clock struct {
		at               time.Time
		ticks, frequency int64
	}
	frequency := syscall.NewLazyDLL("kernel32.dll").NewProc("QueryPerformanceFrequency")
	if ok, _, err := syscall.SyscallN(frequency.Addr(), uintptr(unsafe.Pointer(&clock.frequency))); ok == 0 || clock.frequency <= 0 {
		panic("QUIC performance counter frequency: " + err.Error())
	}
	clock.at = time.Now()
	if ok, _, err := syscall.SyscallN(quicCounter, uintptr(unsafe.Pointer(&clock.ticks))); ok == 0 {
		panic("QUIC performance counter: " + err.Error())
	}
	return clock
}()

func quicNow() time.Time {
	var ticks int64
	if ok, _, err := syscall.SyscallN(quicCounter, uintptr(unsafe.Pointer(&ticks))); ok == 0 {
		panic("QUIC performance counter: " + err.Error())
	}
	elapsed := ticks - quicClock.ticks
	delta := time.Duration(elapsed/quicClock.frequency)*time.Second + time.Duration(elapsed%quicClock.frequency)*time.Second/time.Duration(quicClock.frequency)
	return quicClock.at.Add(delta)
}
