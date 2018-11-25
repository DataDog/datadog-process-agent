package ebpf

import (
	"encoding/binary"
	"errors"
	"unsafe"
)

var (
	// ErrNotImplemented will be returned on non-linux environments like Windows and Mac OSX
	ErrNotImplemented = errors.New("BPF-based network tracing not implemented on non-linux systems")

	nativeEndian binary.ByteOrder
)

// In lack of binary.NativeEndian ...
func init() {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		nativeEndian = binary.LittleEndian
	} else {
		nativeEndian = binary.BigEndian
	}
}

// KERNEL_VERSION(a,b,c) = (a << 16) + (b << 8) + (c)
// Per https://github.com/torvalds/linux/blob/master/Makefile#L1187
func linuxKernelVersionCode(major, minor, patch uint32) uint32 {
	return (major << 16) + (minor << 8) + patch
}
