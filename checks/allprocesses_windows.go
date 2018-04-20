// +build windows

package checks

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/StackExchange/wmi"
	"github.com/shirou/w32"

	cpu "github.com/DataDog/gopsutil/cpu"
	process "github.com/DataDog/gopsutil/process"
	log "github.com/cihub/seelog"
)

const (
	NoMoreFiles   = 0x12
	MaxPathLength = 260
)

var (
	modpsapi                 = syscall.NewLazyDLL("psapi.dll")
	procGetProcessMemoryInfo = modpsapi.NewProc("GetProcessMemoryInfo")

	modkernel                 = syscall.NewLazyDLL("kernel32.dll")
	procGetProcessHandleCount = modkernel.NewProc("GetProcessHandleCount")
	procGetProcessIoCounters  = modkernel.NewProc("GetProcessIoCounters")
)

type SystemProcessInformation struct {
	NextEntryOffset   uint64
	NumberOfThreads   uint64
	Reserved1         [48]byte
	Reserved2         [3]byte
	UniqueProcessID   uintptr
	Reserved3         uintptr
	HandleCount       uint64
	Reserved4         [4]byte
	Reserved5         [11]byte
	PeakPagefileUsage uint64
	PrivatePageCount  uint64
	Reserved6         [6]uint64
}

type MemoryMapsStat struct {
}

type Win32_Process struct {
	Name                string
	ExecutablePath      *string
	CommandLine         *string
	Priority            uint32
	CreationDate        *time.Time
	ProcessID           uint32
	ThreadCount         uint32
	Status              *string
	ReadOperationCount  uint64
	ReadTransferCount   uint64
	WriteOperationCount uint64
	WriteTransferCount  uint64

	/*
		CSCreationClassName   string
		CSName                string
		Caption               *string
		CreationClassName     string
		Description           *string
		ExecutionState        *uint16
		HandleCount           uint32
		KernelModeTime        uint64
		MaximumWorkingSetSize *uint32
		MinimumWorkingSetSize *uint32
		OSCreationClassName   string
		OSName                string
		OtherOperationCount   uint64
		OtherTransferCount    uint64
		PageFaults            uint32
		PageFileUsage         uint32
		ParentProcessID       uint32
		PeakPageFileUsage     uint32
		PeakVirtualSize       uint64
		PeakWorkingSetSize    uint32
		PrivatePageCount      uint64
		TerminationDate       *time.Time
		UserModeTime          uint64
		WorkingSetSize        uint64
	*/
}

type IO_COUNTERS struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

func getProcessMemoryInfo(h syscall.Handle, mem *process.PROCESS_MEMORY_COUNTERS) (err error) {
	r1, _, e1 := syscall.Syscall(procGetProcessMemoryInfo.Addr(), 3, uintptr(h), uintptr(unsafe.Pointer(mem)), uintptr(unsafe.Sizeof(*mem)))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}
func getProcessHandleCount(h syscall.Handle, count *uint32) (err error) {
	r1, _, e1 := procGetProcessHandleCount.Call(uintptr(h), uintptr(unsafe.Pointer(count)))
	if r1 == 0 {
		return e1
	}
	return nil
}

func getProcessIoCounters(h syscall.Handle, counters *IO_COUNTERS) (err error) {
	r1, _, e1 := procGetProcessIoCounters.Call(uintptr(h), uintptr(unsafe.Pointer(counters)))
	if r1 == 0 {
		return e1
	}
	return nil
}

func getProcessMapFromWmi() (map[uint32]Win32_Process, error) {
	var dst []Win32_Process
	q := wmi.CreateQuery(&dst, "")
	err := wmi.Query(q, &dst)
	if err != nil {
		return map[uint32]Win32_Process{}, err
	}
	if len(dst) == 0 {
		return map[uint32]Win32_Process{}, fmt.Errorf("could not get Process")
	}
	results := make(map[uint32]Win32_Process)
	for _, proc := range dst {
		results[proc.ProcessID] = proc
	}
	return results, nil

}
func getAllProcesses() (map[int32]*process.FilledProcess, error) {
	allProcsSnap := w32.CreateToolhelp32Snapshot(w32.TH32CS_SNAPPROCESS, 0)
	if allProcsSnap == 0 {
		return nil, syscall.GetLastError()
	}
	procs := make(map[int32]*process.FilledProcess)

	defer w32.CloseHandle(allProcsSnap)
	var pe32 w32.PROCESSENTRY32
	pe32.DwSize = uint32(unsafe.Sizeof(pe32))

	fromWmi, _ := getProcessMapFromWmi()

	for success := w32.Process32First(allProcsSnap, &pe32); success; success = w32.Process32Next(allProcsSnap, &pe32) {
		pid := pe32.Th32ProcessID
		ppid := pe32.Th32ParentProcessID

		// 0x1000 is PROCESS_QUERY_LIMITED_INFORMATION, but that constant isn't
		// defined in syscall
		procHandle, err := syscall.OpenProcess(0x1000, false, uint32(pid))
		if err != nil {
			continue
		}
		defer syscall.CloseHandle(procHandle)

		var CPU syscall.Rusage
		if err = syscall.GetProcessTimes(procHandle, &CPU.CreationTime, &CPU.ExitTime, &CPU.KernelTime, &CPU.UserTime); err != nil {
			continue
		}

		var handleCount uint32
		if err = getProcessHandleCount(procHandle, &handleCount); err != nil {
			continue
		}

		var pmemcounter process.PROCESS_MEMORY_COUNTERS
		if err = getProcessMemoryInfo(procHandle, &pmemcounter); err != nil {
			continue
		}

		// shell out to getprocessiocounters for io stats
		var ioCounters IO_COUNTERS
		if err = getProcessIoCounters(procHandle, &ioCounters); err != nil {
			continue
		}
		ctime := CPU.CreationTime.Nanoseconds() / 1000000

		exebase := convert_windows_string(pe32.SzExeFile[:])
		cmdbase := *fromWmi[pid].CommandLine
		var parsedargs []string
		if len(cmdbase) == 0 {
			parsedargs = append(parsedargs, exebase)
		} else {
			parsedargs = parseCmdLineArgs(cmdbase)
		}

		utime := float64((int64(CPU.UserTime.HighDateTime) << 32) | int64(CPU.UserTime.LowDateTime))
		stime := float64((int64(CPU.KernelTime.HighDateTime) << 32) | int64(CPU.KernelTime.LowDateTime))
		username, err := get_username_for_process(procHandle)
		procs[int32(pid)] = &process.FilledProcess{
			Pid:     int32(pid),
			Ppid:    int32(ppid),
			Cmdline: parsedargs,
			CpuTime: cpu.TimesStat{
				User:      utime,
				System:    stime,
				Timestamp: time.Now().UnixNano(),
			},

			CreateTime:  ctime,
			OpenFdCount: int32(handleCount),
			//Name
			// Status
			// UIDS
			// GIDs
			NumThreads:  int32(pe32.CntThreads),
			CtxSwitches: &process.NumCtxSwitchesStat{},
			MemInfo: &process.MemoryInfoStat{
				RSS:  pmemcounter.WorkingSetSize,
				VMS:  pmemcounter.QuotaPagedPoolUsage,
				Swap: 0, // it's unclear there's a Windows measurement of swap file usage
			},
			//Cwd
			Exe: exebase,
			IOStat: &process.IOCountersStat{
				ReadCount:  ioCounters.ReadOperationCount,
				WriteCount: ioCounters.WriteOperationCount,
				ReadBytes:  ioCounters.ReadTransferCount,
				WriteBytes: ioCounters.WriteTransferCount,
			},
			Username: username,
		}
	}
	return procs, nil
}

func get_username_for_process(h syscall.Handle) (name string, err error) {
	name = ""
	err = nil
	var t syscall.Token
	err = syscall.OpenProcessToken(h, syscall.TOKEN_QUERY, &t)
	if err != nil {
		log.Debugf("Failed to open process token %v", err)
		return
	}
	defer t.Close()
	tokenUser, err := t.GetTokenUser()

	user, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	return domain + "\\" + user, err

}

func convert_windows_string(winput []uint16) string {
	var retstring string
	for i := 0; i < len(winput); i++ {
		if winput[i] == 0 {
			break
		}
		retstring += string(rune(winput[i]))
	}
	return retstring
}

func parseCmdLineArgs(cmdline string) (res []string) {

	blocks := strings.Split(cmdline, " ")
	findCloseQuote := false
	donestring := false
	var stringInProgress string
	for _, b := range blocks {
		numquotes := strings.Count(b, "\"")
		if numquotes == 0 {
			stringInProgress += b
			if !findCloseQuote {
				donestring = true
			}
		} else if numquotes == 1 {
			stringInProgress += strings.Trim(b, "\"")
			if findCloseQuote {
				donestring = true
			} else {
				findCloseQuote = true
			}
		} else if numquotes == 2 {
			stringInProgress = strings.Trim(b, "\"")
			donestring = true
		} else {
			log.Warnf("Unexpected qutoes in string, giving up")
			return res
		}
		if donestring {
			res = append(res, stringInProgress)
			stringInProgress = ""
			findCloseQuote = false
		}

	}
	return res
}
