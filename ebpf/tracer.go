// +build linux_bpf

package ebpf

import (
	"bytes"
	"fmt"
	"time"
	"unsafe"

	bpflib "github.com/iovisor/gobpf/elf"
)

/*
#include "c/tracer-ebpf.h"
*/
import "C"

var (
	// Feature versions sourced from: https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
	// Minimum kernel version -> max(3.15 - eBPF,
	//                               3.18 - tables/maps,
	//                               4.1 - kprobes,
	//                               4.3 - perf events)
	// 	                      -> 4.3
	minRequiredKernelCode = linuxKernelVersionCode(4, 3, 0)
)

type Tracer struct {
	m      *bpflib.Module
	config *Config
}

// maxActive configures the maximum number of instances of the kretprobe-probed functions handled simultaneously.
// This value should be enough for typical workloads (e.g. some amount of processes blocked on the accept syscall).
const maxActive = 128

// CurrentKernelVersion exposes calculated kernel version - exposed in LINUX_VERSION_CODE format
// That is, for kernel "a.b.c", the version number will be (a<<16 + b<<8 + c)
func CurrentKernelVersion() (uint32, error) {
	return bpflib.CurrentKernelVersion()
}

// IsTracerSupportedByOS returns whether or not the current kernel version supports tracer functionality
func IsTracerSupportedByOS() (bool, error) {
	currentKernelCode, err := bpflib.CurrentKernelVersion()
	if err != nil {
		return false, err
	}

	if currentKernelCode < minRequiredKernelCode {
		return false, fmt.Errorf("incompatible linux version. at least %d required, got %d", minRequiredKernelCode, currentKernelCode)
	}
	return true, nil
}

func NewTracer(config *Config) (*Tracer, error) {
	m, err := loadBPFModule()
	if err != nil {
		return nil, err
	}

	// TODO: This currently loads all defined BPF maps in the ELF file. we should load only the maps
	//       for connection types + families that are enabled.
	err = m.Load(nil)
	if err != nil {
		return nil, err
	}

	// Use the config to determine what kernel probes should be enabled
	enabledProbes := config.EnabledKProbes()
	for k := range m.IterKprobes() {
		if _, ok := enabledProbes[KProbeName(k.Name)]; ok {
			if err = m.EnableKprobe(k.Name, maxActive); err != nil {
				return nil, err
			}
		}
	}

	// TODO: Disable TCPv{4,6} connect kernel probes once offsets have been figured out.
	if err := guess(m, config); err != nil {
		return nil, fmt.Errorf("failed to init module: error guessing offsets: %v", err)
	}

	return &Tracer{m: m, config: config}, nil
}

func (t *Tracer) Stop() {
	t.m.Close()
}

func (t *Tracer) GetActiveConnections() (*Connections, error) {
	var tV4, tV6, uV4, uV6 []ConnectionStats
	var err error

	if t.config.CollectTCPConns {
		tV4, err = t.getTCPv4Connections()
		if err != nil {
			return nil, err
		}

		if t.config.CollectIPv6Conns {
			tV6, err = t.getTCPv6Connections()
			if err != nil {
				return nil, err
			}
		}
	}

	if t.config.CollectUDPConns {
		uV4, err = t.getUDPv4Connections()
		if err != nil {
			return nil, err
		}

		if t.config.CollectIPv6Conns {
			uV6, err = t.getUDPv6Connections()
			if err != nil {
				return nil, err
			}
		}
	}

	conns := append(tV4, append(tV6, append(uV4, uV6...)...)...)

	return &Connections{Conns: conns}, nil
}

func (t *Tracer) getUDPv4Connections() ([]ConnectionStats, error) {
	return t.getV4Connections(v4UDPMap, t.config.UDPConnTimeout)
}

func (t *Tracer) getUDPv6Connections() ([]ConnectionStats, error) {
	return t.getV4Connections(v6UDPMap, t.config.UDPConnTimeout)
}

func (t *Tracer) getTCPv4Connections() ([]ConnectionStats, error) {
	return t.getV4Connections(v4TCPMap, t.config.TCPConnTimeout)
}

func (t *Tracer) getTCPv6Connections() ([]ConnectionStats, error) {
	return t.getV6Connections(v6TCPMap, t.config.TCPConnTimeout)
}

func (t *Tracer) getV4Connections(name bpfMapName, timeout time.Duration) ([]ConnectionStats, error) {
	mp, err := t.getMap(name)
	if err != nil {
		return nil, err
	}

	latestTime, ok, err := t.getLatestTimestamp()
	if err != nil {
		return nil, err
	}

	if !ok { // if no timestamps have been captured, there can be no packets
		return nil, nil
	}

	// Iterate through all key-value pairs in map
	key, nextKey, stats := &ConnTupleV4{}, &ConnTupleV4{}, &ConnStatsWithTimestamp{}
	active := make([]ConnectionStats, 0)
	expired := make([]*ConnTupleV4, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(stats))
		if !hasNext {
			break
		} else if stats.isExpired(latestTime, timeout.Nanoseconds()) {
			expired = append(expired, nextKey.copy())
		} else {
			active = append(active, connStatsFromV4(nextKey, stats))
		}
		key = nextKey
	}

	// Remove expired entries
	for i := range expired {
		t.m.DeleteElement(mp, unsafe.Pointer(expired[i]))
	}

	return active, nil
}

func (t *Tracer) getV6Connections(name bpfMapName, timeout time.Duration) ([]ConnectionStats, error) {
	mp, err := t.getMap(name)
	if err != nil {
		return nil, err
	}

	latestTime, ok, err := t.getLatestTimestamp()
	if err != nil {
		return nil, err
	}

	if !ok { // if no timestamps have been captured, there can be no packets
		return nil, nil
	}

	// Iterate through all key-value pairs in map
	key, nextKey, stats := &ConnTupleV6{}, &ConnTupleV6{}, &ConnStatsWithTimestamp{}
	active := make([]ConnectionStats, 0)
	expired := make([]*ConnTupleV6, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(stats))
		if !hasNext {
			break
		} else if stats.isExpired(latestTime, timeout.Nanoseconds()) {
			expired = append(expired, nextKey.copy())
		} else {
			active = append(active, connStatsFromV6(nextKey, stats))
		}
		key = nextKey
	}

	for i := range expired {
		t.m.DeleteElement(mp, unsafe.Pointer(expired[i]))
	}

	return active, nil
}

// getLatestTimestamp reads the most recent timestamp captured by the eBPF
// module.  if the eBFP module has not yet captured a timestamp (as will be the
// case if the eBPF module has just started), the second return value will be
// false.
func (t *Tracer) getLatestTimestamp() (int64, bool, error) {
	tsMp, err := t.getMap(latestTimestampMap)
	if err != nil {
		return 0, false, err
	}

	var latestTime int64
	if err := t.m.LookupElement(tsMp, unsafe.Pointer(&zero), unsafe.Pointer(&latestTime)); err != nil {
		// If we can't find latest timestamp, there probably haven't been any messages yet
		return 0, false, nil
	}

	return latestTime, true, nil
}

func (t *Tracer) getMap(name bpfMapName) (*bpflib.Map, error) {
	mp := t.m.Map(string(name))
	if mp == nil {
		return nil, fmt.Errorf("no map with name %s", name)
	}
	return mp, nil
}

func loadBPFModule() (*bpflib.Module, error) {
	buf, err := Asset("tracer-ebpf.o")
	if err != nil {
		return nil, fmt.Errorf("couldn't find asset: %s", err)
	}

	m := bpflib.NewModuleFromReader(bytes.NewReader(buf))
	if m == nil {
		return nil, fmt.Errorf("BPF not supported")
	}
	return m, nil
}
