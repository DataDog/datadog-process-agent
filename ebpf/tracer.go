// +build linux_bpf

package ebpf

import (
	"bytes"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/DataDog/dd-go/log"
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
	m       *bpflib.Module
	perfMap *bpflib.PerfMap
	config  *Config
	// Lock for the closedConns
	sync.Mutex
	closedConns   []ConnectionStats
	closedChannel chan []byte
	lostChannel   chan uint64
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

	// TODO clean this
	sections := make(map[string]bpflib.SectionParams)
	// TODO figure out this value
	sections[fmt.Sprintf("maps/%s", tcpCloseEventMap)] = bpflib.SectionParams{PerfRingBufferPageCount: 256}
	err = m.Load(sections)
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

	tr := &Tracer{
		m:             m,
		config:        config,
		closedConns:   []ConnectionStats{},
		closedChannel: make(chan []byte, 100),
		lostChannel:   make(chan uint64, 10),
	}

	tr.perfMap, err = tr.initPerfPolling()
	if err != nil {
		return nil, fmt.Errorf("could not start polling bpf events: %s", err)
	}

	return tr, nil
}

// initPerfPolling starts the listening on perf buffer events to grab closed connections
func (t *Tracer) initPerfPolling() (*bpflib.PerfMap, error) {
	pm, err := bpflib.InitPerfMap(t.m, string(tcpCloseEventMap), t.closedChannel, t.lostChannel)
	if err != nil {
		return nil, fmt.Errorf("error initializing perf map: %s", err)
	}

	pm.PollStart()

	go func() {
		// Stats about how much connections have been closed / lost
		var closedCount, lostCount uint64
		ticker := time.NewTicker(5 * time.Minute)

		for {
			select {
			case c, ok := <-t.closedChannel:
				if !ok {
					return
				}
				closedCount += 1
				stats := decodeRawTCPConn(c)

				t.Lock()
				t.closedConns = append(t.closedConns, stats)
				t.Unlock()

			case c, ok := <-t.lostChannel:
				if !ok {
					return
				}
				lostCount += c

			case <-ticker.C:
				log.Infof("Connection stats: %d losts, %d closed", lostCount, closedCount)
				closedCount = 0
				lostCount = 0
			}
		}
	}()

	return pm, nil
}

func (t *Tracer) Stop() {
	t.m.Close()
	t.perfMap.PollStop()
}

func (t *Tracer) GetActiveConnections() (*Connections, error) {
	conns, err := t.getConnections()
	if err != nil {
		return nil, err
	}

	return &Connections{Conns: conns}, nil
}

func (t *Tracer) getConnections() ([]ConnectionStats, error) {
	mp, err := t.getMap(connMap)
	if err != nil {
		return nil, fmt.Errorf("error retrieving the bpf %s map: %s", connMap, err)
	}

	tcpMp, err := t.getMap(tcpStatsMap)
	if err != nil {
		return nil, fmt.Errorf("error retrieving the bpf %s map: %s", tcpStatsMap, err)
	}

	latestTime, ok, err := t.getLatestTimestamp()
	if err != nil {
		return nil, err
	}

	if !ok { // if no timestamps have been captured, there can be no packets
		return nil, nil
	}

	// Iterate through all key-value pairs in map
	key, nextKey, stats := &ConnTuple{}, &ConnTuple{}, &ConnStatsWithTimestamp{}
	active := make([]ConnectionStats, 0)
	expired := make([]*ConnTuple, 0)
	for {
		hasNext, _ := t.m.LookupNextElement(mp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(stats))
		if !hasNext {
			break
		} else if stats.isExpired(latestTime, t.timeoutForConn(nextKey)) {
			expired = append(expired, nextKey.copy())
		} else {
			active = append(active, connStats(nextKey, stats, t.getTCPStats(tcpMp, nextKey)))
		}
		key = nextKey
	}

	// Remove expired entries
	t.removeEntries(mp, tcpMp, expired)

	// Add the shortlived connections
	// TODO make sure we don't have duplicates
	t.Lock()
	active = append(active, t.closedConns...)
	t.closedConns = []ConnectionStats{}
	t.Unlock()

	return active, nil
}

func (t *Tracer) removeEntries(mp, tcpMp *bpflib.Map, entries []*ConnTuple) {
	var e *ConnTuple
	for _, ent := range entries {
		e = ent
		// TODO check for errors
		t.m.DeleteElement(mp, unsafe.Pointer(e))

		// We have to remove the PID to remove the element from the TCP Map since we don't use the pid there
		e.pid = 0
		// We can ignore the error for this map since it will not always contain the entry
		t.m.DeleteElement(tcpMp, unsafe.Pointer(e))
	}
}

// getTCPStats reads tcp related stats for the given ConnTuple
func (t *Tracer) getTCPStats(mp *bpflib.Map, tuple *ConnTuple) *TCPStats {
	// Remove the PID since we don't use it in the TCP Stats map
	tup := tuple.copy()
	tup.pid = 0

	stats := &TCPStats{retransmits: 0}
	if err := t.m.LookupElement(mp, unsafe.Pointer(tup), unsafe.Pointer(stats)); err != nil {
		return stats
	}

	return stats
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

func (t *Tracer) timeoutForConn(c *ConnTuple) int64 {
	if connType(c.metadata) == TCP {
		return t.config.TCPConnTimeout.Nanoseconds()
	}
	return t.config.UDPConnTimeout.Nanoseconds()
}
