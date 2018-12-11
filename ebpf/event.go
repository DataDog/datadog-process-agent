// +build linux_bpf

package ebpf

import (
	"encoding/binary"
	"net"
)

/*
#include "c/tracer-ebpf.h"
*/
import "C"

/* conn_tuple_t
__u64 saddr_h;
__u64 saddr_l;
__u64 daddr_h;
__u64 daddr_l;
__u16 sport;
__u16 dport;
__u32 netns;
__u32 pid;
__u32 metadata;
*/
type ConnTuple C.conn_tuple_t

func (t *ConnTuple) copy() *ConnTuple {
	return &ConnTuple{
		saddr_h:  t.saddr_h,
		saddr_l:  t.saddr_l,
		daddr_h:  t.daddr_h,
		daddr_l:  t.daddr_l,
		sport:    t.sport,
		dport:    t.dport,
		netns:    t.netns,
		pid:      t.pid,
		metadata: t.metadata,
	}
}

/* conn_stats_ts_t
__u64 send_bytes;
__u64 recv_bytes;
__u64 timestamp;
*/
type ConnStatsWithTimestamp C.conn_stats_ts_t

func (cs *ConnStatsWithTimestamp) isExpired(latestTime int64, timeout int64) bool {
	return latestTime-int64(cs.timestamp) > timeout
}

func connStats(t *ConnTuple, s *ConnStatsWithTimestamp) ConnectionStats {
	family := connFamily(t.metadata)
	return ConnectionStats{
		Pid:       uint32(t.pid),
		Type:      connType(t.metadata),
		Family:    family,
		Source:    ipString(uint64(t.saddr_h), uint64(t.saddr_l), family),
		Dest:      ipString(uint64(t.daddr_h), uint64(t.daddr_l), family),
		SPort:     uint16(t.sport),
		DPort:     uint16(t.dport),
		SendBytes: uint64(s.send_bytes),
		RecvBytes: uint64(s.recv_bytes),
	}
}

func ipString(addr_h, addr_l uint64, family ConnectionFamily) string {
	if family == AFINET {
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(addr_l))
		return net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
	}

	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf, uint64(addr_h))
	binary.LittleEndian.PutUint64(buf[8:], uint64(addr_l))
	return net.IP(buf).String()
}

func connType(m _Ctype_uint) ConnectionType {
	// First bit of metadata indicates if the connection is TCP or UDP
	if m&1 == 0 {
		return UDP
	}
	return TCP
}

func connFamily(m _Ctype_uint) ConnectionFamily {
	// Second bit of metadata indicates if the connection is IPv6 or IPv4
	if m&0x10 == 0 {
		return AFINET
	}

	return AFINET6
}
