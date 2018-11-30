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

/*  struct_ipv4_tuple_t
__u32 saddr;
__u32 daddr;
__u16 sport;
__u16 dport;
__u32 netns;
__u32 pid;
*/
type ConnTupleV4 C.struct_ipv4_tuple_t

func (t *ConnTupleV4) copy() *ConnTupleV4 {
	return &ConnTupleV4{
		saddr: t.saddr,
		daddr: t.daddr,
		sport: t.sport,
		dport: t.dport,
		netns: t.netns,
		pid:   t.pid,
	}
}

/* struct_ipv6_tuple_t
__u64 saddr_h;
__u64 saddr_l;
__u64 daddr_h;
__u64 daddr_l;
__u16 sport;
__u16 dport;
__u32 netns;
__u32 pid;
*/
type ConnTupleV6 C.struct_ipv6_tuple_t

func (t *ConnTupleV6) copy() *ConnTupleV6 {
	return &ConnTupleV6{
		saddr_h: t.saddr_h,
		saddr_l: t.saddr_l,
		daddr_h: t.daddr_h,
		daddr_l: t.daddr_l,
		sport:   t.sport,
		dport:   t.dport,
		netns:   t.netns,
		pid:     t.pid,
	}
}

/* struct conn_stats_t
__u64 send_bytes;
__u64 recv_bytes;
*/
type ConnStats C.struct_conn_stats_t

/* struct conn_stats_ts_t
__u64 send_bytes;
__u64 recv_bytes;
__u64 timestamp;
*/
type ConnStatsWithTimestamp C.struct_conn_stats_ts_t

func (cs *ConnStatsWithTimestamp) isExpired(latestTime int64, timeout int64) bool {
	return latestTime-int64(cs.timestamp) > timeout
}

func connStatsFromTCPv4(t *ConnTupleV4, s *ConnStatsWithTimestamp) ConnectionStats {
	return ConnectionStats{
		Pid:       uint32(t.pid),
		Type:      TCP,
		Family:    AFINET,
		Source:    v4IPString(uint32(t.saddr)),
		Dest:      v4IPString(uint32(t.daddr)),
		SPort:     uint16(t.sport),
		DPort:     uint16(t.dport),
		SendBytes: uint64(s.send_bytes),
		RecvBytes: uint64(s.recv_bytes),
	}
}

func connStatsFromTCPv6(t *ConnTupleV6, s *ConnStatsWithTimestamp) ConnectionStats {
	return ConnectionStats{
		Pid:       uint32(t.pid),
		Type:      TCP,
		Family:    AFINET6,
		Source:    v6IPString(uint64(t.saddr_h), uint64(t.saddr_l)),
		Dest:      v6IPString(uint64(t.daddr_h), uint64(t.daddr_l)),
		SPort:     uint16(t.sport),
		DPort:     uint16(t.dport),
		SendBytes: uint64(s.send_bytes),
		RecvBytes: uint64(s.recv_bytes),
	}
}

func connStatsFromUDPv4(t *ConnTupleV4, s *ConnStatsWithTimestamp) ConnectionStats {
	return ConnectionStats{
		Pid:       uint32(t.pid),
		Type:      UDP,
		Family:    AFINET,
		Source:    v4IPString(uint32(t.saddr)),
		Dest:      v4IPString(uint32(t.daddr)),
		SPort:     uint16(t.sport),
		DPort:     uint16(t.dport),
		SendBytes: uint64(s.send_bytes),
		RecvBytes: uint64(s.recv_bytes),
	}
}

func connStatsFromUDPv6(t *ConnTupleV6, s *ConnStatsWithTimestamp) ConnectionStats {
	return ConnectionStats{
		Pid:       uint32(t.pid),
		Type:      UDP,
		Family:    AFINET6,
		Source:    v6IPString(uint64(t.saddr_h), uint64(t.saddr_l)),
		Dest:      v6IPString(uint64(t.daddr_h), uint64(t.daddr_l)),
		SPort:     uint16(t.sport),
		DPort:     uint16(t.dport),
		SendBytes: uint64(s.send_bytes),
		RecvBytes: uint64(s.recv_bytes),
	}
}

func v4IPString(addr uint32) string {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(addr))
	return net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
}

func v6IPString(addr_h, addr_l uint64) string {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf, uint64(addr_h))
	binary.LittleEndian.PutUint64(buf[8:], uint64(addr_l))
	return net.IP(buf).String()
}
