#ifndef __TRACER_BPF_H
#define __TRACER_BPF_H

#include <linux/types.h>

#define GUESS_SADDR      0
#define GUESS_DADDR      1
#define GUESS_FAMILY     2
#define GUESS_SPORT      3
#define GUESS_DPORT      4
#define GUESS_NETNS      5
#define GUESS_DADDR_IPV6 6

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct proc_t {
    char comm[TASK_COMM_LEN];
};

struct conn_stats_ts_t {
	__u64 send_bytes;
	__u64 recv_bytes;
	__u64 timestamp;
};

// tcp_set_state doesn't run in the context of the process that initiated the
// connection so we need to store a map TUPLE -> PID to send the right PID on
// the event
struct ipv4_tuple_t {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 netns;
	__u32 pid;
	// Metadata description:
	// First bit indicates if the connection is TCP (1) or UDP (0)
	__u32 metadata; // This is that big because it seems that we atleast need a 32-bit aligned struct
};

struct ipv6_tuple_t {
	/* Using the type unsigned __int128 generates an error in the ebpf verifier */
	__u64 saddr_h;
	__u64 saddr_l;
	__u64 daddr_h;
	__u64 daddr_l;
	__u16 sport;
	__u16 dport;
	__u32 netns;
	__u32 pid;
	// Metadata description:
	// First bit indicates if the connection is TCP (1) or UDP (0)
	__u32 metadata; // This is that big because it seems that we atleast need a 32-bit aligned struct
};

#define TRACER_STATE_UNINITIALIZED 0
#define TRACER_STATE_CHECKING      1
#define TRACER_STATE_CHECKED       2
#define TRACER_STATE_READY         3

#define TRACER_IPV6_DISABLED 0
#define TRACER_IPV6_ENABLED  1

struct tracer_status_t {
	__u64 state;

	/* checking */
	struct proc_t proc;
	__u64 what;
	__u64 offset_saddr;
	__u64 offset_daddr;
	__u64 offset_sport;
	__u64 offset_dport;
	__u64 offset_netns;
	__u64 offset_ino;
	__u64 offset_family;
	__u64 offset_daddr_ipv6;

	__u64 err;

	__u32 daddr_ipv6[4];
	__u32 netns;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u16 family;

	__u8 ipv6_enabled;
	__u8 padding;
};

#endif
