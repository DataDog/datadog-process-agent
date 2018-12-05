#include <linux/kconfig.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/ptrace.h>
#pragma clang diagnostic pop
#include <linux/bpf.h>
#include <linux/version.h>
#include "bpf_helpers.h"
#include "tracer-ebpf.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Wenum-conversion"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <net/inet_sock.h>
#include <net/net_namespace.h>

#define bpf_debug(fmt, ...)                                        \
	({                                                             \
		char ____fmt[] = fmt;                                      \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
	})

/* This is a key/value store with the keys being an ipv4_tuple_t for send & recv calls
 * and the values being the struct conn_stats_ts_t *.
 */
struct bpf_map_def SEC("maps/conn_stats_ipv4") conn_stats_ipv4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ipv4_tuple_t),
	.value_size = sizeof(struct conn_stats_ts_t),
	.max_entries = 65536,
	.pinning = 0,
	.namespace = "",
};

/* This is a key/value store with the keys being an ipv6_tuple_t for send & recv calls
 * and the values being the struct conn_stats_ts_t *.
 */
struct bpf_map_def SEC("maps/conn_stats_ipv6") conn_stats_ipv6 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ipv6_tuple_t),
	.value_size = sizeof(struct conn_stats_ts_t),
	.max_entries = 65536,
	.pinning = 0,
	.namespace = "",
};

/* These maps are used to match the kprobe & kretprobe of connect for IPv4 */
/* This is a key/value store with the keys being a pid
 * and the values being a struct sock *.
 */
struct bpf_map_def SEC("maps/connectsock_ipv4") connectsock_ipv4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(void *),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};

/* These maps are used to match the kprobe & kretprobe of connect for IPv6 */
/* This is a key/value store with the keys being a pid
 * and the values being a struct sock *.
 */
struct bpf_map_def SEC("maps/connectsock_ipv6") connectsock_ipv6 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(void *),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};

/* This map is used to match the kprobe & kretprobe of udp_recvmsg */
/* This is a key/value store with the keys being a pid
 * and the values being a struct sock *.
 */
struct bpf_map_def SEC("maps/udp_recv_sock") udp_recv_sock = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(void *),
	.max_entries = 1024,
	.pinning = 0,
	.namespace = "",
};

/* http://stackoverflow.com/questions/1001307/detecting-endianness-programmatically-in-a-c-program */
__attribute__((always_inline))
static bool is_big_endian(void) {
	union {
		uint32_t i;
		char c[4];
	} bint = {0x01020304};

	return bint.c[0] == 1;
}

/* check if IPs are IPv4 mapped to IPv6 ::ffff:xxxx:xxxx
 * https://tools.ietf.org/html/rfc4291#section-2.5.5
 * the addresses are stored in network byte order so IPv4 adddress is stored
 * in the most significant 32 bits of part saddr_l and daddr_l.
 * Meanwhile the end of the mask is stored in the least significant 32 bits.
 */
__attribute__((always_inline))
static bool is_ipv4_mapped_ipv6(u64 saddr_h, u64 saddr_l, u64 daddr_h, u64 daddr_l) {
	if (is_big_endian()) {
		return ((saddr_h == 0 && ((u32)(saddr_l >> 32) == 0x0000FFFF)) || (daddr_h == 0 && ((u32)(daddr_l >> 32) == 0x0000FFFF)));
	} else {
		return ((saddr_h == 0 && ((u32) saddr_l == 0xFFFF0000)) || (daddr_h == 0 && ((u32) daddr_l == 0xFFFF0000)));
	}
}

struct bpf_map_def SEC("maps/tracer_status") tracer_status = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct tracer_status_t),
	.max_entries = 1,
	.pinning = 0,
	.namespace = "",
};

// Keeping track of latest timestamp of monotonic clock
struct bpf_map_def SEC("maps/latest_ts") latest_ts = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u64),
	.max_entries = 1,
	.pinning = 0,
	.namespace = "",
};

__attribute__((always_inline))
static bool proc_t_comm_equals(struct proc_t a, struct proc_t b) {
	int i;
	for (i = 0; i < TASK_COMM_LEN; i++) {
		if (a.comm[i] != b.comm[i]) {
			return false;
		}
	}
	return true;
}

__attribute__((always_inline))
static int are_offsets_ready_v4(struct tracer_status_t *status, struct sock *skp, u64 pid) {
	u64 zero = 0;

	switch (status->state) {
		case TRACER_STATE_UNINITIALIZED:
			return 0;
		case TRACER_STATE_CHECKING:
			break;
		case TRACER_STATE_CHECKED:
			return 0;
		case TRACER_STATE_READY:
			return 1;
		default:
			return 0;
	}

	// Only traffic for the expected process name. Extraneous connections from other processes must be ignored here.
	// Userland must take care to generate connections from the correct thread. In Golang, this can be achieved
	// with runtime.LockOSThread.
	struct proc_t proc = {};
	bpf_get_current_comm(&proc.comm, sizeof(proc.comm));

	if (!proc_t_comm_equals(status->proc, proc))
		return 0;

	struct tracer_status_t new_status = {};
	new_status.state = TRACER_STATE_CHECKED;
	new_status.what = status->what;
	new_status.offset_saddr = status->offset_saddr;
	new_status.offset_daddr = status->offset_daddr;
	new_status.offset_sport = status->offset_sport;
	new_status.offset_dport = status->offset_dport;
	new_status.offset_netns = status->offset_netns;
	new_status.offset_ino = status->offset_ino;
	new_status.offset_family = status->offset_family;
	new_status.offset_daddr_ipv6 = status->offset_daddr_ipv6;
	new_status.err = 0;
	new_status.saddr = status->saddr;
	new_status.daddr = status->daddr;
	new_status.sport = status->sport;
	new_status.dport = status->dport;
	new_status.netns = status->netns;
	new_status.family = status->family;
	new_status.ipv6_enabled = status->ipv6_enabled;

	bpf_probe_read(&new_status.proc.comm, sizeof(proc.comm), proc.comm);

	int i;
	for (i = 0; i < 4; i++) {
		new_status.daddr_ipv6[i] = status->daddr_ipv6[i];
	}

	u32 possible_saddr;
	u32 possible_daddr;
	u16 possible_sport;
	u16 possible_dport;
	possible_net_t *possible_skc_net;
	u32 possible_netns;
	u16 possible_family;
	long ret = 0;

	switch (status->what) {
		case GUESS_SADDR:
			possible_saddr = 0;
			bpf_probe_read(&possible_saddr, sizeof(possible_saddr), ((char *) skp) + status->offset_saddr);
			new_status.saddr = possible_saddr;
			break;
		case GUESS_DADDR:
			possible_daddr = 0;
			bpf_probe_read(&possible_daddr, sizeof(possible_daddr), ((char *) skp) + status->offset_daddr);
			new_status.daddr = possible_daddr;
			break;
		case GUESS_FAMILY:
			possible_family = 0;
			bpf_probe_read(&possible_family, sizeof(possible_family), ((char *) skp) + status->offset_family);
			new_status.family = possible_family;
			break;
		case GUESS_SPORT:
			possible_sport = 0;
			bpf_probe_read(&possible_sport, sizeof(possible_sport), ((char *) skp) + status->offset_sport);
			new_status.sport = possible_sport;
			break;
		case GUESS_DPORT:
			possible_dport = 0;
			bpf_probe_read(&possible_dport, sizeof(possible_dport), ((char *) skp) + status->offset_dport);
			new_status.dport = possible_dport;
			break;
		case GUESS_NETNS:
			possible_netns = 0;
			possible_skc_net = NULL;
			bpf_probe_read(&possible_skc_net, sizeof(possible_net_t *), ((char *) skp) + status->offset_netns);
			// if we get a kernel fault, it means possible_skc_net
			// is an invalid pointer, signal an error so we can go
			// to the next offset_netns
			ret = bpf_probe_read(&possible_netns, sizeof(possible_netns), ((char *) possible_skc_net) + status->offset_ino);
			if (ret == -EFAULT) {
				new_status.err = 1;
				break;
			}
			new_status.netns = possible_netns;
			break;
		default:
			// not for us
			return 0;
	}

	bpf_map_update_elem(&tracer_status, &zero, &new_status, BPF_ANY);

	return 0;
}

__attribute__((always_inline))
static int are_offsets_ready_v6(struct tracer_status_t *status, struct sock *skp, u64 pid) {
	u64 zero = 0;

	switch (status->state) {
		case TRACER_STATE_UNINITIALIZED:
			return 0;
		case TRACER_STATE_CHECKING:
			break;
		case TRACER_STATE_CHECKED:
			return 0;
		case TRACER_STATE_READY:
			return 1;
		default:
			return 0;
	}

	// Only traffic for the expected process name. Extraneous connections from other processes must be ignored here.
	// Userland must take care to generate connections from the correct thread. In Golang, this can be achieved
	// with runtime.LockOSThread.
	struct proc_t proc = {};
	bpf_get_current_comm(&proc.comm, sizeof(proc.comm));

	if (!proc_t_comm_equals(status->proc, proc))
		return 0;

	struct tracer_status_t new_status = {};
	new_status.state = TRACER_STATE_CHECKED;
	new_status.what = status->what;
	new_status.offset_saddr = status->offset_saddr;
	new_status.offset_daddr = status->offset_daddr;
	new_status.offset_sport = status->offset_sport;
	new_status.offset_dport = status->offset_dport;
	new_status.offset_netns = status->offset_netns;
	new_status.offset_ino = status->offset_ino;
	new_status.offset_family = status->offset_family;
	new_status.offset_daddr_ipv6 = status->offset_daddr_ipv6;
	new_status.err = 0;
	new_status.saddr = status->saddr;
	new_status.daddr = status->daddr;
	new_status.sport = status->sport;
	new_status.dport = status->dport;
	new_status.netns = status->netns;
	new_status.family = status->family;
	new_status.ipv6_enabled = status->ipv6_enabled;

	bpf_probe_read(&new_status.proc.comm, sizeof(proc.comm), proc.comm);

	int i;
	for (i = 0; i < 4; i++) {
		new_status.daddr_ipv6[i] = status->daddr_ipv6[i];
	}

	u32 possible_daddr_ipv6[4] = {};
	switch (status->what) {
		case GUESS_DADDR_IPV6:
			bpf_probe_read(&possible_daddr_ipv6, sizeof(possible_daddr_ipv6), ((char *) skp) + status->offset_daddr_ipv6);

			int i;
			for (i = 0; i < 4; i++) {
				new_status.daddr_ipv6[i] = possible_daddr_ipv6[i];
			}
			break;
		default:
			// not for us
			return 0;
	}

	bpf_map_update_elem(&tracer_status, &zero, &new_status, BPF_ANY);

	return 0;
}

__attribute__((always_inline))
static bool check_family(struct sock *sk, struct tracer_status_t *status, u16 expected_family) {
	u16 family = 0;
	bpf_probe_read(&family, sizeof(u16), ((char *) sk) + status->offset_family);
	return family == expected_family;
}

__attribute__((always_inline))
static bool is_ipv6_enabled(struct tracer_status_t *status) {
	return status->ipv6_enabled == TRACER_IPV6_ENABLED;
}

__attribute__((always_inline))
static int read_ipv4_tuple(struct ipv4_tuple_t *tuple, struct tracer_status_t *status, struct sock *skp) {
	u32 saddr, daddr, net_ns_inum;
	u16 sport, dport;
	possible_net_t *skc_net;

	saddr = 0;
	daddr = 0;
	sport = 0;
	dport = 0;
	skc_net = NULL;
	net_ns_inum = 0;

	bpf_probe_read(&saddr, sizeof(saddr), ((char *) skp) + status->offset_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), ((char *) skp) + status->offset_daddr);
	bpf_probe_read(&sport, sizeof(sport), ((char *) skp) + status->offset_sport);
	bpf_probe_read(&dport, sizeof(dport), ((char *) skp) + status->offset_dport);
	// Get network namespace id
	bpf_probe_read(&skc_net, sizeof(void *), ((char *) skp) + status->offset_netns);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), ((char *) skc_net) + status->offset_ino);

	tuple->saddr = saddr;
	tuple->daddr = daddr;
	tuple->sport = sport;
	tuple->dport = dport;
	tuple->netns = net_ns_inum;

	// if addresses or ports are 0, ignore
	if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
		return 0;
	}

	return 1;
}

__attribute__((always_inline))
static int read_ipv6_tuple(struct ipv6_tuple_t *tuple, struct tracer_status_t *status, struct sock *skp) {
	u32 net_ns_inum;
	u16 sport, dport;
	u64 saddr_h, saddr_l, daddr_h, daddr_l;
	possible_net_t *skc_net;

	saddr_h = 0;
	saddr_l = 0;
	daddr_h = 0;
	daddr_l = 0;
	sport = 0;
	dport = 0;
	skc_net = NULL;
	net_ns_inum = 0;

	bpf_probe_read(&saddr_h, sizeof(saddr_h), ((char *) skp) + status->offset_daddr_ipv6 + 2 * sizeof(u64));
	bpf_probe_read(&saddr_l, sizeof(saddr_l), ((char *) skp) + status->offset_daddr_ipv6 + 3 * sizeof(u64));
	bpf_probe_read(&daddr_h, sizeof(daddr_h), ((char *) skp) + status->offset_daddr_ipv6);
	bpf_probe_read(&daddr_l, sizeof(daddr_l), ((char *) skp) + status->offset_daddr_ipv6 + sizeof(u64));
	bpf_probe_read(&sport, sizeof(sport), ((char *) skp) + status->offset_sport);
	bpf_probe_read(&dport, sizeof(dport), ((char *) skp) + status->offset_dport);
	// Get network namespace id
	bpf_probe_read(&skc_net, sizeof(void *), ((char *) skp) + status->offset_netns);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), ((char *) skc_net) + status->offset_ino);

	tuple->saddr_h = saddr_h;
	tuple->saddr_l = saddr_l;
	tuple->daddr_h = daddr_h;
	tuple->daddr_l = daddr_l;
	tuple->sport = sport;
	tuple->dport = dport;
	tuple->netns = net_ns_inum;

	// if addresses or ports are 0, ignore
	if (!(saddr_h || saddr_l) || !(daddr_h || daddr_l) || sport == 0 || dport == 0) {
		return 0;
	}

	return 1;
}

__attribute__((always_inline))
static int increment_tcp_stats(struct sock *sk, struct tracer_status_t *status, size_t send_bytes, size_t recv_bytes) {
	struct conn_stats_ts_t *val;

	u64 pid = bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();

	if (check_family(sk, status, AF_INET)) {
		if (!are_offsets_ready_v4(status, sk, pid)) {
			return 0;
		}

		struct ipv4_tuple_t t = {};
		t.metadata = 1;

		if (!read_ipv4_tuple(&t, status, sk)) {
			return 0;
		}

		t.pid = pid >> 32;
		t.sport = ntohs(t.sport); // Making ports human-readable
		t.dport = ntohs(t.dport);

		val = bpf_map_lookup_elem(&conn_stats_ipv4, &t);
		if (val != NULL) { // If already in our map, increment size in-place
			(*val).send_bytes += send_bytes;
			(*val).recv_bytes += recv_bytes;
			(*val).timestamp  = ts;
		} else { // Otherwise add the key, value to the map
			struct conn_stats_ts_t s = {
				.send_bytes = send_bytes,
				.recv_bytes = recv_bytes,
				.timestamp = ts,
			};
			bpf_map_update_elem(&conn_stats_ipv4, &t, &s, BPF_ANY);
		}
	} else if (is_ipv6_enabled(status) && check_family(sk, status, AF_INET6)) {
		if (!are_offsets_ready_v6(status, sk, pid)) {
			return 0;
		}

		struct ipv6_tuple_t t = {};
		t.metadata = 1;

		if (!read_ipv6_tuple(&t, status, sk)) {
			return 0;
		}

		// IPv4 can be mapped as IPv6
		if (is_ipv4_mapped_ipv6(t.saddr_h, t.saddr_l, t.daddr_h, t.daddr_l)) {
			struct ipv4_tuple_t t2 = {
				t2.saddr = (u32)(t.saddr_l >> 32),
				t2.daddr = (u32)(t.daddr_l >> 32),
				t2.sport = ntohs(t.sport),
				t2.dport = ntohs(t.dport),
				t2.netns = t.netns,
				t2.pid = pid >> 32,
				t2.metadata = 1,
			};

			val = bpf_map_lookup_elem(&conn_stats_ipv4, &t2);
			if (val != NULL) { // If already in our map, increment size in-place
				(*val).send_bytes += send_bytes;
				(*val).recv_bytes += recv_bytes;
				(*val).timestamp = ts;
			} else { // Otherwise add the key, value to the map
				struct conn_stats_ts_t s = {
					.send_bytes = send_bytes,
					.recv_bytes = recv_bytes,
					.timestamp = ts,
				};
				bpf_map_update_elem(&conn_stats_ipv4, &t2, &s, BPF_ANY);
			}
		} else {
			t.pid = pid >> 32;
			t.sport = ntohs(t.sport); // Making ports human-readable
			t.dport = ntohs(t.dport);

			val = bpf_map_lookup_elem(&conn_stats_ipv6, &t);
			// If already in our map, increment size in-place
			if (val != NULL) {
				(*val).send_bytes += send_bytes;
				(*val).recv_bytes += recv_bytes;
				(*val).timestamp = ts;
			} else { // Otherwise add the key, value to the map
				struct conn_stats_ts_t s = {
					.send_bytes = send_bytes,
					.recv_bytes = recv_bytes,
					.timestamp = ts,
				};
				bpf_map_update_elem(&conn_stats_ipv6, &t, &s, BPF_ANY);
			}
		}
	}

	// Update latest timestamp that we've seen - for connection expiration tracking
	u64 zero = 0;
	bpf_map_update_elem(&latest_ts, &zero, &ts, BPF_ANY);

	return 0;
}

__attribute__((always_inline))
static int increment_udp_stats(struct sock *sk,
                               struct tracer_status_t *status,
                               u64 pid_tgid,
                               size_t send_bytes,
                               size_t recv_bytes) {
	struct conn_stats_ts_t *val;

	u64 zero = 0;
	u64 ts = bpf_ktime_get_ns();

	if (check_family(sk, status, AF_INET)) {
		if (!are_offsets_ready_v4(status, sk, pid_tgid)) {
			return 0;
		}

		struct ipv4_tuple_t t = {};
		t.metadata = 0;

		if (!read_ipv4_tuple(&t, status, sk)) {
			return 0;
		}

		t.pid = pid_tgid >> 32;
		// Making ports human-readable
		t.sport = ntohs(t.sport);
		t.dport = ntohs(t.dport);

		val = bpf_map_lookup_elem(&conn_stats_ipv4, &t);
		// If already in our map, increment stats in-place
		if (val != NULL) {
			(*val).send_bytes += send_bytes;
			(*val).recv_bytes += recv_bytes;
			(*val).timestamp = ts;
		} else { // Otherwise add the (key, value) to the map
			struct conn_stats_ts_t s = {
				.send_bytes = send_bytes,
				.recv_bytes = recv_bytes,
				.timestamp = ts,
			};
			bpf_map_update_elem(&conn_stats_ipv4, &t, &s, BPF_ANY);
		}
	} else if (is_ipv6_enabled(status) && check_family(sk, status, AF_INET6)) {
		if (!are_offsets_ready_v6(status, sk, pid_tgid)) {
			return 0;
		}

		struct ipv6_tuple_t t = {};
		t.metadata = 0;

		if (!read_ipv6_tuple(&t, status, sk)) {
			return 0;
		}

		// IPv4 can be mapped as IPv6
		if (is_ipv4_mapped_ipv6(t.saddr_h, t.saddr_l, t.daddr_h, t.daddr_l)) {
			struct ipv4_tuple_t t2 = {
				t2.saddr = (u32)(t.saddr_l >> 32),
				t2.daddr = (u32)(t.daddr_l >> 32),
				t2.sport = ntohs(t.sport),
				t2.dport = ntohs(t.dport),
				t2.netns = t.netns,
				t2.pid = pid_tgid >> 32,
				t2.metadata = 0,
			};

			val = bpf_map_lookup_elem(&conn_stats_ipv4, &t2);
			if (val != NULL) { // If already in our map, increment size in-place
				(*val).send_bytes += send_bytes;
				(*val).recv_bytes += recv_bytes;
			} else { // Otherwise add the key, value to the map
				struct conn_stats_ts_t s = {
					.send_bytes = send_bytes,
					.recv_bytes = recv_bytes,
					.timestamp = ts,
				};
				bpf_map_update_elem(&conn_stats_ipv4, &t2, &s, BPF_ANY);
			}
		} else { // It's IPv6
			t.pid = pid_tgid >> 32;
			t.sport = ntohs(t.sport); // Making ports human-readable
			t.dport = ntohs(t.dport);

			val = bpf_map_lookup_elem(&conn_stats_ipv6, &t);
			// If already in our map, increment size in-place
			if (val != NULL) {
				(*val).send_bytes += send_bytes;
				(*val).recv_bytes += recv_bytes;
				(*val).timestamp = ts;
			} else { // Otherwise add the key, value to the map
				struct conn_stats_ts_t s = {
					.send_bytes = send_bytes,
					.recv_bytes = recv_bytes,
					.timestamp = ts,
				};
				bpf_map_update_elem(&conn_stats_ipv6, &t, &s, BPF_ANY);
			}
		}
	}

	// Update latest timestamp that we've seen - for connection expiration tracking
	bpf_map_update_elem(&latest_ts, &zero, &ts, BPF_ANY);

	return 0;
}

// Used for offset guessing (see: pkg/offsetguess.go)
SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx) {
	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&connectsock_ipv4, &pid, &sk, BPF_ANY);

	return 0;
}

// Used for offset guessing (see: pkg/offsetguess.go)
SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	u64 zero = 0;
	struct tracer_status_t *status;

	skpp = bpf_map_lookup_elem(&connectsock_ipv4, &pid);
	if (skpp == 0) {
		return 0; // missed entry
	}

	struct sock *skp = *skpp;

	bpf_map_delete_elem(&connectsock_ipv4, &pid);

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

	status = bpf_map_lookup_elem(&tracer_status, &zero);
	if (status == NULL || status->state == TRACER_STATE_UNINITIALIZED) {
		return 0;
	}

	// We should figure out offsets if they're not already figured out
	are_offsets_ready_v4(status, skp, pid);

	return 0;
}

// Used for offset guessing (see: pkg/offsetguess.go)
SEC("kprobe/tcp_v6_connect")
int kprobe__tcp_v6_connect(struct pt_regs *ctx) {
	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&connectsock_ipv6, &pid, &sk, BPF_ANY);

	return 0;
}

// Used for offset guessing (see: pkg/offsetguess.go)
SEC("kretprobe/tcp_v6_connect")
int kretprobe__tcp_v6_connect(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid();
	u64 zero = 0;
	struct sock **skpp;
	struct tracer_status_t *status;
	skpp = bpf_map_lookup_elem(&connectsock_ipv6, &pid);
	if (skpp == 0) {
		return 0; // missed entry
	}

	bpf_map_delete_elem(&connectsock_ipv6, &pid);

	struct sock *skp = *skpp;

	status = bpf_map_lookup_elem(&tracer_status, &zero);
	if (status == NULL || status->state == TRACER_STATE_UNINITIALIZED) {
		return 0;
	}

	// We should figure out offsets if they're not already figured out
	are_offsets_ready_v6(status, skp, pid);

	return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
	struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
	size_t size = (size_t) PT_REGS_PARM3(ctx);
	u64 zero = 0;

	// TODO: Add DEBUG macro so this is only printed, if enabled
	// bpf_debug("map: tcp_send_ipv4 kprobe\n");

	struct tracer_status_t *status = bpf_map_lookup_elem(&tracer_status, &zero);
	if (status == NULL || status->state == TRACER_STATE_UNINITIALIZED) {
		return 0;
	}

	return increment_tcp_stats(sk, status, size, 0);
}

SEC("kprobe/tcp_cleanup_rbuf")
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx) {
	struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
	int copied = (int) PT_REGS_PARM2(ctx);
	if (copied < 0) {
		return 0;
	}
	u64 zero = 0;

	struct tracer_status_t *status = bpf_map_lookup_elem(&tracer_status, &zero);
	if (status == NULL || status->state == TRACER_STATE_UNINITIALIZED) {
		return 0;
	}

	return increment_tcp_stats(sk, status, 0, copied);
}

SEC("kprobe/tcp_close")
int kprobe__tcp_close(struct pt_regs *ctx) {
	struct sock *sk;
	struct tracer_status_t *status;
	u64 zero = 0;
	u64 pid = bpf_get_current_pid_tgid();
	sk = (struct sock *) PT_REGS_PARM1(ctx);

	status = bpf_map_lookup_elem(&tracer_status, &zero);
	if (status == NULL || status->state != TRACER_STATE_READY) {
		return 0;
	}

	u32 net_ns_inum;
	u16 sport, dport;
	sport = 0;
	dport = 0;

	// Get network namespace id
	possible_net_t *skc_net;

	skc_net = NULL;
	net_ns_inum = 0;
	bpf_probe_read(&skc_net, sizeof(possible_net_t *), ((char *) sk) + status->offset_netns);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), ((char *) skc_net) + status->offset_ino);

	if (check_family(sk, status, AF_INET)) {
		struct ipv4_tuple_t t = {};
		t.metadata = 1;


		if (!read_ipv4_tuple(&t, status, sk)) {
			return 0;
		}

		t.pid = pid >> 32;
		t.sport = ntohs(t.sport); // Making ports human-readable
		t.dport = ntohs(t.dport);

		// Delete this connection from our stats map
		bpf_map_delete_elem(&conn_stats_ipv4, &t);
	} else if (is_ipv6_enabled(status) && check_family(sk, status, AF_INET6)) {
		struct ipv6_tuple_t t = {};
		t.metadata = 1;

		if (!read_ipv6_tuple(&t, status, sk)) {
			return 0;
		}

		// IPv4 can be mapped as IPv6
		if (is_ipv4_mapped_ipv6(t.saddr_h, t.saddr_l, t.daddr_h, t.daddr_l)) {
			struct ipv4_tuple_t t2 = {
				t2.saddr = (u32)(t.saddr_l >> 32),
				t2.daddr = (u32)(t.daddr_l >> 32),
				t2.sport = ntohs(t.sport),
				t2.dport = ntohs(t.dport),
				t2.netns = t.netns,
				t2.pid = pid >> 32,
				t2.metadata = 1,
			};

			// Delete this connection from our stats map, and return
			bpf_map_delete_elem(&conn_stats_ipv4, &t2);
			return 0;
		} else { // Otherwise it's IPv6
			t.pid = pid >> 32;
			t.sport = ntohs(t.sport); // Making ports human-readable
			t.dport = ntohs(t.dport);

			bpf_map_delete_elem(&conn_stats_ipv6, &t);
		}
	}
	return 0;
}

SEC("kprobe/udp_sendmsg")
int kprobe__udp_sendmsg(struct pt_regs *ctx) {
	struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
	size_t size = (size_t) PT_REGS_PARM3(ctx);
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 zero = 0;

	struct tracer_status_t *status = bpf_map_lookup_elem(&tracer_status, &zero);
	if (status == NULL || status->state == TRACER_STATE_UNINITIALIZED) {
		return 0;
	}

	increment_udp_stats(sk, status, pid_tgid, size, 0);

	return 0;
}

// We can only get the accurate number of copied bytes from the return value, so we pass our
// sock* pointer from the kprobe to the kretprobe via a map (udp_recv_sock) to get all required info
//
// The same issue exists for TCP, but we can conveniently use the downstream function tcp_cleanup_rbuf
//
// On UDP side, no similar function exists in all kernel versions, though we may be able to use something like
// skb_consume_udp (v4.10+, https://elixir.bootlin.com/linux/v4.10/source/net/ipv4/udp.c#L1500)
SEC("kprobe/udp_recvmsg")
int kprobe__udp_recvmsg(struct pt_regs *ctx) {
	struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
	u64 pid_tgid = bpf_get_current_pid_tgid();

	// Store pointer to the socket using the pid/tgid
	bpf_map_update_elem(&udp_recv_sock, &pid_tgid, &sk, BPF_ANY);

	return 0;
}

SEC("kretprobe/udp_recvmsg")
int kretprobe__udp_recvmsg(struct pt_regs *ctx) {
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 zero = 0;

	// Retrieve socket pointer from kprobe via pid/tgid
	struct sock **skpp = bpf_map_lookup_elem(&udp_recv_sock, &pid_tgid);
	if (skpp == 0) { // Missed entry
		return 0;
	}
	struct sock *sk = *skpp;

	// Make sure we clean up that pointer reference
	bpf_map_delete_elem(&udp_recv_sock, &pid_tgid);

	int copied = (int) PT_REGS_RC(ctx);
	if (copied < 0) { // Non-zero values are errors (e.g -EINVAL)
		return 0;
	}

	struct tracer_status_t *status = bpf_map_lookup_elem(&tracer_status, &zero);
	if (status == NULL || status->state == TRACER_STATE_UNINITIALIZED) {
		return 0;
	}

	increment_udp_stats(sk, status, pid_tgid, 0, copied);

	return 0;
}

// This number will be interpreted by gobpf-elf-loader to set the current running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE;

char _license[] SEC("license") = "GPL";
