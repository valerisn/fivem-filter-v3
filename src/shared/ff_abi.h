/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Everything that crosses the map boundary between the XDP program and
 * fivemctl. Both sides memcpy these structs blind, so field order is the ABI.
 * Rule of thumb that's kept us out of trouble: u64s first, then u32, u16, u8,
 * and pad explicitly so the BPF side and x86 userspace agree byte for byte.
 *
 * Bump FF_ABI_VERSION on any layout change. fivemctl refuses to talk to a
 * pinned filter with a different version instead of scribbling garbage into
 * its config map, which is what v2 would happily do after an upgrade.
 */
#ifndef FF_ABI_H
#define FF_ABI_H

#include <linux/types.h>

#define FF_ABI_VERSION 3

#define FF_AF_INET  4
#define FF_AF_INET6 6

/*
 * Rate-limit key. v4 address in a[0], v6 /64 prefix in a[0..1], family tag in
 * a[3] so a v4 address can never alias a v6 prefix. Only used for per-source
 * state; the allow/block lists match on full addresses.
 */
struct ff_addr {
	__u32 a[4];
};

/* LPM trie keys. prefixlen must come first, the kernel insists. */
struct ff_lpm4 {
	__u32 prefixlen;
	__u8  addr[4];
};

struct ff_lpm6 {
	__u32 prefixlen;
	__u8  addr[16];
};

/*
 * One trie per family holds both allow and block rules. Longest prefix wins,
 * so "block 198.51.100.0/24, allow 198.51.100.7" does what anyone would
 * expect. v2 kept separate lists where allow always won, which made punching
 * a ban hole inside an allowed range impossible.
 */
#define FF_ACT_ALLOW 1
#define FF_ACT_BLOCK 2

struct ff_rule {
	__u64 expires_ns;	/* CLOCK_MONOTONIC (bpf_ktime_get_ns); 0 = never */
	__u64 added_ns;
	__u64 hits;		/* approximate, sampled - see ff_rule_hit() */
	__u8  action;
	__u8  pad_[7];
};

/* ------------------------------------------------------------------ config */

#define FF_F_ENABLED		(1U << 0)  /* master switch */
#define FF_F_DRY_RUN		(1U << 1)  /* count + log drops, pass anyway */
#define FF_F_DROP_ICMP		(1U << 2)  /* drop all ICMP to the protected address */
#define FF_F_DROP_IPV6		(1U << 3)  /* drop IPv6 to the protected address */
#define FF_F_STRICT_TCP		(1U << 4)  /* non-SYN TCP on game ports needs a flow */
#define FF_F_DROP_IP_OPTS	(1U << 5)  /* drop IPv4 carrying options */
#define FF_F_DROP_FRAGS		(1U << 6)  /* drop every fragment, first included */
#define FF_F_LOG		(1U << 7)  /* sampled drop events to the ringbuf */
#define FF_F_BOGON		(1U << 8)  /* drop martian sources on game ports */
#define FF_F_LOCKDOWN		(1U << 9)  /* game ports: allowlisted sources only */
#define FF_F_DROP_OOB		(1U << 10) /* drop getinfo/getstatus outright */

#define FF_F_DEFAULT (FF_F_ENABLED | FF_F_BOGON | FF_F_STRICT_TCP | FF_F_LOG)

/* Per-source token buckets. Index into ff_config.refill_ns / burst. */
enum ff_bucket_class {
	FF_B_PKT = 0,		/* everything on the game ports */
	FF_B_SYN,		/* new TCP connections */
	FF_B_ICMP,		/* ICMP echo */
	FF_B_OOB,		/* CFX out-of-band queries */
	FF_B_MAX
};

#define FF_MAX_AUX_PORTS 4

struct ff_config {
	/* 64-bit */
	__u64 refill_ns[FF_B_MAX];	/* one token per this many ns; 0 = unlimited */
	__u64 flow_idle_ns;		/* TCP flow idle eviction */
	__u64 conn_window_ns;		/* window for the new-connection quota */
	__u64 tcp_learn_until_ns;	/* adopt unknown TCP flows until this ktime */
	__u64 frag_ttl_ns;		/* how long a first-fragment verdict sticks */

	/* 32-bit */
	__u32 abi_version;		/* FF_ABI_VERSION, written by the loader */
	__u32 flags;
	__u32 burst[FF_B_MAX];		/* bucket depth per class */
	__u32 v4_addr;			/* network order; 0 = every destination */
	__u32 hash_seed;		/* randomised per load */
	__u32 amp_limit;		/* bytes above which amp source ports die */
	__u32 udp_min_len;		/* accepted UDP payload on game ports */
	__u32 udp_max_len;		/* 0 = no ceiling */
	__u32 conn_per_window;		/* 0 = no quota */
	__u32 global_syn_pps;		/* box-wide ceilings; 0 = off */
	__u32 global_oob_pps;
	__u32 log_sample;		/* 1 event per N drops; 0 = off */
	/*
	 * The global ceilings are per-CPU buckets that each get pps / nr_cpus.
	 * v2 used one spin-locked bucket, i.e. every core fighting over one
	 * cacheline during exactly the SYN flood it exists to absorb.
	 */
	__u32 nr_cpus;
	__u32 pad32_;

	/* 16-bit */
	__u16 port_lo;			/* inclusive game port range, host order */
	__u16 port_hi;
	__u16 aux_ports[FF_MAX_AUX_PORTS]; /* txAdmin etc; 0 = unused slot */

	/* 8-bit */
	__u8  v6_set;
	__u8  pad_[3];
	__u8  v6_addr[16];		/* network order */
};

/* -------------------------------------------------------------------- stats */

/*
 * Single source of truth for counters. Order is ABI, append only. The first
 * three are pass reasons; FF_STAT_IS_PASS relies on that, so don't wedge a
 * drop reason in front of them.
 *
 * Third column is the short name used for JSON keys and Prometheus labels.
 */
#define FF_STAT_LIST(X)                                                          \
	X(PASS,             "pass",                                "pass")              \
	X(PASS_ALLOW,       "allowlisted",                         "allowlist")         \
	X(PASS_OTHER,       "not protected (passed untouched)",    "unprotected")       \
	X(DRYRUN,           "dry-run (would have dropped)",        "dry_run")           \
	X(DROP_BLOCK,       "blocklist",                           "blocklist")         \
	X(DROP_LOCKDOWN,    "lockdown (not allowlisted)",          "lockdown")          \
	X(DROP_BOGON,       "bogon / martian source",              "bogon")             \
	X(DROP_LAND,        "land attack (src == dst)",            "land")              \
	X(DROP_IP_OPTS,     "ipv4 options",                        "ip_options")        \
	X(DROP_FRAG,        "fragment (policy)",                   "fragment")          \
	X(DROP_FRAG_ORPHAN, "fragment without a first fragment",   "fragment_orphan")   \
	X(DROP_AMP,         "udp amplification source port",       "amplification")     \
	X(DROP_UDP_SIZE,    "udp payload outside accepted size",   "udp_size")          \
	X(DROP_RATE,        "per-source packet rate",              "rate")              \
	X(DROP_SYN_RATE,    "per-source syn rate",                 "syn_rate")          \
	X(DROP_CONN_RATE,   "per-source new-connection quota",     "conn_quota")        \
	X(DROP_GLOBAL_SYN,  "global syn ceiling",                  "global_syn")        \
	X(DROP_GLOBAL_OOB,  "global oob query ceiling",            "global_oob")        \
	X(DROP_OOB_RATE,    "per-source oob query rate",           "oob_rate")          \
	X(DROP_OOB,         "oob queries disabled",                "oob_disabled")      \
	X(DROP_ICMP,        "icmp (policy)",                       "icmp")              \
	X(DROP_ICMP_RATE,   "per-source icmp echo rate",           "icmp_rate")         \
	X(DROP_TCP_NOFLOW,  "tcp without established flow",        "tcp_noflow")        \
	X(DROP_TCP_FLAGS,   "invalid tcp flag combination",        "tcp_flags")         \
	X(DROP_TCP_SYNDATA, "syn carrying payload",                "tcp_syn_data")      \
	X(DROP_IPV6,        "ipv6 disabled",                       "ipv6")              \
	X(DROP_MALFORMED,   "malformed / truncated header",        "malformed")

enum ff_stat {
#define FF_STAT_ENUM(name, desc, key) FF_STAT_##name,
	FF_STAT_LIST(FF_STAT_ENUM)
#undef FF_STAT_ENUM
	FF_STAT_MAX
};

#define FF_STAT_IS_PASS(r) ((r) <= FF_STAT_PASS_OTHER)

/* Per-CPU value of the stats map. Bytes are IP-layer lengths. */
struct ff_counter {
	__u64 packets;
	__u64 bytes;
};

#ifndef __BPF__
static const char *const ff_stat_desc[FF_STAT_MAX] = {
#define FF_STAT_DESC(name, desc, key) [FF_STAT_##name] = desc,
	FF_STAT_LIST(FF_STAT_DESC)
#undef FF_STAT_DESC
};

static const char *const ff_stat_key[FF_STAT_MAX] = {
#define FF_STAT_KEY(name, desc, key) [FF_STAT_##name] = key,
	FF_STAT_LIST(FF_STAT_KEY)
#undef FF_STAT_KEY
};
#endif

/* ------------------------------------------------------------------ events */

struct ff_event {
	__u64 ts_ns;
	__u32 saddr[4];		/* full addresses, network order, v4 in [0] */
	__u32 daddr[4];
	__u16 sport;		/* host order */
	__u16 dport;
	__u16 pkt_len;
	__u8  proto;
	__u8  af;
	__u8  reason;		/* enum ff_stat */
	__u8  dry;
	__u8  pad_[2];
};

/* Everything the loader pins lives under here. */
#define FF_PIN_DIR "/sys/fs/bpf/fivem-filter"

#endif /* FF_ABI_H */
