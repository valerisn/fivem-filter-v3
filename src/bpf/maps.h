/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Map definitions and BPF-private types. Only included by filter.bpf.c, but
 * kept separate so the pipeline file reads like a pipeline.
 */
#ifndef FF_MAPS_H
#define FF_MAPS_H

/*
 * Per-source state is a fixed hashed array, not an LRU hash:
 *  - memory is allocated at load, never under flood
 *  - nothing gets evicted at the exact moment it matters (an LRU under a
 *    source-rotating flood evicts precisely the entries you were tracking)
 *  - array values can carry a bpf_spin_lock, LRU values can't, and a token
 *    bucket is read-modify-write that races across RX queues without one
 * Collisions are resolved by `tag`: a mismatch resets the slot so two
 * sources sharing a slot don't rate limit each other.
 */
#ifndef FF_STATE_SLOTS
#define FF_STATE_SLOTS (1u << 17)	/* 131072 * 72B ~= 9 MiB */
#endif
#define FF_STATE_MASK (FF_STATE_SLOTS - 1)

#define FF_MAP_RULES  262144
#define FF_MAP_FLOWS  524288
#define FF_MAP_FRAGS  65536
#define FF_RINGBUF    (1u << 20)

/* FIN seen: keep the flow around this long so the final ACK of the close
 * handshake isn't dropped as "no flow". v2 deleted on FIN and left the
 * server retransmitting its own FIN into the void until LAST_ACK timed out. */
#define FF_FLOW_CLOSE_NS (10ULL * 1000000000ULL)

#define FF_DEFAULT_FRAG_TTL_NS (2ULL * 1000000000ULL)

enum ff_global_slot {
	FF_G_SYN = 0,
	FF_G_OOB,
	FF_G_MAX
};

struct ff_state {
	struct bpf_spin_lock lock;
	__u32 tag;
	__u64 stamp[FF_B_MAX];
	__u64 conn_ns;
	__u32 tokens[FF_B_MAX];
	__u32 conn_count;
	__u32 pad_;
};

struct ff_gbucket {
	__u64 stamp;
	__u32 tokens;
	__u32 pad_;
};

struct ff_flow_key {
	__u32 saddr[4];
	__u32 daddr[4];
	__u16 sport;		/* network order, straight off the wire */
	__u16 dport;
	__u8  af;
	__u8  pad_[3];
};

struct ff_flow_val {
	__u64 last_ns;
	__u8  closing;
	__u8  pad_[7];
};

/*
 * Only the first fragment carries ports. Its verdict is remembered here and
 * every later fragment of the same datagram inherits it, so fragmented
 * traffic to ports we don't care about (big DNS answers to the server's own
 * resolver, say) keeps working. v2 dropped every non-first fragment to the
 * protected address, which quietly broke exactly that.
 */
struct ff_frag_key {
	__u32 saddr[4];
	__u32 daddr[4];
	__u32 id;
	__u8  proto;
	__u8  af;
	__u16 pad_;
};

struct ff_frag_val {
	__u64 expires_ns;
	__u32 reason;
	__u32 pad_;
};

/* Decoded packet. Addresses are full and in network order, v4 in [0]. */
struct ff_pkt {
	__u32 src[4];
	__u32 dst[4];
	struct ff_addr key;	/* rate-limit key: v4, or v6 /64 */
	__u16 sport;		/* host order */
	__u16 dport;
	__u16 len;		/* IP length from the header, padding excluded */
	__u8  proto;
	__u8  af;
};

struct ff_l3 {
	void *l4;
	void *end;		/* end of the datagram per its own length field */
	__u32 iplen;
	__u32 frag_id;
	__u8  proto;
	bool  frag;
	bool  frag_first;
	bool  has_opts;
};

/* ------------------------------------------------------------------ maps */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ff_config);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FF_STATE_SLOTS);
	__type(key, __u32);
	__type(value, struct ff_state);
} state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, FF_G_MAX);
	__type(key, __u32);
	__type(value, struct ff_gbucket);
} global SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, FF_MAP_RULES);
	__type(key, struct ff_lpm4);
	__type(value, struct ff_rule);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} rules4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, FF_MAP_RULES);
	__type(key, struct ff_lpm6);
	__type(value, struct ff_rule);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} rules6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, FF_MAP_FLOWS);
	__type(key, struct ff_flow_key);
	__type(value, struct ff_flow_val);
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, FF_MAP_FRAGS);
	__type(key, struct ff_frag_key);
	__type(value, struct ff_frag_val);
} frags SEC(".maps");

/* Per-CPU so the fast path never contends; fivemctl sums on read. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, FF_STAT_MAX);
	__type(key, __u32);
	__type(value, struct ff_counter);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, FF_RINGBUF);
} events SEC(".maps");

#endif /* FF_MAPS_H */
