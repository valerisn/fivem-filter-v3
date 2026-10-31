/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FF_LIMIT_H
#define FF_LIMIT_H

static __always_inline __u32 ff_hash(const struct ff_addr *a, __u32 seed)
{
	__u32 h = seed ^ a->a[0];

	h *= 0x9e3779b1u;
	h ^= h >> 15;
	h += a->a[1];
	h *= 0x85ebca6bu;
	h ^= h >> 13;
	h += a->a[2] ^ a->a[3];
	h *= 0xc2b2ae35u;
	h ^= h >> 16;
	return h;
}

/* Which per-source checks to run. */
#define FF_CHK_PKT  0x01
#define FF_CHK_SYN  0x02
#define FF_CHK_ICMP 0x04
#define FF_CHK_OOB  0x08
#define FF_CHK_CONN 0x10

#define FF_TAKE(cls) \
	ff_tb_take(&s->stamp[cls], &s->tokens[cls], now, \
		   cfg->refill_ns[cls], cfg->burst[cls])

/*
 * Every per-source decision for a packet happens under one lock in one pass,
 * so nothing is ever seen half-updated. Returns FF_STAT_PASS or a drop reason.
 *
 * No helper calls while the lock is held - the verifier will (rightly) refuse.
 * ff_tb_take is pure arithmetic and inlined, so it's fine in here.
 */
static __always_inline __u32 ff_source_check(struct ff_config *cfg,
					     const struct ff_addr *key,
					     __u64 now, __u32 checks)
{
	__u32 idx = ff_hash(key, cfg->hash_seed) & FF_STATE_MASK;
	/* |1 so a zeroed (never used) slot can never match */
	__u32 tag = ff_hash(key, cfg->hash_seed ^ 0x5bf03635u) | 1u;
	__u32 reason = FF_STAT_PASS;
	struct ff_state *s;

	s = bpf_map_lookup_elem(&state, &idx);
	if (!s)
		return FF_STAT_PASS;	/* can't happen for an array, verifier wants it */

	bpf_spin_lock(&s->lock);

	if (s->tag != tag) {
		s->tag = tag;
#pragma unroll
		for (int i = 0; i < FF_B_MAX; i++) {
			s->stamp[i] = now;
			s->tokens[i] = cfg->burst[i];
		}
		s->conn_ns = now;
		s->conn_count = 0;
	}

	if ((checks & FF_CHK_PKT) && !FF_TAKE(FF_B_PKT))
		reason = FF_STAT_DROP_RATE;
	else if ((checks & FF_CHK_SYN) && !FF_TAKE(FF_B_SYN))
		reason = FF_STAT_DROP_SYN_RATE;
	else if ((checks & FF_CHK_ICMP) && !FF_TAKE(FF_B_ICMP))
		reason = FF_STAT_DROP_ICMP_RATE;
	else if ((checks & FF_CHK_OOB) && !FF_TAKE(FF_B_OOB))
		reason = FF_STAT_DROP_OOB_RATE;
	else if (checks & FF_CHK_CONN) {
		/* Fixed window, not a running count of open flows: a running
		 * count drifts every time a flow gets evicted without a FIN,
		 * which under attack is all the time. */
		if (now - s->conn_ns >= cfg->conn_window_ns) {
			s->conn_ns = now;
			s->conn_count = 0;
		}
		if (cfg->conn_per_window && s->conn_count >= cfg->conn_per_window)
			reason = FF_STAT_DROP_CONN_RATE;
		else
			s->conn_count++;
	}

	bpf_spin_unlock(&s->lock);
	return reason;
}

/*
 * Box-wide ceiling for things spoofed sources make cheap (SYNs, OOB queries).
 * Per-source limits are useless against a source-rotating flood; this is the
 * one that actually holds. Per-CPU, each core gets pps / nr_cpus, no locks.
 * The approximation is fine because a spoofed flood spreads across RSS
 * queues pretty evenly - that's sort of the whole problem with it.
 */
static __always_inline bool ff_global_allow(struct ff_config *cfg, __u32 slot,
					    __u32 pps, __u64 now)
{
	struct ff_gbucket *b;
	__u32 share;

	if (!pps)
		return true;
	share = pps / (cfg->nr_cpus ? cfg->nr_cpus : 1);
	if (!share)
		share = 1;

	b = bpf_map_lookup_elem(&global, &slot);
	if (!b)
		return true;
	return ff_tb_take(&b->stamp, &b->tokens, now,
			  FF_NSEC_PER_SEC / share, share);
}

#endif /* FF_LIMIT_H */
