/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FF_VERDICT_H
#define FF_VERDICT_H

static __always_inline void ff_count(__u32 idx, __u32 len)
{
	struct ff_counter *c = bpf_map_lookup_elem(&stats, &idx);

	if (c) {
		/* per-CPU, so plain adds are fine */
		c->packets += 1;
		c->bytes += len;
	}
}

static __always_inline void ff_log(struct ff_config *cfg, struct ff_pkt *pkt,
				   __u32 reason, bool dry)
{
	struct ff_event *e;

	if (!(cfg->flags & FF_F_LOG) || !cfg->log_sample)
		return;
	if (cfg->log_sample > 1 && (bpf_get_prandom_u32() % cfg->log_sample))
		return;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;	/* ringbuf full: userspace isn't keeping up, oh well */

	e->ts_ns = bpf_ktime_get_ns();
	__builtin_memcpy(e->saddr, pkt->src, sizeof(e->saddr));
	__builtin_memcpy(e->daddr, pkt->dst, sizeof(e->daddr));
	e->sport = pkt->sport;
	e->dport = pkt->dport;
	e->pkt_len = pkt->len;
	e->proto = pkt->proto;
	e->af = pkt->af;
	e->reason = (__u8)reason;
	e->dry = dry;
	e->pad_[0] = 0;
	e->pad_[1] = 0;
	bpf_ringbuf_submit(e, 0);
}

/* The one exit. Counts, logs, honours dry-run. */
static __always_inline int ff_verdict(struct ff_config *cfg, struct ff_pkt *pkt,
				      __u32 reason)
{
	bool dry;

	if (reason >= FF_STAT_MAX)
		reason = FF_STAT_PASS;	/* belt and braces for the stats index */

	ff_count(reason, pkt->len);
	if (FF_STAT_IS_PASS(reason))
		return XDP_PASS;

	dry = cfg->flags & FF_F_DRY_RUN;
	ff_log(cfg, pkt, reason, dry);
	if (dry) {
		ff_count(FF_STAT_DRYRUN, pkt->len);
		return XDP_PASS;
	}
	return XDP_DROP;
}

#endif /* FF_VERDICT_H */
