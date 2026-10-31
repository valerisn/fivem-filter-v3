/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Address-level policy: what counts as "ours", allow/block rules, martians,
 * and the fragment verdict cache.
 */
#ifndef FF_POLICY_H
#define FF_POLICY_H

/* Sentinel for "no rule matched, keep going". Never reaches ff_verdict. */
#define FF_NO_VERDICT FF_STAT_MAX

/*
 * Link-scope IPv6 (NDP, RA, MLD, DAD) can't arrive from the internet, and
 * the box stops having IPv6 at all if we eat it. v2 ran the bogon screen
 * before anything else, saw fe80:: sources, and dropped neighbour discovery.
 */
static __always_inline bool ff_v6_linkscope(const struct ff_pkt *pkt)
{
	__u32 s0 = bpf_ntohl(pkt->src[0]);
	__u32 d0 = bpf_ntohl(pkt->dst[0]);

	return (s0 >> 22) == 0x3fa ||	/* src fe80::/10 */
	       (d0 >> 24) == 0xff ||	/* dst multicast */
	       (!pkt->src[0] && !pkt->src[1] && !pkt->src[2] && !pkt->src[3]);
}

/* Is this packet addressed to something we protect? */
static __always_inline bool ff_in_scope(const struct ff_config *cfg,
					const struct ff_pkt *pkt)
{
	if (pkt->af == FF_AF_INET)
		return !cfg->v4_addr || pkt->dst[0] == cfg->v4_addr;

	if (!cfg->v6_set)
		return true;

	/* not memcmp: clang is allowed to turn that into a libcall, and BPF
	 * has no libc to call */
	__u32 w[4];

	__builtin_memcpy(w, cfg->v6_addr, 16);
	return pkt->dst[0] == w[0] && pkt->dst[1] == w[1] &&
	       pkt->dst[2] == w[2] && pkt->dst[3] == w[3];
}

/* Subprogram: the bogon tables are a wall of branches, and inlined into
 * every caller they were most of what blew the verifier's budget. */
FF_SUBPROG int ff_is_bogon(const struct ff_pkt *pkt)
{
	if (!pkt)
		return 0;
	if (pkt->af == FF_AF_INET)
		return ff_bogon4(bpf_ntohl(pkt->src[0]));
	return ff_bogon6(bpf_ntohl(pkt->src[0]), bpf_ntohl(pkt->src[1]),
			 bpf_ntohl(pkt->src[2]), bpf_ntohl(pkt->src[3]));
}

/*
 * Longest-prefix match over one trie per family. Returns PASS_ALLOW,
 * DROP_BLOCK, or FF_NO_VERDICT.
 *
 * Expired rules simply stop matching. The kernel can't delete them from here
 * (a trie lookup doesn't hand back the matched key), so `fivemctl reap` on a
 * timer cleans up. Known wart: an expired /32 inside a live /24 shadows the
 * /24 until reaped. The timer runs every minute so it's a short window.
 */
static __always_inline __u32 ff_rules(const struct ff_pkt *pkt, __u64 now)
{
	struct ff_rule *r;

	if (pkt->af == FF_AF_INET) {
		struct ff_lpm4 k = { .prefixlen = 32 };

		__builtin_memcpy(k.addr, &pkt->src[0], 4);
		r = bpf_map_lookup_elem(&rules4, &k);
	} else {
		struct ff_lpm6 k = { .prefixlen = 128 };

		__builtin_memcpy(k.addr, pkt->src, 16);
		r = bpf_map_lookup_elem(&rules6, &k);
	}

	if (!r || (r->expires_ns && now > r->expires_ns))
		return FF_NO_VERDICT;

	/*
	 * Sampled hit counter. An atomic add on every packet from a blocked /16
	 * means every core bouncing the same cacheline, which costs more than
	 * the drop does. 1-in-64 with +64 is plenty accurate for "is this rule
	 * doing anything".
	 */
	if (!(bpf_get_prandom_u32() & 63))
		__sync_fetch_and_add(&r->hits, 64);

	return r->action == FF_ACT_ALLOW ? FF_STAT_PASS_ALLOW : FF_STAT_DROP_BLOCK;
}

static __always_inline void ff_frag_key_init(struct ff_frag_key *k,
					     const struct ff_pkt *pkt,
					     const struct ff_l3 *l3)
{
	__builtin_memcpy(k->saddr, pkt->src, 16);
	__builtin_memcpy(k->daddr, pkt->dst, 16);
	k->id = l3->frag_id;
	k->proto = l3->proto;
	k->af = pkt->af;
	k->pad_ = 0;
}

static __always_inline void ff_frag_remember(struct ff_config *cfg,
					     const struct ff_pkt *pkt,
					     const struct ff_l3 *l3,
					     __u32 reason, __u64 now)
{
	struct ff_frag_key k;
	struct ff_frag_val v = {};
	__u64 ttl = cfg->frag_ttl_ns ? cfg->frag_ttl_ns : FF_DEFAULT_FRAG_TTL_NS;

	ff_frag_key_init(&k, pkt, l3);
	v.expires_ns = now + ttl;
	v.reason = reason;
	bpf_map_update_elem(&frags, &k, &v, BPF_ANY);
}

/*
 * A later fragment inherits whatever its first fragment got. No first
 * fragment seen (reordered, or never sent - which is the attack) means drop.
 * Reordering that badly is rare enough that we eat the occasional loss.
 */
static __always_inline __u32 ff_frag_follow(const struct ff_pkt *pkt,
					    const struct ff_l3 *l3, __u64 now)
{
	struct ff_frag_key k;
	struct ff_frag_val *v;

	ff_frag_key_init(&k, pkt, l3);
	v = bpf_map_lookup_elem(&frags, &k);
	if (!v || now > v->expires_ns)
		return FF_STAT_DROP_FRAG_ORPHAN;
	return v->reason;
}

#endif /* FF_POLICY_H */
