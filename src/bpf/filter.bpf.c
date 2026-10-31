/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * fivem-filter v3 - XDP ingress filter for FiveM / RedM (CFX) servers.
 *
 * Pipeline, first match wins:
 *
 *   parse -> link-scope v6 -> scope (dst is ours?) -> v6 policy -> rules
 *         -> land -> ip options -> fragments -> UDP | TCP | ICMP | other
 *
 * The big change from v2 is that scope comes first. v2 ran blocklist,
 * lockdown and bogon checks on everything that hit the NIC, which made it
 * not-actually-safe on shared interfaces no matter what the README said.
 *
 * All tunables live in the config map; see src/shared/ff_abi.h.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "ff_abi.h"
#include "bogon.h"
#include "bucket.h"

#include "maps.h"
#include "parse.h"
#include "limit.h"
#include "verdict.h"
#include "policy.h"
#include "l4.h"

static __always_inline __u32 ff_decide(struct ff_config *cfg, struct ff_pkt *pkt,
				       struct ff_l3 *l3, void *data_end, __u64 now)
{
	__u32 r;

	if (pkt->af == FF_AF_INET6 && ff_v6_linkscope(pkt))
		return FF_STAT_PASS_OTHER;

	if (!ff_in_scope(cfg, pkt))
		return FF_STAT_PASS_OTHER;

	if (pkt->af == FF_AF_INET6 && (cfg->flags & FF_F_DROP_IPV6))
		return FF_STAT_DROP_IPV6;

	r = ff_rules(pkt, now);
	if (r != FF_NO_VERDICT)
		return r;

	/* v4 only. Comparing full v6 addresses would be fine too, but nobody
	 * has ever seen a v6 land attack in the wild and it's one less branch. */
	if (pkt->af == FF_AF_INET && pkt->src[0] == pkt->dst[0])
		return FF_STAT_DROP_LAND;

	if (l3->has_opts && (cfg->flags & FF_F_DROP_IP_OPTS))
		return FF_STAT_DROP_IP_OPTS;

	if (l3->frag) {
		if (cfg->flags & FF_F_DROP_FRAGS)
			return FF_STAT_DROP_FRAG;
		if (!l3->frag_first)
			return ff_frag_follow(pkt, l3, now);
		/* first fragment carries the L4 header: fall through and
		 * judge it like anything else, the caller remembers it */
	}

	switch (l3->proto) {
	case IPPROTO_UDP:
		return ff_udp(cfg, pkt, l3, data_end, now);
	case IPPROTO_TCP:
		return ff_tcp(cfg, pkt, l3, data_end, now);
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		return ff_icmp(cfg, pkt, l3, data_end, now);
	}

	/* GRE, ESP, SCTP, whatever: aimed at us but not a game port. The
	 * kernel answers unknown protocols with ICMP, so budget it. */
	return ff_source_check(cfg, &pkt->key, now, FF_CHK_PKT);
}

SEC("xdp")
int fivem_filter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ff_pkt pkt = {};
	struct ff_l3 l3 = {};
	struct ff_config *cfg;
	__u32 zero = 0, reason;
	__u64 now;
	int rc;

	cfg = bpf_map_lookup_elem(&config, &zero);
	if (!cfg || !(cfg->flags & FF_F_ENABLED))
		return XDP_PASS;

	rc = ff_parse(data, data_end, &pkt, &l3);
	if (rc > 0)
		return XDP_PASS;	/* ARP and friends, not even counted */
	if (rc < 0)
		return ff_verdict(cfg, &pkt, FF_STAT_DROP_MALFORMED);

	pkt.len = (__u16)l3.iplen;
	now = bpf_ktime_get_ns();

	reason = ff_decide(cfg, &pkt, &l3, data_end, now);

	if (l3.frag && l3.frag_first)
		ff_frag_remember(cfg, &pkt, &l3, reason, now);

	return ff_verdict(cfg, &pkt, reason);
}

char LICENSE[] SEC("license") = "GPL";
