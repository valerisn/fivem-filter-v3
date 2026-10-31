/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FF_PARSE_H
#define FF_PARSE_H

#define FF_V6_MAX_EXT 6		/* extension headers we bother walking */

struct ff_v6_frag {
	__u8   nexthdr;
	__u8   reserved;
	__be16 frag_off;
	__be32 identification;
};

/*
 * Returns 0 for a parsed IPv4/IPv6 packet, 1 for anything that isn't ours to
 * look at (ARP, LLDP, non-IP), -1 for malformed.
 *
 * Lengths come from the IP header and get clamped to data_end, never the
 * other way round: frames under 60 bytes arrive padded, so data_end lies
 * about where the datagram stops.
 */
FF_SUBPROG int ff_parse(struct xdp_md *ctx, struct ff_pkt *pkt, struct ff_l3 *l3)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	void *cur = (void *)(eth + 1);
	void *end;
	__u16 proto;

	if (!pkt || !l3)
		return -1;
	if (cur > data_end)
		return -1;
	proto = eth->h_proto;

	/* 802.1Q and QinQ, two deep is all anyone sane runs */
#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (proto != bpf_htons(ETH_P_8021Q) &&
		    proto != bpf_htons(ETH_P_8021AD))
			break;
		if (cur + 4 > data_end)
			return -1;
		proto = *(__u16 *)(cur + 2);
		cur += 4;
	}

	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = cur;
		__u32 hlen, tot;
		__u16 fo;

		if ((void *)(ip + 1) > data_end)
			return -1;
		if (ip->version != 4 || ip->ihl < 5)
			return -1;
		hlen = ip->ihl * 4;
		if (cur + hlen > data_end)
			return -1;
		tot = bpf_ntohs(ip->tot_len);
		if (tot < hlen)
			return -1;

		l3->iplen = tot;
		end = cur + tot;
		if (end > data_end)
			end = data_end;
		l3->end_off = (__u16)(end - data);

		pkt->af = FF_AF_INET;
		pkt->src[0] = ip->saddr;
		pkt->dst[0] = ip->daddr;
		pkt->key.a[0] = ip->saddr;
		pkt->key.a[3] = FF_AF_INET;
		pkt->proto = ip->protocol;

		fo = bpf_ntohs(ip->frag_off);
		l3->has_opts = ip->ihl > 5;
		l3->frag = (fo & 0x2000) || (fo & 0x1fff);
		l3->frag_first = (fo & 0x2000) && !(fo & 0x1fff);
		l3->frag_id = bpf_ntohs(ip->id);
		l3->proto = ip->protocol;
		l3->l4_off = (__u16)(cur + hlen - data);
		return 0;
	}

	if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = cur;
		__u8 nexthdr;
		__u32 tot;

		if ((void *)(ip6 + 1) > data_end)
			return -1;

		tot = sizeof(*ip6) + bpf_ntohs(ip6->payload_len);
		l3->iplen = tot;
		end = cur + tot;
		if (end > data_end)
			end = data_end;
		l3->end_off = (__u16)(end - data);

		pkt->af = FF_AF_INET6;
		__builtin_memcpy(pkt->src, &ip6->saddr, 16);
		__builtin_memcpy(pkt->dst, &ip6->daddr, 16);
		/* rate limit on the /64: the low half is the attacker's to pick */
		pkt->key.a[0] = pkt->src[0];
		pkt->key.a[1] = pkt->src[1];
		pkt->key.a[3] = FF_AF_INET6;

		nexthdr = ip6->nexthdr;
		cur = (void *)(ip6 + 1);

#pragma unroll
		for (int i = 0; i < FF_V6_MAX_EXT; i++) {
			struct ipv6_opt_hdr *oh;

			if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP ||
			    nexthdr == IPPROTO_ICMPV6)
				break;

			if (nexthdr == IPPROTO_FRAGMENT) {
				struct ff_v6_frag *fh = cur;
				__u16 off;

				if ((void *)(fh + 1) > data_end)
					return -1;
				off = bpf_ntohs(fh->frag_off);
				l3->frag = 1;
				l3->frag_first = !(off & 0xfff8);
				l3->frag_id = bpf_ntohl(fh->identification);
				nexthdr = fh->nexthdr;
				cur = (void *)(fh + 1);
				/* past this point a non-first fragment is
				 * payload, not headers - stop walking */
				if (!l3->frag_first)
					break;
				continue;
			}

			if (nexthdr != IPPROTO_HOPOPTS &&
			    nexthdr != IPPROTO_ROUTING &&
			    nexthdr != IPPROTO_DSTOPTS)
				break;	/* ESP/AH/unknown: leave it */

			oh = cur;
			if ((void *)(oh + 1) > data_end)
				return -1;
			nexthdr = oh->nexthdr;
			cur += (oh->hdrlen + 1) * 8;
			if (cur > data_end)
				return -1;
			l3->has_opts = 1;
		}

		/* 500 bytes of extension headers is not a game client */
		if (cur - data > FF_MAX_L4_OFF)
			return -1;

		pkt->proto = nexthdr;
		l3->proto = nexthdr;
		l3->l4_off = (__u16)(cur - data);
		return 0;
	}

	return 1;
}

#endif /* FF_PARSE_H */
