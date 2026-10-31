/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FF_L4_H
#define FF_L4_H

/* UDP source ports that only ever show up as reflected amplification. */
static __always_inline bool ff_amp_port(__u16 sport)
{
	switch (sport) {
	case 19:	/* chargen */
	case 53:	/* DNS */
	case 69:	/* TFTP */
	case 111:	/* portmap */
	case 123:	/* NTP */
	case 137:	/* NetBIOS */
	case 161:	/* SNMP */
	case 389:	/* CLDAP */
	case 427:	/* SLP - the 2023 one, 2200x */
	case 520:	/* RIPv1 */
	case 1434:	/* MS-SQL browser */
	case 1900:	/* SSDP */
	case 3283:	/* Apple Remote Desktop */
	case 3702:	/* WS-Discovery */
	case 5093:	/* Sentinel */
	case 5353:	/* mDNS */
	case 5683:	/* CoAP */
	case 10001:	/* Ubiquiti discovery */
	case 11211:	/* memcached */
	case 27015:	/* Source engine query */
	case 37810:	/* DVR DHCPDiscover */
		return true;
	default:
		return false;
	}
}

static __always_inline bool ff_port_match(const struct ff_config *cfg, __u16 dport)
{
	if (dport >= cfg->port_lo && dport <= cfg->port_hi)
		return true;
#pragma unroll
	for (int i = 0; i < FF_MAX_AUX_PORTS; i++)
		if (cfg->aux_ports[i] && dport == cfg->aux_ports[i])
			return true;
	return false;
}

/* Checks every game-port packet gets before protocol specifics. */
static __always_inline __u32 ff_game_port_gate(struct ff_config *cfg,
					       const struct ff_pkt *pkt)
{
	if (cfg->flags & FF_F_LOCKDOWN)
		return FF_STAT_DROP_LOCKDOWN;	/* allowlist already returned */
	if ((cfg->flags & FF_F_BOGON) && ff_is_bogon(pkt))
		return FF_STAT_DROP_BOGON;
	return FF_NO_VERDICT;
}

/* ------------------------------------------------------------------- UDP */

/*
 * CFX out-of-band packets (getinfo, getstatus, connect, rcon) start with
 * 0xFFFFFFFF. Tiny request, big reply: the cheapest thing to flood a FiveM
 * box with, so they get a budget of their own plus a global ceiling.
 */
static __always_inline bool ff_is_oob(void *payload, void *data_end)
{
	__u32 *magic = payload;

	if ((void *)(magic + 1) > data_end)
		return false;
	return *magic == 0xffffffffu;
}

static __always_inline __u32 ff_udp(struct ff_config *cfg, struct ff_pkt *pkt,
				    struct ff_l3 *l3, void *data_end, __u64 now)
{
	struct udphdr *udp = l3->l4;
	__u32 checks = FF_CHK_PKT;
	void *payload;
	__u32 plen, r;

	if ((void *)(udp + 1) > data_end)
		return FF_STAT_DROP_MALFORMED;
	if (bpf_ntohs(udp->len) < sizeof(*udp))
		return FF_STAT_DROP_MALFORMED;

	pkt->sport = bpf_ntohs(udp->source);
	pkt->dport = bpf_ntohs(udp->dest);

	if (!ff_port_match(cfg, pkt->dport))
		return FF_STAT_PASS_OTHER;

	r = ff_game_port_gate(cfg, pkt);
	if (r != FF_NO_VERDICT)
		return r;

	if (pkt->len > cfg->amp_limit && ff_amp_port(pkt->sport))
		return FF_STAT_DROP_AMP;

	payload = (void *)(udp + 1);
	/* measured, not claimed: udp->len is whatever the attacker typed */
	plen = payload <= l3->end ? (__u32)((long)l3->end - (long)payload) : 0;
	if (plen < cfg->udp_min_len ||
	    (cfg->udp_max_len && plen > cfg->udp_max_len))
		return FF_STAT_DROP_UDP_SIZE;

	if (plen >= 4 && ff_is_oob(payload, data_end)) {
		if (cfg->flags & FF_F_DROP_OOB)
			return FF_STAT_DROP_OOB;
		if (!ff_global_allow(cfg, FF_G_OOB, cfg->global_oob_pps, now))
			return FF_STAT_DROP_GLOBAL_OOB;
		checks |= FF_CHK_OOB;
	}

	return ff_source_check(cfg, &pkt->key, now, checks);
}

/* ------------------------------------------------------------------- TCP */

/* Combinations no real stack emits. Cheaper to kill here than in conntrack. */
static __always_inline bool ff_tcp_flags_ok(const struct tcphdr *tcp)
{
	if (!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst &&
	    !tcp->psh && !tcp->urg)
		return false;				/* null scan */
	if (tcp->syn && tcp->fin)		return false;
	if (tcp->syn && tcp->rst)		return false;
	if (tcp->fin && tcp->urg && tcp->psh)	return false;	/* xmas */
	if (tcp->fin && !tcp->ack)		return false;
	if (tcp->rst && (tcp->psh || tcp->urg))	return false;
	if (tcp->urg && !tcp->ack)		return false;
	return true;
}

static __always_inline __u32 ff_tcp(struct ff_config *cfg, struct ff_pkt *pkt,
				    struct ff_l3 *l3, void *data_end, __u64 now)
{
	struct tcphdr *tcp = l3->l4;
	struct ff_flow_key fk = {};
	struct ff_flow_val *fv;
	__u64 idle;
	__u32 hlen, r;

	if ((void *)(tcp + 1) > data_end)
		return FF_STAT_DROP_MALFORMED;
	if (tcp->doff < 5)
		return FF_STAT_DROP_MALFORMED;
	hlen = tcp->doff * 4;
	if ((void *)tcp + hlen > data_end)
		return FF_STAT_DROP_MALFORMED;

	pkt->sport = bpf_ntohs(tcp->source);
	pkt->dport = bpf_ntohs(tcp->dest);

	if (!ff_port_match(cfg, pkt->dport))
		return FF_STAT_PASS_OTHER;

	r = ff_game_port_gate(cfg, pkt);
	if (r != FF_NO_VERDICT)
		return r;

	if (!ff_tcp_flags_ok(tcp))
		return FF_STAT_DROP_TCP_FLAGS;

	__builtin_memcpy(fk.saddr, pkt->src, 16);
	__builtin_memcpy(fk.daddr, pkt->dst, 16);
	fk.sport = tcp->source;
	fk.dport = tcp->dest;
	fk.af = pkt->af;

	if (tcp->syn && !tcp->ack) {
		struct ff_flow_val nfv = { .last_ns = now };

		/* l3->end, not data_end, so runt-frame padding isn't payload */
		if ((void *)tcp + hlen < l3->end)
			return FF_STAT_DROP_TCP_SYNDATA;
		if (!ff_global_allow(cfg, FF_G_SYN, cfg->global_syn_pps, now))
			return FF_STAT_DROP_GLOBAL_SYN;

		r = ff_source_check(cfg, &pkt->key, now,
				    FF_CHK_PKT | FF_CHK_SYN | FF_CHK_CONN);
		if (r != FF_STAT_PASS)
			return r;

		bpf_map_update_elem(&flows, &fk, &nfv, BPF_ANY);
		return FF_STAT_PASS;
	}

	fv = bpf_map_lookup_elem(&flows, &fk);
	if (!fv) {
		/*
		 * Connections from before the filter loaded have no entry.
		 * Adopt them during the grace window instead of kicking the
		 * whole server; after that, strict mode drops.
		 */
		struct ff_flow_val nfv = { .last_ns = now };

		if (now >= cfg->tcp_learn_until_ns &&
		    (cfg->flags & FF_F_STRICT_TCP))
			return FF_STAT_DROP_TCP_NOFLOW;

		bpf_map_update_elem(&flows, &fk, &nfv, BPF_ANY);
		return ff_source_check(cfg, &pkt->key, now, FF_CHK_PKT);
	}

	idle = fv->closing ? FF_FLOW_CLOSE_NS : cfg->flow_idle_ns;
	if (now - fv->last_ns > idle) {
		bpf_map_delete_elem(&flows, &fk);
		if (cfg->flags & FF_F_STRICT_TCP)
			return FF_STAT_DROP_TCP_NOFLOW;
		return ff_source_check(cfg, &pkt->key, now, FF_CHK_PKT);
	}

	r = ff_source_check(cfg, &pkt->key, now, FF_CHK_PKT);
	if (r != FF_STAT_PASS)
		return r;

	if (tcp->rst) {
		bpf_map_delete_elem(&flows, &fk);
	} else {
		if (tcp->fin)
			fv->closing = 1;
		fv->last_ns = now;
	}
	return FF_STAT_PASS;
}

/* ------------------------------------------------------------------ ICMP */

static __always_inline __u32 ff_icmp(struct ff_config *cfg, struct ff_pkt *pkt,
				     struct ff_l3 *l3, void *data_end, __u64 now)
{
	struct icmphdr *icmp = l3->l4;
	bool echo;

	if (cfg->flags & FF_F_DROP_ICMP)
		return FF_STAT_DROP_ICMP;
	if ((void *)icmp + 4 > data_end)
		return FF_STAT_DROP_MALFORMED;

	if (l3->proto == IPPROTO_ICMP)
		echo = icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY;
	else
		echo = icmp->type == ICMPV6_ECHO_REQUEST ||
		       icmp->type == ICMPV6_ECHO_REPLY;

	if (echo) {
		if ((cfg->flags & FF_F_BOGON) && ff_is_bogon(pkt))
			return FF_STAT_DROP_BOGON;
		return ff_source_check(cfg, &pkt->key, now, FF_CHK_ICMP);
	}

	/*
	 * Non-echo is PMTU discovery, unreachables, time exceeded - TCP needs
	 * these and plenty of ISP routers send them from RFC1918 addresses,
	 * so no bogon screen. Rate limited, never dropped by default.
	 */
	return ff_source_check(cfg, &pkt->key, now, FF_CHK_PKT);
}

#endif /* FF_L4_H */
