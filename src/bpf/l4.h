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

/*
 * Transport header pointer from ctx + offset. The mask is for the verifier,
 * which can't see through the struct that l4_off came from; the parser
 * already rejected anything past FF_MAX_L4_OFF.
 */
static __always_inline void *ff_l4(struct xdp_md *ctx, const struct ff_l3 *l3)
{
	void *data = (void *)(long)ctx->data;
	__u32 off = l3->l4_off;

	if (off > FF_MAX_L4_OFF)
		return NULL;
	return data + off;
}

/* Bytes between the end of an L4 header and the end of the datagram. */
static __always_inline __u32 ff_payload_len(const struct ff_l3 *l3, __u32 hdr)
{
	__u32 start = (__u32)l3->l4_off + hdr;

	return l3->end_off > start ? l3->end_off - start : 0;
}

/* ------------------------------------------------------------------- UDP */

/*
 * CFX out-of-band packets (getinfo, getstatus, connect, rcon) start with
 * 0xFFFFFFFF. Tiny request, big reply: the cheapest thing to flood a FiveM
 * box with, so they get a budget of their own plus a global ceiling.
 */
FF_SUBPROG __u32 ff_udp(struct xdp_md *ctx, struct ff_config *cfg,
			struct ff_pkt *pkt, struct ff_l3 *l3, __u64 now)
{
	void *data_end = (void *)(long)ctx->data_end;
	__u32 checks = FF_CHK_PKT;
	struct udphdr *udp;
	bool oob = false;
	__u32 plen, r;

	if (!cfg || !pkt || !l3)
		return FF_STAT_PASS;

	udp = ff_l4(ctx, l3);
	if (!udp || (void *)(udp + 1) > data_end)
		return FF_STAT_DROP_MALFORMED;
	if (bpf_ntohs(udp->len) < sizeof(*udp))
		return FF_STAT_DROP_MALFORMED;

	pkt->sport = bpf_ntohs(udp->source);
	pkt->dport = bpf_ntohs(udp->dest);

	if (!ff_port_match(cfg, pkt->dport))
		return FF_STAT_PASS_OTHER;

	/* measured, not claimed: udp->len is whatever the attacker typed */
	plen = ff_payload_len(l3, sizeof(*udp));

	/* last packet read; see the note in ff_tcp about subprogram calls */
	if (plen >= 4) {
		__u32 *magic = (void *)(udp + 1);

		oob = (void *)(magic + 1) <= data_end && *magic == 0xffffffffu;
	}

	r = ff_game_port_gate(cfg, pkt);
	if (r != FF_NO_VERDICT)
		return r;

	if (pkt->len > cfg->amp_limit && ff_amp_port(pkt->sport))
		return FF_STAT_DROP_AMP;

	if (plen < cfg->udp_min_len ||
	    (cfg->udp_max_len && plen > cfg->udp_max_len))
		return FF_STAT_DROP_UDP_SIZE;

	if (oob) {
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

FF_SUBPROG __u32 ff_tcp(struct xdp_md *ctx, struct ff_config *cfg,
			struct ff_pkt *pkt, struct ff_l3 *l3, __u64 now)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ff_flow_key fk = {};
	struct ff_flow_val *fv;
	struct tcphdr *tcp;
	__u64 idle;
	__u32 hlen, r;
	bool syn, ack, fin, rst, flags_ok;

	if (!cfg || !pkt || !l3)
		return FF_STAT_PASS;

	tcp = ff_l4(ctx, l3);
	if (!tcp || (void *)(tcp + 1) > data_end)
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

	/*
	 * Everything we need from the header gets copied out before the first
	 * subprogram call. Depending on kernel version the verifier may treat
	 * packet pointers as stale after a call, and re-proving bounds is
	 * noisier than just not touching the packet again.
	 */
	flags_ok = ff_tcp_flags_ok(tcp);
	syn = tcp->syn;
	ack = tcp->ack;
	fin = tcp->fin;
	rst = tcp->rst;
	fk.sport = tcp->source;
	fk.dport = tcp->dest;

	r = ff_game_port_gate(cfg, pkt);
	if (r != FF_NO_VERDICT)
		return r;

	if (!flags_ok)
		return FF_STAT_DROP_TCP_FLAGS;

	__builtin_memcpy(fk.saddr, pkt->src, 16);
	__builtin_memcpy(fk.daddr, pkt->dst, 16);
	fk.af = pkt->af;

	if (syn && !ack) {
		struct ff_flow_val nfv = { .last_ns = now };

		/* end_off, not data_end, so runt-frame padding isn't payload */
		if (ff_payload_len(l3, hlen))
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

	if (rst) {
		bpf_map_delete_elem(&flows, &fk);
	} else {
		if (fin)
			fv->closing = 1;
		fv->last_ns = now;
	}
	return FF_STAT_PASS;
}

/* ------------------------------------------------------------------ ICMP */

/*
 * Not from linux/icmp.h: on current distros that drags in linux/if.h ->
 * sys/socket.h -> glibc's stubs-32.h, which doesn't exist under -target bpf.
 * Four constants and a header struct aren't worth the fight.
 */
#define FF_ICMP_ECHOREPLY	0
#define FF_ICMP_ECHO		8
#define FF_ICMP6_ECHO_REQUEST	128
#define FF_ICMP6_ECHO_REPLY	129

struct ff_icmphdr {
	__u8	type;
	__u8	code;
	__sum16	checksum;
};

FF_SUBPROG __u32 ff_icmp(struct xdp_md *ctx, struct ff_config *cfg,
			 struct ff_pkt *pkt, struct ff_l3 *l3, __u64 now)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ff_icmphdr *icmp;
	bool echo;

	if (!cfg || !pkt || !l3)
		return FF_STAT_PASS;

	if (cfg->flags & FF_F_DROP_ICMP)
		return FF_STAT_DROP_ICMP;

	icmp = ff_l4(ctx, l3);
	if (!icmp || (void *)(icmp + 1) > data_end)
		return FF_STAT_DROP_MALFORMED;

	if (l3->proto == IPPROTO_ICMP)
		echo = icmp->type == FF_ICMP_ECHO ||
		       icmp->type == FF_ICMP_ECHOREPLY;
	else
		echo = icmp->type == FF_ICMP6_ECHO_REQUEST ||
		       icmp->type == FF_ICMP6_ECHO_REPLY;

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
