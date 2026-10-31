// SPDX-License-Identifier: GPL-2.0-only
/*
 * Runs hand-built frames through the real filter.bpf.o with
 * BPF_PROG_TEST_RUN and checks both the XDP verdict and which counter moved.
 * Nothing gets attached anywhere; needs root only because loading BPF does.
 *
 *   sudo build/tests/test_xdp build/filter.bpf.o
 *
 * v2 had no way to test any of this short of pointing hping3 at a live box,
 * which is how half its bugs survived as long as they did.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ff_abi.h"
#include "bucket.h"
#include "pkt.h"

#define SERVER4 "45.90.12.10"
#define SERVER6 "2a0e:1234::10"
#define PLAYER4 "81.2.69.160"
#define PLAYER6 "2606:4700::1111"
#define GAME    30120

static int prog_fd, cfg_fd, stats_fd, rules4_fd, rules6_fd;
static int ncpu;
static struct ff_config cfg;
static int failed, total;
static const char *group = "";

static __u64 now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void push_cfg(void)
{
	__u32 zero = 0;

	if (bpf_map_update_elem(cfg_fd, &zero, &cfg, BPF_ANY)) {
		perror("config update");
		exit(2);
	}
}

/*
 * Fresh config per group. The seed bump puts every source in a new state
 * slot, which is a cheap way to reset all per-source buckets at once.
 */
static void reset(const char *name)
{
	static __u32 seed = 0x1234;

	group = name;
	memset(&cfg, 0, sizeof(cfg));
	cfg.abi_version = FF_ABI_VERSION;
	cfg.flags = FF_F_ENABLED | FF_F_BOGON | FF_F_STRICT_TCP;
	cfg.refill_ns[FF_B_PKT] = ff_rate_to_ns(1000);
	cfg.burst[FF_B_PKT] = 1000;
	cfg.refill_ns[FF_B_SYN] = ff_rate_to_ns(10);
	cfg.burst[FF_B_SYN] = 10;
	cfg.refill_ns[FF_B_ICMP] = ff_rate_to_ns(1);
	cfg.burst[FF_B_ICMP] = 2;
	cfg.refill_ns[FF_B_OOB] = ff_rate_to_ns(1);
	cfg.burst[FF_B_OOB] = 2;
	cfg.flow_idle_ns = 120 * FF_NSEC_PER_SEC;
	cfg.conn_window_ns = 60 * FF_NSEC_PER_SEC;
	cfg.frag_ttl_ns = 2 * FF_NSEC_PER_SEC;
	cfg.amp_limit = 512;
	cfg.udp_min_len = 1;
	cfg.udp_max_len = 1400;
	cfg.conn_per_window = 60;
	cfg.nr_cpus = 1;	/* we pin to one CPU, so one bucket is the whole budget */
	cfg.port_lo = GAME;
	cfg.port_hi = GAME;
	cfg.hash_seed = seed++;
	inet_pton(AF_INET, SERVER4, &cfg.v4_addr);
	inet_pton(AF_INET6, SERVER6, cfg.v6_addr);
	cfg.v6_set = 1;
	push_cfg();
}

static void stats_snapshot(__u64 *out)
{
	struct ff_counter per[ncpu];

	for (__u32 i = 0; i < FF_STAT_MAX; i++) {
		out[i] = 0;
		if (bpf_map_lookup_elem(stats_fd, &i, per))
			continue;
		for (int c = 0; c < ncpu; c++)
			out[i] += per[c].packets;
	}
}

static int run(struct frame *f)
{
	LIBBPF_OPTS(bpf_test_run_opts, o,
		.data_in = f->b,
		.data_size_in = (__u32)f->n,
		.repeat = 1,
	);

	if (bpf_prog_test_run_opts(prog_fd, &o)) {
		fprintf(stderr, "test_run: %s\n", strerror(errno));
		exit(2);
	}
	return (int)o.retval;
}

/* want_stat < 0 means "don't care which counter". */
static void expect_(int line, const char *what, struct frame *f,
		    int want_xdp, int want_stat)
{
	__u64 before[FF_STAT_MAX], after[FF_STAT_MAX];
	int got;

	stats_snapshot(before);
	got = run(f);
	stats_snapshot(after);
	total++;

	if (got != want_xdp) {
		failed++;
		fprintf(stderr, "FAIL [%s] line %d %s: verdict %s, want %s\n",
			group, line, what,
			got == XDP_DROP ? "DROP" : got == XDP_PASS ? "PASS" : "?",
			want_xdp == XDP_DROP ? "DROP" : "PASS");
	}
	if (want_stat >= 0 && after[want_stat] != before[want_stat] + 1) {
		failed++;
		fprintf(stderr, "FAIL [%s] line %d %s: counter '%s' moved by %llu, want 1. moved:",
			group, line, what, ff_stat_key[want_stat],
			(unsigned long long)(after[want_stat] - before[want_stat]));
		for (int i = 0; i < FF_STAT_MAX; i++)
			if (after[i] != before[i])
				fprintf(stderr, " %s", ff_stat_key[i]);
		fputc('\n', stderr);
	}
}

#define PASS(what, f, stat) expect_(__LINE__, what, f, XDP_PASS, stat)
#define DROP(what, f, stat) expect_(__LINE__, what, f, XDP_DROP, stat)
#define S(x) FF_STAT_##x

/* ------------------------------------------------------------ builders */

static void udp4(struct frame *f, const char *src, const char *dst,
		 uint16_t sport, uint16_t dport, size_t plen)
{
	f_eth(f, 0x0800);
	f_ip4(f, src, dst, 17, 0, 1);
	f_udp(f, sport, dport);
	f_fill(f, plen, 0xab);
	f_done(f);
	f_pad(f, 60);
}

static void oob4(struct frame *f, const char *src)
{
	f_eth(f, 0x0800);
	f_ip4(f, src, SERVER4, 17, 0, 1);
	f_udp(f, 50000, GAME);
	f_bytes(f, "\xff\xff\xff\xffgetinfo xyz", 15);
	f_done(f);
}

static void tcp4(struct frame *f, const char *src, uint16_t sport,
		 uint16_t dport, uint8_t flags, size_t plen)
{
	f_eth(f, 0x0800);
	f_ip4(f, src, SERVER4, 6, 0, 1);
	f_tcp(f, sport, dport, flags);
	f_fill(f, plen, 0x41);
	f_done(f);
	f_pad(f, 60);
}

static void udp6(struct frame *f, const char *src, const char *dst,
		 uint16_t dport, size_t plen)
{
	f_eth(f, 0x86dd);
	f_ip6(f, src, dst, 17);
	f_udp(f, 50000, dport);
	f_fill(f, plen, 0xcd);
	f_done(f);
}

/* -------------------------------------------------------------- tests */

static void t_scope(void)
{
	struct frame f;

	reset("scope");
	udp4(&f, PLAYER4, "45.90.12.11", 5000, GAME, 100);
	PASS("other destination untouched", &f, S(PASS_OTHER));

	udp4(&f, "10.0.0.5", "45.90.12.11", 5000, GAME, 100);
	PASS("bogon to other destination untouched", &f, S(PASS_OTHER));

	udp4(&f, "10.0.0.5", SERVER4, 53, 41000, 100);
	PASS("bogon to non-game port (e.g. VPC DNS answer)", &f, S(PASS_OTHER));

	udp4(&f, "169.254.169.254", SERVER4, 80, 41001, 100);
	PASS("cloud metadata reply", &f, S(PASS_OTHER));

	f_eth(&f, 0x0806);
	f_fill(&f, 46, 0);
	PASS("arp", &f, -1);

	cfg.flags &= ~FF_F_ENABLED;
	push_cfg();
	udp4(&f, "10.0.0.5", SERVER4, 5000, GAME, 100);
	PASS("disabled passes everything", &f, -1);
}

static void t_udp(void)
{
	struct frame f;

	reset("udp");
	udp4(&f, PLAYER4, SERVER4, 50000, GAME, 120);
	PASS("player to game port", &f, S(PASS));

	udp4(&f, "10.1.2.3", SERVER4, 50000, GAME, 120);
	DROP("rfc1918 to game port", &f, S(DROP_BOGON));

	udp4(&f, "100.64.0.1", SERVER4, 50000, GAME, 120);
	DROP("cgnat to game port", &f, S(DROP_BOGON));

	udp4(&f, PLAYER4, SERVER4, 11211, GAME, 1000);
	DROP("memcached reflection", &f, S(DROP_AMP));

	udp4(&f, PLAYER4, SERVER4, 11211, GAME, 100);
	PASS("small packet from amp port is fine", &f, S(PASS));

	udp4(&f, PLAYER4, SERVER4, 50000, GAME, 0);
	DROP("empty payload", &f, S(DROP_UDP_SIZE));

	udp4(&f, PLAYER4, SERVER4, 50000, GAME, 1401);
	DROP("oversize payload", &f, S(DROP_UDP_SIZE));

	/* 1 byte payload, padded to 60 on the wire: must be measured as 1 */
	udp4(&f, PLAYER4, SERVER4, 50000, GAME, 1);
	PASS("runt frame padding not counted as payload", &f, S(PASS));

	udp4(&f, PLAYER4, SERVER4, 50000, GAME, 1);
	f.b[14 + 20 + 4] = 0;
	f.b[14 + 20 + 5] = 4;
	DROP("udp length below header size", &f, S(DROP_MALFORMED));

	f_eth(&f, 0x0800);
	f_vlan(&f, 100);
	f_ip4(&f, "10.9.9.9", SERVER4, 17, 0, 1);
	f_udp(&f, 1, GAME);
	f_fill(&f, 50, 1);
	f_done(&f);
	DROP("vlan-tagged bogon still parsed", &f, S(DROP_BOGON));

	udp4(&f, SERVER4, SERVER4, GAME, GAME, 20);
	DROP("land", &f, S(DROP_LAND));

	f_eth(&f, 0x0800);
	f_fill(&f, 10, 0x45);
	DROP("truncated ip header", &f, S(DROP_MALFORMED));
}

static void t_rate(void)
{
	struct frame f;
	int dropped = 0;

	reset("rate");
	cfg.refill_ns[FF_B_PKT] = ff_rate_to_ns(1);
	cfg.burst[FF_B_PKT] = 5;
	push_cfg();

	udp4(&f, PLAYER4, SERVER4, 50000, GAME, 100);
	for (int i = 0; i < 5; i++)
		PASS("within burst", &f, S(PASS));
	DROP("burst exhausted", &f, S(DROP_RATE));

	udp4(&f, "81.2.69.161", SERVER4, 50000, GAME, 100);
	PASS("other source has its own bucket", &f, S(PASS));

	/* OOB: own bucket of 2, independent of the packet bucket */
	reset("oob");
	oob4(&f, PLAYER4);
	PASS("getinfo 1", &f, S(PASS));
	PASS("getinfo 2", &f, S(PASS));
	DROP("getinfo 3 over oob budget", &f, S(DROP_OOB_RATE));
	udp4(&f, PLAYER4, SERVER4, 50000, GAME, 100);
	PASS("gameplay unaffected by oob budget", &f, S(PASS));

	cfg.flags |= FF_F_DROP_OOB;
	push_cfg();
	oob4(&f, "81.2.69.170");
	DROP("drop-oob", &f, S(DROP_OOB));

	/* global oob ceiling across rotating sources */
	reset("global-oob");
	cfg.global_oob_pps = 3;
	push_cfg();
	for (int i = 0; i < 6; i++) {
		char src[32];

		snprintf(src, sizeof(src), "81.2.70.%d", i + 1);
		oob4(&f, src);
		dropped += run(&f) == XDP_DROP;
	}
	total++;
	if (dropped != 3) {
		failed++;
		fprintf(stderr, "FAIL [global-oob] %d of 6 dropped, want 3\n", dropped);
	}
}

static void t_tcp(void)
{
	struct frame f;
	int dropped = 0;

	reset("tcp");
	tcp4(&f, PLAYER4, 40001, GAME, TH_SYN, 0);
	PASS("syn", &f, S(PASS));
	tcp4(&f, PLAYER4, 40001, GAME, TH_ACK, 0);
	PASS("ack on known flow", &f, S(PASS));
	tcp4(&f, PLAYER4, 40001, GAME, TH_ACK | TH_PSH, 200);
	PASS("data on known flow", &f, S(PASS));

	tcp4(&f, PLAYER4, 40002, GAME, TH_ACK, 0);
	DROP("ack without flow (strict)", &f, S(DROP_TCP_NOFLOW));

	tcp4(&f, PLAYER4, 40003, GAME, TH_SYN, 64);
	DROP("syn with payload", &f, S(DROP_TCP_SYNDATA));

	tcp4(&f, PLAYER4, 40004, GAME, TH_FIN | TH_URG | TH_PSH, 0);
	DROP("xmas", &f, S(DROP_TCP_FLAGS));
	tcp4(&f, PLAYER4, 40004, GAME, 0, 0);
	DROP("null scan", &f, S(DROP_TCP_FLAGS));
	tcp4(&f, PLAYER4, 40004, GAME, TH_SYN | TH_FIN, 0);
	DROP("syn+fin", &f, S(DROP_TCP_FLAGS));

	tcp4(&f, PLAYER4, 40005, 22, TH_ACK, 0);
	PASS("ssh untouched by strict tcp", &f, S(PASS_OTHER));

	/* graceful close: FIN, then the final ACK must still match */
	tcp4(&f, PLAYER4, 40010, GAME, TH_SYN, 0);
	PASS("close: syn", &f, S(PASS));
	tcp4(&f, PLAYER4, 40010, GAME, TH_FIN | TH_ACK, 0);
	PASS("close: fin", &f, S(PASS));
	tcp4(&f, PLAYER4, 40010, GAME, TH_ACK, 0);
	PASS("close: final ack after fin", &f, S(PASS));

	tcp4(&f, PLAYER4, 40011, GAME, TH_SYN, 0);
	PASS("rst: syn", &f, S(PASS));
	tcp4(&f, PLAYER4, 40011, GAME, TH_RST | TH_ACK, 0);
	PASS("rst", &f, S(PASS));
	tcp4(&f, PLAYER4, 40011, GAME, TH_ACK, 0);
	DROP("flow gone after rst", &f, S(DROP_TCP_NOFLOW));

	/* grace window adopts unknown flows */
	cfg.tcp_learn_until_ns = now_ns() + 30 * FF_NSEC_PER_SEC;
	push_cfg();
	tcp4(&f, PLAYER4, 40020, GAME, TH_ACK, 10);
	PASS("pre-existing flow adopted during grace", &f, S(PASS));
	cfg.tcp_learn_until_ns = 0;
	push_cfg();
	PASS("adopted flow survives the grace window", &f, S(PASS));

	/* SYN bucket: burst 10, so the 11th from one source drops */
	reset("syn-rate");
	for (int i = 0; i < 10; i++) {
		tcp4(&f, PLAYER4, (uint16_t)(41000 + i), GAME, TH_SYN, 0);
		PASS("parallel connects within syn burst", &f, S(PASS));
	}
	tcp4(&f, PLAYER4, 41100, GAME, TH_SYN, 0);
	DROP("11th syn", &f, S(DROP_SYN_RATE));

	reset("conn-quota");
	cfg.refill_ns[FF_B_SYN] = 0;
	cfg.conn_per_window = 3;
	push_cfg();
	for (int i = 0; i < 3; i++) {
		tcp4(&f, PLAYER4, (uint16_t)(42000 + i), GAME, TH_SYN, 0);
		PASS("within conn quota", &f, S(PASS));
	}
	tcp4(&f, PLAYER4, 42100, GAME, TH_SYN, 0);
	DROP("conn quota", &f, S(DROP_CONN_RATE));

	reset("global-syn");
	cfg.global_syn_pps = 4;
	push_cfg();
	for (int i = 0; i < 8; i++) {
		char src[32];

		snprintf(src, sizeof(src), "81.2.71.%d", i + 1);
		tcp4(&f, src, 43000, GAME, TH_SYN, 0);
		dropped += run(&f) == XDP_DROP;
	}
	total++;
	if (dropped != 4) {
		failed++;
		fprintf(stderr, "FAIL [global-syn] %d of 8 dropped, want 4\n", dropped);
	}
}

static void t_icmp(void)
{
	struct frame f;

	reset("icmp");
	f_eth(&f, 0x0800);
	f_ip4(&f, PLAYER4, SERVER4, 1, 0, 1);
	f_icmp(&f, 8);
	f_done(&f);
	f_pad(&f, 60);
	PASS("ping 1", &f, S(PASS));
	PASS("ping 2", &f, S(PASS));
	DROP("ping 3 over echo budget", &f, S(DROP_ICMP_RATE));

	f_eth(&f, 0x0800);
	f_ip4(&f, "10.20.30.40", SERVER4, 1, 0, 1);
	f_icmp(&f, 3);
	f_done(&f);
	f_pad(&f, 60);
	PASS("frag-needed from an rfc1918 router hop", &f, S(PASS));

	f_eth(&f, 0x0800);
	f_ip4(&f, "10.20.30.40", SERVER4, 1, 0, 1);
	f_icmp(&f, 8);
	f_done(&f);
	f_pad(&f, 60);
	DROP("ping from bogon", &f, S(DROP_BOGON));

	cfg.flags |= FF_F_DROP_ICMP;
	push_cfg();
	DROP("drop-icmp", &f, S(DROP_ICMP));
}

static void t_frag(void)
{
	struct frame f;

	reset("frag");
	/* first fragment of a big DNS answer to the server's resolver */
	f_eth(&f, 0x0800);
	f_ip4(&f, "1.1.1.1", SERVER4, 17, 0x2000, 777);
	f_udp(&f, 53, 41234);
	f_fill(&f, 1400, 0);
	f_done(&f);
	PASS("first fragment, non-game port", &f, S(PASS_OTHER));

	f_eth(&f, 0x0800);
	f_ip4(&f, "1.1.1.1", SERVER4, 17, 0x00b9, 777);
	f_fill(&f, 300, 0);
	f_done(&f);
	PASS("trailing fragment inherits pass", &f, S(PASS_OTHER));

	f_eth(&f, 0x0800);
	f_ip4(&f, "1.1.1.1", SERVER4, 17, 0x00b9, 778);
	f_fill(&f, 300, 0);
	f_done(&f);
	DROP("orphan fragment", &f, S(DROP_FRAG_ORPHAN));

	f_eth(&f, 0x0800);
	f_ip4(&f, PLAYER4, SERVER4, 17, 0x2000, 900);
	f_udp(&f, 11211, GAME);
	f_fill(&f, 1400, 0);
	f_done(&f);
	DROP("first fragment of amp flood", &f, S(DROP_AMP));

	f_eth(&f, 0x0800);
	f_ip4(&f, PLAYER4, SERVER4, 17, 0x00b9, 900);
	f_fill(&f, 1000, 0);
	f_done(&f);
	DROP("trailing fragment inherits the drop", &f, S(DROP_AMP));

	f_eth(&f, 0x86dd);
	f_ip6(&f, PLAYER6, SERVER6, 44);
	f_frag6(&f, 17, 0, 1, 0xabcdef);
	f_udp(&f, 53, 41000);
	f_fill(&f, 1200, 0);
	f_done(&f);
	PASS("v6 first fragment", &f, S(PASS_OTHER));

	f_eth(&f, 0x86dd);
	f_ip6(&f, PLAYER6, SERVER6, 44);
	f_frag6(&f, 17, 151, 0, 0xabcdef);
	f_fill(&f, 200, 0);
	f_done(&f);
	PASS("v6 trailing fragment", &f, S(PASS_OTHER));

	cfg.flags |= FF_F_DROP_FRAGS;
	push_cfg();
	DROP("drop-frags", &f, S(DROP_FRAG));
}

static void t_v6(void)
{
	struct frame f;

	reset("ipv6");
	udp6(&f, PLAYER6, SERVER6, GAME, 100);
	PASS("v6 player", &f, S(PASS));

	udp6(&f, "2001:db8::1", SERVER6, GAME, 100);
	DROP("v6 documentation prefix", &f, S(DROP_BOGON));

	udp6(&f, "fd00::1", SERVER6, GAME, 100);
	DROP("v6 ula", &f, S(DROP_BOGON));

	udp6(&f, PLAYER6, "2a0e:1234::11", GAME, 100);
	PASS("other v6 destination in the same /64", &f, S(PASS_OTHER));

	/* neighbour solicitation: fe80 source, solicited-node multicast dst */
	f_eth(&f, 0x86dd);
	f_ip6(&f, "fe80::1", "ff02::1:ff00:10", 58);
	f_icmp(&f, 135);
	f_fill(&f, 16, 0);
	f_done(&f);
	PASS("ndp neighbour solicitation", &f, S(PASS_OTHER));

	/* NS straight to our unicast address from a link-local router */
	f_eth(&f, 0x86dd);
	f_ip6(&f, "fe80::1", SERVER6, 58);
	f_icmp(&f, 135);
	f_fill(&f, 16, 0);
	f_done(&f);
	PASS("unicast ndp from link-local", &f, S(PASS_OTHER));

	cfg.flags |= FF_F_DROP_IPV6;
	push_cfg();
	udp6(&f, PLAYER6, SERVER6, GAME, 100);
	DROP("drop-ipv6", &f, S(DROP_IPV6));
	f_eth(&f, 0x86dd);
	f_ip6(&f, "fe80::1", "ff02::1:ff00:10", 58);
	f_icmp(&f, 135);
	f_fill(&f, 16, 0);
	f_done(&f);
	PASS("drop-ipv6 still leaves ndp alone", &f, S(PASS_OTHER));
}

static void add_rule4(const char *a, __u32 plen, __u8 action, __u64 expires)
{
	struct ff_lpm4 k = { .prefixlen = plen };
	struct ff_rule r = { .expires_ns = expires, .action = action };

	inet_pton(AF_INET, a, k.addr);
	if (bpf_map_update_elem(rules4_fd, &k, &r, BPF_ANY)) {
		perror("rules4");
		exit(2);
	}
}

static void add_rule6(const char *a, __u32 plen, __u8 action)
{
	struct ff_lpm6 k = { .prefixlen = plen };
	struct ff_rule r = { .action = action };

	inet_pton(AF_INET6, a, k.addr);
	if (bpf_map_update_elem(rules6_fd, &k, &r, BPF_ANY)) {
		perror("rules6");
		exit(2);
	}
}

static void t_rules(void)
{
	struct frame f;

	reset("rules");
	add_rule4("62.10.0.0", 16, FF_ACT_BLOCK, 0);
	add_rule4("62.10.5.5", 32, FF_ACT_ALLOW, 0);
	add_rule4("62.11.0.0", 16, FF_ACT_BLOCK, 1);	/* expired long ago */
	add_rule4("10.50.0.0", 16, FF_ACT_ALLOW, 0);
	add_rule6("2a01:4f8::", 32, FF_ACT_BLOCK);
	add_rule6("2a01:4f8::77", 128, FF_ACT_ALLOW);

	udp4(&f, "62.10.1.1", SERVER4, 5000, GAME, 50);
	DROP("blocked /16", &f, S(DROP_BLOCK));
	udp4(&f, "62.10.1.1", SERVER4, 5000, 22, 50);
	DROP("block applies to every port on the protected address", &f, S(DROP_BLOCK));
	udp4(&f, "62.10.5.5", SERVER4, 5000, GAME, 50);
	PASS("allowed /32 inside blocked /16", &f, S(PASS_ALLOW));
	udp4(&f, "62.11.1.1", SERVER4, 5000, GAME, 50);
	PASS("expired block", &f, S(PASS));
	udp4(&f, "10.50.0.9", SERVER4, 5000, GAME, 50);
	PASS("allowlist beats the bogon screen", &f, S(PASS_ALLOW));
	udp4(&f, "62.10.1.1", "45.90.12.99", 5000, GAME, 50);
	PASS("block doesn't reach other destinations", &f, S(PASS_OTHER));

	udp6(&f, "2a01:4f8::1", SERVER6, GAME, 50);
	DROP("v6 blocked /32", &f, S(DROP_BLOCK));
	udp6(&f, "2a01:4f8::77", SERVER6, GAME, 50);
	PASS("v6 allowed /128 inside it", &f, S(PASS_ALLOW));

	cfg.flags |= FF_F_LOCKDOWN;
	push_cfg();
	udp4(&f, PLAYER4, SERVER4, 5000, GAME, 50);
	DROP("lockdown", &f, S(DROP_LOCKDOWN));
	udp4(&f, "62.10.5.5", SERVER4, 5000, GAME, 50);
	PASS("lockdown lets allowlisted through", &f, S(PASS_ALLOW));
	tcp4(&f, PLAYER4, 40000, 22, TH_SYN, 0);
	PASS("lockdown leaves ssh alone", &f, S(PASS_OTHER));
}

static void t_misc(void)
{
	struct frame f;

	reset("dry-run");
	cfg.flags |= FF_F_DRY_RUN;
	push_cfg();
	udp4(&f, "10.1.1.1", SERVER4, 5000, GAME, 50);
	PASS("dry-run passes a bogon", &f, S(DROP_BOGON));
	PASS("and counts it as dry-run", &f, S(DRYRUN));

	reset("ip-options");
	f_eth(&f, 0x0800);
	f_ip4_opts(&f, PLAYER4, SERVER4, 17);
	f_udp(&f, 5000, GAME);
	f_fill(&f, 50, 0);
	f_done(&f);
	PASS("options allowed by default", &f, S(PASS));
	cfg.flags |= FF_F_DROP_IP_OPTS;
	push_cfg();
	DROP("drop-ip-opts", &f, S(DROP_IP_OPTS));

	reset("aux-ports");
	cfg.aux_ports[0] = 40120;
	push_cfg();
	tcp4(&f, PLAYER4, 40000, 40120, TH_ACK, 0);
	DROP("aux port gets strict tcp", &f, S(DROP_TCP_NOFLOW));
	tcp4(&f, PLAYER4, 40000, 40121, TH_ACK, 0);
	PASS("neighbouring port untouched", &f, S(PASS_OTHER));

	reset("port-range");
	cfg.port_hi = GAME + 9;
	push_cfg();
	udp4(&f, "10.0.0.1", SERVER4, 5000, GAME + 9, 50);
	DROP("top of port range", &f, S(DROP_BOGON));
	udp4(&f, "10.0.0.1", SERVER4, 5000, GAME + 10, 50);
	PASS("one past the range", &f, S(PASS_OTHER));

	reset("any-destination");
	cfg.v4_addr = 0;
	push_cfg();
	udp4(&f, "10.0.0.1", "45.90.12.200", 5000, GAME, 50);
	DROP("no --ip filters every destination", &f, S(DROP_BOGON));
}

static int open_fd(struct bpf_object *obj, const char *name)
{
	struct bpf_map *m = bpf_object__find_map_by_name(obj, name);

	if (!m) {
		fprintf(stderr, "object has no map '%s'\n", name);
		exit(2);
	}
	return bpf_map__fd(m);
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	cpu_set_t set;

	if (argc < 2) {
		fprintf(stderr, "usage: %s filter.bpf.o\n", argv[0]);
		return 2;
	}

	/* per-CPU global buckets: stay on one CPU or the budget tests lie */
	CPU_ZERO(&set);
	CPU_SET(0, &set);
	if (sched_setaffinity(0, sizeof(set), &set))
		perror("sched_setaffinity (global bucket tests may flake)");

	ncpu = libbpf_num_possible_cpus();
	obj = bpf_object__open_file(argv[1], NULL);
	if (!obj || bpf_object__load(obj)) {
		fprintf(stderr, "cannot load %s: %s\n", argv[1], strerror(errno));
		return 2;
	}
	prog = bpf_object__find_program_by_name(obj, "fivem_filter");
	if (!prog) {
		fprintf(stderr, "no fivem_filter program\n");
		return 2;
	}
	prog_fd = bpf_program__fd(prog);
	cfg_fd = open_fd(obj, "config");
	stats_fd = open_fd(obj, "stats");
	rules4_fd = open_fd(obj, "rules4");
	rules6_fd = open_fd(obj, "rules6");

	t_scope();
	t_udp();
	t_rate();
	t_tcp();
	t_icmp();
	t_frag();
	t_v6();
	t_rules();
	t_misc();

	printf("%-14s %d/%d passed\n", "xdp", total - failed, total);
	bpf_object__close(obj);
	return failed ? 1 : 0;
}
