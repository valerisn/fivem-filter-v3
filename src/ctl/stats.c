// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ctl.h"

void stats_read(struct ff_counter *out)
{
	int fd = pin_open("stats");
	int ncpu = libbpf_num_possible_cpus();
	struct ff_counter *per;

	if (ncpu < 1)
		die("cannot work out the CPU count");
	per = calloc((size_t)ncpu, sizeof(*per));
	if (!per)
		die("out of memory");

	for (__u32 i = 0; i < FF_STAT_MAX; i++) {
		out[i].packets = out[i].bytes = 0;
		if (bpf_map_lookup_elem(fd, &i, per))
			continue;
		for (int c = 0; c < ncpu; c++) {
			out[i].packets += per[c].packets;
			out[i].bytes += per[c].bytes;
		}
	}
	free(per);
	close(fd);
}

static void stats_reset(void)
{
	int fd = pin_open("stats");
	int ncpu = libbpf_num_possible_cpus();
	struct ff_counter *zeros = calloc(ncpu > 0 ? (size_t)ncpu : 1, sizeof(*zeros));

	for (__u32 k = 0; k < FF_STAT_MAX; k++)
		if (bpf_map_update_elem(fd, &k, zeros, BPF_ANY))
			die("resetting counters: %s", strerror(errno));
	free(zeros);
	close(fd);
}

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static __u64 dropped_total(const struct ff_counter *s, bool bytes)
{
	__u64 t = 0;

	for (int i = 0; i < FF_STAT_MAX; i++)
		if (!FF_STAT_IS_PASS(i) && i != FF_STAT_DRYRUN)
			t += bytes ? s[i].bytes : s[i].packets;
	return t;
}

static void print_json(const struct ff_counter *s)
{
	printf("{\"version\":\"%s\",\"counters\":{", FF_VERSION);
	for (int i = 0; i < FF_STAT_MAX; i++)
		printf("%s\"%s\":{\"packets\":%llu,\"bytes\":%llu}", i ? "," : "",
		       ff_stat_key[i], (unsigned long long)s[i].packets,
		       (unsigned long long)s[i].bytes);
	printf("},\"dropped\":{\"packets\":%llu,\"bytes\":%llu}}\n",
	       (unsigned long long)dropped_total(s, false),
	       (unsigned long long)dropped_total(s, true));
}

static void print_table(const struct ff_counter *cur, const struct ff_counter *prev,
			double secs, bool all)
{
	char a[24], b[24];

	printf("%-40s %12s %12s %12s %12s\n", "counter", "packets", "bytes", "pps", "bps");
	for (int i = 0; i < FF_STAT_MAX; i++) {
		double pps = 0, bps = 0;

		if (!all && !cur[i].packets && i != FF_STAT_PASS)
			continue;	/* idle counters are just noise */
		if (prev && secs > 0) {
			pps = (double)(cur[i].packets - prev[i].packets) / secs;
			bps = (double)(cur[i].bytes - prev[i].bytes) * 8.0 / secs;
		}
		fmt_count(cur[i].packets, a, sizeof(a));
		fmt_count(cur[i].bytes, b, sizeof(b));
		printf("%-40s %12s %12s %12.1f %12s\n", ff_stat_desc[i], a, b, pps,
		       (fmt_count((__u64)bps, a, sizeof(a)), a));
	}
}

int cmd_stats(int argc, char **argv)
{
	struct ff_counter cur[FF_STAT_MAX], prev[FF_STAT_MAX];
	bool watch = false, json = false, all = false, first = true;
	__u64 interval = 1, t0 = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--watch") || !strcmp(argv[i], "-w")) {
			watch = true;
			if (i + 1 < argc && argv[i + 1][0] != '-' &&
			    !parse_duration(argv[++i], &interval))
				die("--watch wants a number of seconds");
		} else if (!strcmp(argv[i], "--json")) {
			json = true;
		} else if (!strcmp(argv[i], "--all") || !strcmp(argv[i], "-a")) {
			all = true;
		} else if (!strcmp(argv[i], "--reset")) {
			stats_reset();
			printf("counters reset\n");
			return 0;
		} else {
			die("stats: unexpected '%s'", argv[i]);
		}
	}
	if (!interval)
		interval = 1;

	if (json && !watch) {
		stats_read(cur);
		print_json(cur);
		return 0;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	do {
		__u64 t = mono_ns();

		stats_read(cur);
		if (json) {
			print_json(cur);
			fflush(stdout);
		} else {
			if (watch && !first)
				printf("\033[H\033[J");
			print_table(cur, first ? NULL : prev,
				    first ? 0 : (double)(t - t0) / 1e9, all);
		}
		memcpy(prev, cur, sizeof(prev));
		t0 = t;
		first = false;
		if (watch && !stop)
			sleep((unsigned)interval);
	} while (watch && !stop);
	return 0;
}

int cmd_status(int argc, char **argv)
{
	struct ff_counter s[FF_STAT_MAX];
	struct attach_info ai;
	struct ff_config cfg;
	char a[24], b[24];
	__u64 dropped;

	(void)argc; (void)argv;
	if (!filter_loaded()) {
		printf("fivem-filter %s: not loaded\n", FF_VERSION);
		return 3;	/* LSB "not running", handy for scripts */
	}
	config_read(&cfg);

	printf("fivem-filter %s, ABI %u\n", FF_VERSION, cfg.abi_version);
	if (attach_info_read(&ai))
		printf("attached to      %s (prog id %u)\n", ai.iface, ai.prog_id);
	config_print(stdout, &cfg);

	stats_read(s);
	dropped = dropped_total(s, false);
	fmt_count(s[FF_STAT_PASS].packets + s[FF_STAT_PASS_ALLOW].packets, a, sizeof(a));
	fmt_count(dropped, b, sizeof(b));
	printf("\npassed %s, %s %s", a,
	       (cfg.flags & FF_F_DRY_RUN) ? "would have dropped" : "dropped", b);
	fmt_count(s[FF_STAT_PASS_OTHER].packets, a, sizeof(a));
	printf(", %s not for us\n", a);
	if (cfg.flags & FF_F_DRY_RUN)
		printf("DRY RUN is on - nothing is actually being dropped.\n");
	if (!(cfg.flags & FF_F_ENABLED))
		printf("filter is DISABLED (--on enabled to turn it back on).\n");
	return 0;
}

/* Partial live update: only what you name changes. */
int cmd_config(int argc, char **argv)
{
	struct load_opts lo = { 0 };
	struct ff_config cfg;
	bool changed = false;

	config_read(&cfg);
	if (parse_tunable_args(argc, argv, &cfg, &lo, &changed))
		die("config: unexpected argument '%s'", argv[1]);
	if (lo.iface || lo.obj || lo.conf || lo.xdp_mode || lo.force)
		die("interface, obj, config, mode and force only make sense for load");

	if (lo.grace_set)
		cfg.tcp_learn_until_ns = lo.grace_sec
			? mono_ns() + lo.grace_sec * FF_NSEC_PER_SEC : 0;

	if (changed) {
		config_write(&cfg);
		printf("config updated\n\n");
	}
	config_print(stdout, &cfg);
	return 0;
}
