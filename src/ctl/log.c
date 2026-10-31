// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "ctl.h"

struct log_opts {
	bool json;
	int only;		/* -1 = every reason */
	__u64 shown;
};

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static int on_event(void *ctx, void *data, size_t len)
{
	struct log_opts *lo = ctx;
	const struct ff_event *e = data;
	char src[64], dst[64], ts[16];
	time_t now = time(NULL);
	struct tm tm;

	if (len < sizeof(*e))
		return 0;
	if (lo->only >= 0 && e->reason != lo->only)
		return 0;

	fmt_addr(e->af, e->saddr, src, sizeof(src));
	fmt_addr(e->af, e->daddr, dst, sizeof(dst));
	localtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%H:%M:%S", &tm);

	if (lo->json) {
		printf("{\"time\":%lld,\"action\":\"%s\",\"reason\":\"%s\",\"proto\":%u,"
		       "\"src\":\"%s\",\"sport\":%u,\"dst\":\"%s\",\"dport\":%u,\"len\":%u}\n",
		       (long long)now, e->dry ? "would-drop" : "drop",
		       e->reason < FF_STAT_MAX ? ff_stat_key[e->reason] : "unknown",
		       e->proto, src, e->sport, dst, e->dport, e->pkt_len);
	} else {
		/* brackets around v6 so the :port isn't ambiguous */
		const char *l = e->af == FF_AF_INET6 ? "[" : "";
		const char *r = e->af == FF_AF_INET6 ? "]" : "";

		printf("%s %-10s %s%s%s:%u -> %s%s%s:%u %s len %u  %s\n", ts,
		       e->dry ? "WOULD-DROP" : "DROP", l, src, r, e->sport, l, dst, r,
		       e->dport, e->proto == 6 ? "tcp" : e->proto == 17 ? "udp" :
		       e->proto == 1 || e->proto == 58 ? "icmp" : "ip", e->pkt_len,
		       e->reason < FF_STAT_MAX ? ff_stat_desc[e->reason] : "?");
	}
	fflush(stdout);
	lo->shown++;
	return 0;
}

int cmd_log(int argc, char **argv)
{
	struct log_opts lo = { .only = -1 };
	struct ff_config cfg;
	struct ring_buffer *rb;
	int fd;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--json")) {
			lo.json = true;
		} else if (!strcmp(argv[i], "--reason") && i + 1 < argc) {
			i++;
			for (int k = 0; k < FF_STAT_MAX; k++)
				if (!strcmp(argv[i], ff_stat_key[k]))
					lo.only = k;
			if (lo.only < 0)
				die("unknown reason '%s'. Names are the keys from "
				    "`fivemctl stats --json`.", argv[i]);
		} else {
			die("log: unexpected '%s'", argv[i]);
		}
	}

	config_read(&cfg);
	if (!(cfg.flags & FF_F_LOG) || !cfg.log_sample)
		warnx("logging is off in the filter (--on log, --log-sample N); "
		      "this will sit here quietly");

	fd = pin_open("events");
	rb = ring_buffer__new(fd, on_event, &lo, NULL);
	if (!rb)
		die("cannot open the event ring buffer: %s", strerror(errno));

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	if (!lo.json)
		fprintf(stderr, "sampled drops, 1 in %u (ctrl-c to stop)\n", cfg.log_sample);
	while (!stop) {
		int err = ring_buffer__poll(rb, 250);

		if (err < 0 && err != -EINTR) {
			warnx("ring buffer poll: %s", strerror(-err));
			break;
		}
	}
	ring_buffer__free(rb);
	close(fd);
	return 0;
}
