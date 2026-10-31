// SPDX-License-Identifier: GPL-2.0-only
/*
 * Prometheus text exposition on a tiny blocking HTTP server. One connection
 * at a time is plenty for a scraper hitting us every 15s, and it keeps this
 * file free of threads, epoll and other things to get wrong.
 *
 * Binds to localhost by default. Exposing counters of what you're dropping
 * to the same internet you're dropping it from is a gift to the attacker.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include "ctl.h"

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static void count_rules(const char *map, size_t ksz, __u64 *allow, __u64 *block)
{
	__u8 key[32], next[32];
	struct ff_rule r;
	void *cur = NULL;
	__u64 now = mono_ns();
	int fd = pin_try_open(map);

	if (fd < 0)
		return;
	while (!bpf_map_get_next_key(fd, cur, next)) {
		memcpy(key, next, ksz);
		cur = key;
		if (bpf_map_lookup_elem(fd, key, &r))
			continue;
		if (r.expires_ns && now > r.expires_ns)
			continue;
		if (r.action == FF_ACT_ALLOW)
			(*allow)++;
		else
			(*block)++;
	}
	close(fd);
}

/* Builds the whole body in memory; it's a couple of KB. */
static char *render(size_t *len)
{
	struct ff_counter s[FF_STAT_MAX];
	struct ff_config cfg;
	__u64 allow = 0, block = 0;
	char *buf = NULL;
	size_t cap = 0;
	FILE *f = open_memstream(&buf, &cap);

	if (!f)
		return NULL;

	fprintf(f, "# HELP fivem_filter_info Build and ABI of the running filter.\n"
		   "# TYPE fivem_filter_info gauge\n"
		   "fivem_filter_info{version=\"%s\",abi=\"%u\"} 1\n", FF_VERSION, FF_ABI_VERSION);

	if (!filter_loaded()) {
		fprintf(f, "# HELP fivem_filter_up Whether the filter is loaded.\n"
			   "# TYPE fivem_filter_up gauge\nfivem_filter_up 0\n");
		fclose(f);
		*len = cap;
		return buf;
	}

	/* config_read dies on an ABI mismatch, which would kill the exporter
	 * mid-upgrade. Read it raw instead and just report. */
	{
		int fd = pin_open("config");
		__u32 zero = 0;

		memset(&cfg, 0, sizeof(cfg));
		bpf_map_lookup_elem(fd, &zero, &cfg);
		close(fd);
	}
	stats_read(s);
	count_rules("rules4", sizeof(struct ff_lpm4), &allow, &block);
	count_rules("rules6", sizeof(struct ff_lpm6), &allow, &block);

	fprintf(f, "# HELP fivem_filter_up Whether the filter is loaded.\n"
		   "# TYPE fivem_filter_up gauge\nfivem_filter_up 1\n");
	fprintf(f, "# HELP fivem_filter_dry_run 1 when drops are only being counted.\n"
		   "# TYPE fivem_filter_dry_run gauge\nfivem_filter_dry_run %d\n",
		!!(cfg.flags & FF_F_DRY_RUN));
	fprintf(f, "# HELP fivem_filter_enabled 0 when the master switch is off.\n"
		   "# TYPE fivem_filter_enabled gauge\nfivem_filter_enabled %d\n",
		!!(cfg.flags & FF_F_ENABLED));

	fprintf(f, "# HELP fivem_filter_packets_total Packets by verdict reason.\n"
		   "# TYPE fivem_filter_packets_total counter\n");
	for (int i = 0; i < FF_STAT_MAX; i++)
		fprintf(f, "fivem_filter_packets_total{reason=\"%s\",verdict=\"%s\"} %llu\n",
			ff_stat_key[i],
			FF_STAT_IS_PASS(i) ? "pass" : i == FF_STAT_DRYRUN ? "dry_run" : "drop",
			(unsigned long long)s[i].packets);

	fprintf(f, "# HELP fivem_filter_bytes_total IP-layer bytes by verdict reason.\n"
		   "# TYPE fivem_filter_bytes_total counter\n");
	for (int i = 0; i < FF_STAT_MAX; i++)
		fprintf(f, "fivem_filter_bytes_total{reason=\"%s\",verdict=\"%s\"} %llu\n",
			ff_stat_key[i],
			FF_STAT_IS_PASS(i) ? "pass" : i == FF_STAT_DRYRUN ? "dry_run" : "drop",
			(unsigned long long)s[i].bytes);

	fprintf(f, "# HELP fivem_filter_rules Live (unexpired) rules by action.\n"
		   "# TYPE fivem_filter_rules gauge\n"
		   "fivem_filter_rules{action=\"allow\"} %llu\n"
		   "fivem_filter_rules{action=\"block\"} %llu\n",
		(unsigned long long)allow, (unsigned long long)block);

	fclose(f);
	*len = cap;
	return buf;
}

static void reply(int c, const char *status, const char *type, const char *body, size_t n)
{
	char hdr[256];
	int h = snprintf(hdr, sizeof(hdr),
			 "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
			 "Connection: close\r\n\r\n", status, type, n);

	if (write(c, hdr, (size_t)h) < 0 || (n && write(c, body, n) < 0))
		return;	/* scraper hung up, not our problem */
}

static void serve(int c)
{
	char req[1024];
	ssize_t n = read(c, req, sizeof(req) - 1);

	if (n <= 0)
		return;
	req[n] = '\0';

	if (!strncmp(req, "GET /metrics", 12) &&
	    (req[12] == ' ' || req[12] == '?')) {
		size_t len = 0;
		char *body = render(&len);

		if (body)
			reply(c, "200 OK", "text/plain; version=0.0.4", body, len);
		else
			reply(c, "500 Internal Server Error", "text/plain", "", 0);
		free(body);
	} else if (!strncmp(req, "GET / ", 6)) {
		static const char idx[] = "fivem-filter exporter. Metrics at /metrics\n";

		reply(c, "200 OK", "text/plain", idx, sizeof(idx) - 1);
	} else {
		reply(c, "404 Not Found", "text/plain", "", 0);
	}
}

/* "9273", ":9273", "127.0.0.1:9273", "[::1]:9273", "[::]:9273" */
static int listen_on(const char *spec)
{
	struct sockaddr_storage ss = { 0 };
	char host[64] = "127.0.0.1";
	const char *port_s = spec;
	socklen_t sl;
	__u64 port;
	int fd, one = 1;

	if (spec[0] == '[') {
		const char *rb = strchr(spec, ']');

		if (!rb || rb[1] != ':' || (size_t)(rb - spec - 1) >= sizeof(host))
			die("bad --listen '%s'", spec);
		memcpy(host, spec + 1, (size_t)(rb - spec - 1));
		host[rb - spec - 1] = '\0';
		port_s = rb + 2;
	} else if (strchr(spec, ':')) {
		const char *colon = strrchr(spec, ':');

		if ((size_t)(colon - spec) >= sizeof(host))
			die("bad --listen '%s'", spec);
		if (colon != spec) {
			memcpy(host, spec, (size_t)(colon - spec));
			host[colon - spec] = '\0';
		}
		port_s = colon + 1;
	}
	if (!parse_u64(port_s, &port) || !port || port > 65535)
		die("bad port in --listen '%s'", spec);

	if (strchr(host, ':')) {
		struct sockaddr_in6 *s6 = (void *)&ss;

		s6->sin6_family = AF_INET6;
		s6->sin6_port = htons((__u16)port);
		if (inet_pton(AF_INET6, host, &s6->sin6_addr) != 1)
			die("bad address in --listen '%s'", spec);
		sl = sizeof(*s6);
	} else {
		struct sockaddr_in *s4 = (void *)&ss;

		s4->sin_family = AF_INET;
		s4->sin_port = htons((__u16)port);
		if (inet_pton(AF_INET, host, &s4->sin_addr) != 1)
			die("bad address in --listen '%s'", spec);
		sl = sizeof(*s4);
	}

	fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		die("socket: %s", strerror(errno));
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(fd, (struct sockaddr *)&ss, sl) || listen(fd, 16))
		die("cannot listen on %s: %s", spec, strerror(errno));
	return fd;
}

int cmd_exporter(int argc, char **argv)
{
	const char *spec = "127.0.0.1:9273";
	struct timeval tv = { .tv_sec = 2 };
	struct sigaction sa = { .sa_handler = on_signal };
	int lfd;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--listen") && i + 1 < argc)
			spec = argv[++i];
		else
			die("exporter: unexpected '%s'", argv[i]);
	}

	lfd = listen_on(spec);
	/* no SA_RESTART: we want accept() to bail out on SIGTERM */
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);
	fprintf(stderr, "serving metrics on http://%s/metrics\n", spec);

	while (!stop) {
		int c = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);

		if (c < 0) {
			if (errno == EINTR)
				continue;
			warnx("accept: %s", strerror(errno));
			continue;
		}
		/* a client that connects and says nothing can't wedge us */
		setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		serve(c);
		close(c);
	}
	close(lfd);
	return 0;
}
