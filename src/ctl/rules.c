// SPDX-License-Identifier: GPL-2.0-only
/*
 * Allow/block rules. One LPM trie per family, both actions in the same trie,
 * longest prefix wins. Expiry is CLOCK_MONOTONIC (same as the kernel side),
 * converted to wall-clock only when saving to disk, since monotonic time
 * restarts at boot and the whole point of saving is surviving one.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include "bucket.h"
#include "ctl.h"

struct rule_ent {
	struct prefix p;
	struct ff_rule r;
};

struct rule_set {
	struct rule_ent *v;
	size_t n, cap;
};

static const char *map_for(int af)
{
	return af == FF_AF_INET ? "rules4" : "rules6";
}

/* both key structs start with prefixlen then the address bytes */
static size_t key_size(int af)
{
	return af == FF_AF_INET ? sizeof(struct ff_lpm4) : sizeof(struct ff_lpm6);
}

static void to_key(const struct prefix *p, void *key)
{
	if (p->af == FF_AF_INET) {
		struct ff_lpm4 *k = key;

		k->prefixlen = p->len;
		memcpy(k->addr, p->addr, 4);
	} else {
		struct ff_lpm6 *k = key;

		k->prefixlen = p->len;
		memcpy(k->addr, p->addr, 16);
	}
}

static void from_key(int af, const void *key, struct prefix *p)
{
	memset(p, 0, sizeof(*p));
	p->af = af;
	if (af == FF_AF_INET) {
		const struct ff_lpm4 *k = key;

		p->len = k->prefixlen;
		memcpy(p->addr, k->addr, 4);
	} else {
		const struct ff_lpm6 *k = key;

		p->len = k->prefixlen;
		memcpy(p->addr, k->addr, 16);
	}
}

static void set_push(struct rule_set *s, const struct rule_ent *e)
{
	if (s->n == s->cap) {
		s->cap = s->cap ? s->cap * 2 : 256;
		s->v = realloc(s->v, s->cap * sizeof(*s->v));
		if (!s->v)
			die("out of memory");
	}
	s->v[s->n++] = *e;
}

/* Snapshot first, act after: deleting mid-walk invalidates the cursor. */
static void rules_snapshot(int af, struct rule_set *out)
{
	__u8 key[sizeof(struct ff_lpm6)], next[sizeof(struct ff_lpm6)];
	int fd = pin_open(map_for(af));
	void *cur = NULL;
	struct rule_ent e;

	while (!bpf_map_get_next_key(fd, cur, next)) {
		memcpy(key, next, key_size(af));
		cur = key;
		if (bpf_map_lookup_elem(fd, key, &e.r))
			continue;	/* raced with a delete */
		from_key(af, key, &e.p);
		set_push(out, &e);
	}
	close(fd);
}

static bool rule_expired(const struct ff_rule *r, __u64 now)
{
	return r->expires_ns && now > r->expires_ns;
}

static const char *act_name(__u8 a)
{
	return a == FF_ACT_ALLOW ? "allow" : a == FF_ACT_BLOCK ? "block" : "?";
}

static int rule_put(const struct prefix *p, __u8 action, __u64 expires_ns,
		    __u64 added_ns, __u8 *was)
{
	__u8 key[sizeof(struct ff_lpm6)] = { 0 };
	struct ff_rule r = { 0 }, old;
	int fd = pin_open(map_for(p->af)), err;

	to_key(p, key);
	*was = 0;
	if (!bpf_map_lookup_elem(fd, key, &old))
		*was = old.action;

	r.action = action;
	r.expires_ns = expires_ns;
	r.added_ns = added_ns;
	err = bpf_map_update_elem(fd, key, &r, BPF_ANY);
	if (err && errno == E2BIG)
		die("rule table is full (%u entries). `fivemctl reap` or remove some.",
		    262144);
	close(fd);
	return err;
}

int cmd_rule(int argc, char **argv)
{
	const char *cmd = argv[0];
	bool remove = cmd[0] == 'u';
	__u8 action = strstr(cmd, "allow") ? FF_ACT_ALLOW : FF_ACT_BLOCK;
	__u64 ttl = 0, now = mono_ns();
	bool quiet = false;
	int nprefix = 0, failed = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--ttl")) {
			if (remove)
				die("%s doesn't take --ttl", cmd);
			if (i + 1 >= argc || !parse_duration(argv[++i], &ttl) || !ttl)
				die("--ttl wants a duration like 90s, 30m, 12h, 7d");
		} else if (!strcmp(argv[i], "-q") || !strcmp(argv[i], "--quiet")) {
			quiet = true;
		} else if (argv[i][0] == '-') {
			die("%s: unknown option %s", cmd, argv[i]);
		} else {
			argv[++nprefix] = argv[i];
		}
	}
	if (!nprefix)
		die("usage: fivemctl %s <ip|cidr>...%s", cmd, remove ? "" : " [--ttl 1h]");

	for (int i = 1; i <= nprefix; i++) {
		struct prefix p;
		char buf[80];
		__u8 key[sizeof(struct ff_lpm6)] = { 0 };

		if (!parse_prefix(argv[i], &p))
			die("'%s' isn't an address or CIDR", argv[i]);
		fmt_prefix(&p, buf, sizeof(buf));

		if (remove) {
			struct ff_rule old;
			int fd = pin_open(map_for(p.af));

			to_key(&p, key);
			if (bpf_map_lookup_elem(fd, key, &old)) {
				warnx("%s has no rule", buf);
				failed++;
			} else if (old.action != action) {
				/* `unblock` silently removing an allow would be a
				 * fun way to lock out your own staff */
				warnx("%s is an %s rule, not %s - use un%s", buf,
				      act_name(old.action), act_name(action),
				      act_name(old.action));
				failed++;
			} else if (bpf_map_delete_elem(fd, key)) {
				warnx("removing %s: %s", buf, strerror(errno));
				failed++;
			} else if (!quiet) {
				printf("removed %s %s\n", act_name(action), buf);
			}
			close(fd);
			continue;
		}

		{
			__u8 was;
			char d[32];

			if (rule_put(&p, action,
				     ttl ? now + ttl * FF_NSEC_PER_SEC : 0, now, &was)) {
				warnx("adding %s: %s", buf, strerror(errno));
				failed++;
				continue;
			}
			if (quiet)
				continue;
			if (ttl)
				fmt_duration(ttl, d, sizeof(d));
			printf("%s %s %s%s%s\n", action == FF_ACT_ALLOW ? "allowed" : "blocked",
			       buf, ttl ? "for " : "permanently", ttl ? d : "",
			       was && was != action ? " (replaced an existing " : "");
			if (was && was != action)
				printf("  ^ that was an %s rule before\n", act_name(was));
		}
	}
	return failed ? 1 : 0;
}

int cmd_list(int argc, char **argv)
{
	struct rule_set s = { 0 };
	__u8 want = 0;
	bool json = false, first = true;
	__u64 now = mono_ns();

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "block"))
			want = FF_ACT_BLOCK;
		else if (!strcmp(argv[i], "allow"))
			want = FF_ACT_ALLOW;
		else if (!strcmp(argv[i], "--json"))
			json = true;
		else
			die("list: unexpected '%s'", argv[i]);
	}

	rules_snapshot(FF_AF_INET, &s);
	rules_snapshot(FF_AF_INET6, &s);

	if (json)
		printf("[");
	else
		printf("%-6s %-44s %-12s %-10s %s\n", "action", "prefix", "expires", "age", "hits~");

	for (size_t i = 0; i < s.n; i++) {
		const struct rule_ent *e = &s.v[i];
		char pfx[80], exp[32], age[32];

		if (want && e->r.action != want)
			continue;
		fmt_prefix(&e->p, pfx, sizeof(pfx));

		if (json) {
			long long left = e->r.expires_ns
				? (long long)(e->r.expires_ns - now) / 1000000000LL : -1;

			printf("%s{\"action\":\"%s\",\"prefix\":\"%s\",\"expires_in\":%lld,"
			       "\"expired\":%s,\"hits\":%llu}", first ? "" : ",",
			       act_name(e->r.action), pfx,
			       rule_expired(&e->r, now) ? 0 : left,
			       rule_expired(&e->r, now) ? "true" : "false",
			       (unsigned long long)e->r.hits);
			first = false;
			continue;
		}

		if (!e->r.expires_ns)
			snprintf(exp, sizeof(exp), "never");
		else if (rule_expired(&e->r, now))
			snprintf(exp, sizeof(exp), "expired");
		else
			fmt_duration((e->r.expires_ns - now) / FF_NSEC_PER_SEC, exp, sizeof(exp));
		if (e->r.added_ns && e->r.added_ns <= now)
			fmt_duration((now - e->r.added_ns) / FF_NSEC_PER_SEC, age, sizeof(age));
		else
			snprintf(age, sizeof(age), "-");
		printf("%-6s %-44s %-12s %-10s %llu\n", act_name(e->r.action), pfx, exp,
		       age, (unsigned long long)e->r.hits);
		first = false;
	}

	if (json)
		printf("]\n");
	else if (first)
		printf("(no rules)\n");
	free(s.v);
	return 0;
}

/* Run by fivem-filter-reap.timer. Also safe to run by hand whenever. */
int cmd_reap(int argc, char **argv)
{
	bool quiet = argc > 1 && (!strcmp(argv[1], "-q") || !strcmp(argv[1], "--quiet"));
	__u64 now = mono_ns();
	size_t n = 0;

	for (int af = FF_AF_INET; af <= FF_AF_INET6; af += FF_AF_INET6 - FF_AF_INET) {
		struct rule_set s = { 0 };
		int fd;

		rules_snapshot(af, &s);
		fd = pin_open(map_for(af));
		for (size_t i = 0; i < s.n; i++) {
			__u8 key[sizeof(struct ff_lpm6)] = { 0 };

			if (!rule_expired(&s.v[i].r, now))
				continue;
			to_key(&s.v[i].p, key);
			if (!bpf_map_delete_elem(fd, key))
				n++;
		}
		close(fd);
		free(s.v);
	}
	if (!quiet || n)
		printf("reaped %zu expired rule%s\n", n, n == 1 ? "" : "s");
	return 0;
}

int cmd_save(int argc, char **argv)
{
	struct rule_set s = { 0 };
	__u64 now = mono_ns(), wall = wall_sec();
	char tmp[4096];
	size_t kept = 0;
	FILE *f;

	if (argc != 2)
		die("usage: fivemctl save FILE");
	rules_snapshot(FF_AF_INET, &s);
	rules_snapshot(FF_AF_INET6, &s);

	/* tmp + rename so a crash mid-save never leaves a half file that
	 * restore then cheerfully loads */
	snprintf(tmp, sizeof(tmp), "%s.tmp.%d", argv[1], (int)getpid());
	f = fopen(tmp, "w");
	if (!f)
		die("cannot write %s: %s", tmp, strerror(errno));
	fprintf(f, "# fivem-filter rules, saved by fivemctl %s\n"
		   "# action prefix [expires-unix-time]\n", FF_VERSION);
	for (size_t i = 0; i < s.n; i++) {
		const struct rule_ent *e = &s.v[i];
		char pfx[80];

		if (rule_expired(&e->r, now))
			continue;
		fmt_prefix(&e->p, pfx, sizeof(pfx));
		if (e->r.expires_ns)
			fprintf(f, "%s %s %llu\n", act_name(e->r.action), pfx,
				(unsigned long long)(wall + (e->r.expires_ns - now) / FF_NSEC_PER_SEC));
		else
			fprintf(f, "%s %s\n", act_name(e->r.action), pfx);
		kept++;
	}
	if (fflush(f) || fsync(fileno(f)) || fclose(f)) {
		unlink(tmp);
		die("writing %s: %s", tmp, strerror(errno));
	}
	if (rename(tmp, argv[1])) {
		unlink(tmp);
		die("rename to %s: %s", argv[1], strerror(errno));
	}
	printf("saved %zu rule%s to %s\n", kept, kept == 1 ? "" : "s", argv[1]);
	free(s.v);
	return 0;
}

/*
 * Reads what save writes, plus plain one-address-per-line lists (with
 * --as block|allow) so you can feed it a public blocklist without sed.
 */
int cmd_restore(int argc, char **argv)
{
	const char *path = NULL;
	__u8 as = 0;
	bool replace = false;
	__u64 now = mono_ns(), wall = wall_sec();
	size_t added = 0, skipped = 0;
	char line[512];
	int ln = 0;
	FILE *f;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--replace")) {
			replace = true;
		} else if (!strcmp(argv[i], "--as") && i + 1 < argc) {
			i++;
			as = !strcmp(argv[i], "allow") ? FF_ACT_ALLOW
			   : !strcmp(argv[i], "block") ? FF_ACT_BLOCK : 0;
			if (!as)
				die("--as wants block or allow");
		} else if (!path && argv[i][0] != '-') {
			path = argv[i];
		} else {
			die("restore: unexpected '%s'", argv[i]);
		}
	}
	if (!path)
		die("usage: fivemctl restore FILE [--replace] [--as block|allow]");

	f = !strcmp(path, "-") ? stdin : fopen(path, "r");
	if (!f) {
		/* first boot, nothing saved yet - not an error for the unit */
		if (errno == ENOENT) {
			printf("%s doesn't exist, nothing to restore\n", path);
			return 0;
		}
		die("cannot read %s: %s", path, strerror(errno));
	}

	if (replace) {
		for (int af = FF_AF_INET; af <= FF_AF_INET6; af += FF_AF_INET6 - FF_AF_INET) {
			struct rule_set s = { 0 };
			int fd;

			rules_snapshot(af, &s);
			fd = pin_open(map_for(af));
			for (size_t i = 0; i < s.n; i++) {
				__u8 key[sizeof(struct ff_lpm6)] = { 0 };

				to_key(&s.v[i].p, key);
				bpf_map_delete_elem(fd, key);
			}
			close(fd);
			free(s.v);
		}
	}

	while (fgets(line, sizeof(line), f)) {
		char *tok[3] = { 0 }, *save = NULL, *p;
		int nt = 0;
		__u8 action = as, was;
		__u64 exp_wall = 0, exp_ns = 0;
		struct prefix pf;

		ln++;
		if ((p = strchr(line, '#')))
			*p = '\0';
		for (p = strtok_r(line, " \t\r\n", &save); p && nt < 3;
		     p = strtok_r(NULL, " \t\r\n", &save))
			tok[nt++] = p;
		if (!nt)
			continue;

		if (!strcmp(tok[0], "block") || !strcmp(tok[0], "allow")) {
			action = tok[0][0] == 'a' ? FF_ACT_ALLOW : FF_ACT_BLOCK;
			memmove(tok, tok + 1, 2 * sizeof(*tok));
			tok[2] = NULL;
			nt--;
		}
		if (!action)
			die("%s:%d: no action on this line; add block/allow or pass --as",
			    path, ln);
		if (!nt || !parse_prefix(tok[0], &pf))
			die("%s:%d: '%s' isn't an address or CIDR", path, ln,
			    nt ? tok[0] : "");
		if (nt > 1 && !parse_u64(tok[1], &exp_wall))
			die("%s:%d: bad expiry '%s'", path, ln, tok[1]);

		if (exp_wall) {
			if (exp_wall <= wall) {
				skipped++;
				continue;
			}
			exp_ns = now + (exp_wall - wall) * FF_NSEC_PER_SEC;
		}
		if (rule_put(&pf, action, exp_ns, now, &was))
			die("%s:%d: adding rule: %s", path, ln, strerror(errno));
		added++;
	}
	if (f != stdin)
		fclose(f);

	printf("restored %zu rule%s", added, added == 1 ? "" : "s");
	if (skipped)
		printf(", skipped %zu that expired while saved", skipped);
	printf("\n");
	return 0;
}
