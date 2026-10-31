// SPDX-License-Identifier: GPL-2.0-only
/*
 * Every knob, in one table. The command line, /etc/fivem-filter.conf and
 * `fivemctl help` all read from here, so they can't drift apart the way
 * v2's getopt table, apply_tune switch and usage text slowly did.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_link.h>

#include "bucket.h"
#include "ctl.h"

enum kind {
	T_IFACE, T_OBJ, T_CONF, T_MODE, T_GRACE, T_FORCE,
	T_IP4, T_IP6, T_PORT, T_PORT_HI, T_AUX,
	T_RATE, T_BURST, T_U32, T_DURATION, T_CONN_PER_MIN,
	T_ON, T_OFF,
};

struct tunable {
	const char *name;
	enum kind kind;
	size_t arg;		/* bucket class or offsetof() into ff_config */
	bool load_only;		/* meaningless on a running filter */
	const char *help;
};

#define CFG(field) offsetof(struct ff_config, field)

static const struct tunable tunables[] = {
	{ "interface",      T_IFACE,    0, true,  "interface to attach to (also -i)" },
	{ "obj",            T_OBJ,      0, true,  "path to filter.bpf.o" },
	{ "config",         T_CONF,     0, true,  "read settings from this file first" },
	{ "mode",           T_MODE,     0, true,  "auto | native | skb | hw" },
	{ "force",          T_FORCE,    0, true,  "replace an XDP program that isn't ours" },
	{ "grace",          T_GRACE,    0, false, "adopt pre-existing TCP flows for this long (30s)" },

	{ "ip",             T_IP4,      0, false, "protected IPv4, or 'any'" },
	{ "ip6",            T_IP6,      0, false, "protected IPv6, or 'none'" },
	{ "port",           T_PORT,     0, false, "game port or range, e.g. 30120 or 30120-30129" },
	{ "port-hi",        T_PORT_HI,  0, false, "top of the game port range" },
	{ "aux-port",       T_AUX,      0, false, "extra protected ports, comma separated (max 4)" },

	{ "pps",            T_RATE,     FF_B_PKT,  false, "sustained packets/sec per source (200)" },
	{ "burst",          T_BURST,    FF_B_PKT,  false, "packet burst per source (60)" },
	{ "syn-rate",       T_RATE,     FF_B_SYN,  false, "new TCP connections/sec per source (5)" },
	{ "syn-burst",      T_BURST,    FF_B_SYN,  false, "SYN burst per source (16)" },
	{ "icmp-rate",      T_RATE,     FF_B_ICMP, false, "ICMP echo/sec per source (1)" },
	{ "icmp-burst",     T_BURST,    FF_B_ICMP, false, "ICMP echo burst per source (4)" },
	{ "oob-rate",       T_RATE,     FF_B_OOB,  false, "getinfo/getstatus per sec per source (1)" },
	{ "oob-burst",      T_BURST,    FF_B_OOB,  false, "OOB query burst per source (3)" },
	{ "conn-per-min",   T_CONN_PER_MIN, 0, false, "new TCP connections/min per source, 0 = off (60)" },
	{ "global-syn-pps", T_U32,      CFG(global_syn_pps), false, "box-wide SYN ceiling, 0 = off (20000)" },
	{ "global-oob-pps", T_U32,      CFG(global_oob_pps), false, "box-wide OOB ceiling, 0 = off (2000)" },
	{ "amp-limit",      T_U32,      CFG(amp_limit),   false, "bytes above which amp source ports drop (512)" },
	{ "udp-min",        T_U32,      CFG(udp_min_len), false, "min UDP payload on game ports (1)" },
	{ "udp-max",        T_U32,      CFG(udp_max_len), false, "max UDP payload on game ports, 0 = off (1400)" },
	{ "flow-idle",      T_DURATION, CFG(flow_idle_ns), false, "TCP flow idle timeout (2m)" },
	{ "frag-ttl",       T_DURATION, CFG(frag_ttl_ns),  false, "how long a fragment verdict sticks (2s)" },
	{ "log-sample",     T_U32,      CFG(log_sample),  false, "log 1 in N drops, 0 = off (256)" },

	{ "on",             T_ON,       0, false, "turn flags on, comma separated" },
	{ "off",            T_OFF,      0, false, "turn flags off, comma separated" },
};

static const struct {
	const char *name;
	__u32 bit;
	const char *help;
} flags[] = {
	{ "enabled",      FF_F_ENABLED,      "master switch" },
	{ "dry-run",      FF_F_DRY_RUN,      "count and log drops, pass the packet anyway" },
	{ "bogon",        FF_F_BOGON,        "drop unroutable sources on game ports" },
	{ "strict-tcp",   FF_F_STRICT_TCP,   "non-SYN TCP on game ports needs a known flow" },
	{ "log",          FF_F_LOG,          "emit sampled drop events" },
	{ "drop-icmp",    FF_F_DROP_ICMP,    "drop all ICMP instead of rate limiting it" },
	{ "drop-ipv6",    FF_F_DROP_IPV6,    "drop IPv6 to the protected address" },
	{ "drop-frags",   FF_F_DROP_FRAGS,   "drop every fragment, first included" },
	{ "drop-ip-opts", FF_F_DROP_IP_OPTS, "drop packets carrying IP options" },
	{ "drop-oob",     FF_F_DROP_OOB,     "drop all OOB queries (delists you from browsers)" },
	{ "lockdown",     FF_F_LOCKDOWN,     "game ports: allowlisted sources only" },
};

const char *flag_name(__u32 bit)
{
	for (size_t i = 0; i < ARRAY_SIZE(flags); i++)
		if (flags[i].bit == bit)
			return flags[i].name;
	return "?";
}

__u32 flag_bit(const char *name)
{
	for (size_t i = 0; i < ARRAY_SIZE(flags); i++)
		if (!strcmp(flags[i].name, name))
			return flags[i].bit;
	return 0;
}

void config_defaults(struct ff_config *c)
{
	memset(c, 0, sizeof(*c));
	c->abi_version = FF_ABI_VERSION;
	c->flags = FF_F_DEFAULT;

	/*
	 * Per-source packet budget. FiveM clients sit well under 100 pps in
	 * normal play (our observation, not a spec); 200 sustained with 60 of
	 * burst leaves room for a bad connection retransmitting hard.
	 */
	c->refill_ns[FF_B_PKT]  = ff_rate_to_ns(200);
	c->burst[FF_B_PKT]      = 60;
	/* A joining client opens several HTTP connections at once. A burst
	 * of 16 is the fix for v2's 100ms SYN gap eating them. */
	c->refill_ns[FF_B_SYN]  = ff_rate_to_ns(5);
	c->burst[FF_B_SYN]      = 16;
	c->refill_ns[FF_B_ICMP] = ff_rate_to_ns(1);
	c->burst[FF_B_ICMP]     = 4;
	c->refill_ns[FF_B_OOB]  = ff_rate_to_ns(1);
	c->burst[FF_B_OOB]      = 3;

	c->flow_idle_ns    = 120 * FF_NSEC_PER_SEC;
	c->conn_window_ns  = 60 * FF_NSEC_PER_SEC;
	c->conn_per_window = 60;
	c->frag_ttl_ns     = 2 * FF_NSEC_PER_SEC;
	c->global_syn_pps  = 20000;
	c->global_oob_pps  = 2000;
	c->amp_limit       = 512;
	c->udp_min_len     = 1;
	c->udp_max_len     = 1400;
	c->log_sample      = 256;
	c->port_lo         = 30120;
	c->port_hi         = 30120;
}

static const struct tunable *find(const char *name)
{
	for (size_t i = 0; i < ARRAY_SIZE(tunables); i++)
		if (!strcmp(tunables[i].name, name))
			return &tunables[i];
	return NULL;
}

bool tunable_takes_value(const char *name)
{
	const struct tunable *t = find(name);

	return t && t->kind != T_FORCE;
}

static __u64 need_u64(const char *name, const char *v, const char *where, __u64 max)
{
	__u64 x;

	if (!parse_u64(v, &x) || x > max)
		die("%s: %s wants a number up to %llu, got '%s'", where, name,
		    (unsigned long long)max, v);
	return x;
}

static __u16 need_port(const char *name, const char *v, const char *where)
{
	__u64 p = need_u64(name, v, where, 65535);

	if (!p)
		die("%s: %s can't be 0", where, name);
	return (__u16)p;
}

/* "a,b,c" -> calls fn for each trimmed piece */
static void each_csv(const char *v, void (*fn)(const char *, void *), void *ctx)
{
	char buf[256], *save = NULL, *tok;

	snprintf(buf, sizeof(buf), "%s", v);
	for (tok = strtok_r(buf, ", \t", &save); tok; tok = strtok_r(NULL, ", \t", &save))
		fn(tok, ctx);
}

struct flag_ctx {
	struct ff_config *c;
	bool on;
	const char *where;
};

static void apply_flag(const char *name, void *p)
{
	struct flag_ctx *fc = p;
	__u32 bit = flag_bit(name);

	if (!bit)
		die("%s: unknown flag '%s' (see `fivemctl help`)", fc->where, name);
	if (fc->on)
		fc->c->flags |= bit;
	else
		fc->c->flags &= ~bit;
}

struct aux_ctx {
	struct ff_config *c;
	int n;
	const char *where;
};

static void apply_aux(const char *v, void *p)
{
	struct aux_ctx *ac = p;

	if (ac->n >= FF_MAX_AUX_PORTS)
		die("%s: at most %d aux ports", ac->where, FF_MAX_AUX_PORTS);
	ac->c->aux_ports[ac->n++] = need_port("aux-port", v, ac->where);
}

bool tunable_apply(const char *name, const char *v, struct ff_config *c,
		   struct load_opts *lo, const char *where)
{
	const struct tunable *t = find(name);
	__u64 x;

	if (!t)
		return false;
	if (t->kind != T_FORCE && (!v || !*v))
		die("%s: %s needs a value", where, name);

	switch (t->kind) {
	case T_IFACE:	lo->iface = strdup(v); break;
	case T_OBJ:	lo->obj = strdup(v); break;
	case T_CONF:	lo->conf = strdup(v); break;
	case T_FORCE:	lo->force = true; break;

	case T_MODE:
		if (!strcmp(v, "auto"))
			lo->xdp_mode = 0;
		else if (!strcmp(v, "native") || !strcmp(v, "drv"))
			lo->xdp_mode = XDP_FLAGS_DRV_MODE;
		else if (!strcmp(v, "skb") || !strcmp(v, "generic"))
			lo->xdp_mode = XDP_FLAGS_SKB_MODE;
		else if (!strcmp(v, "hw") || !strcmp(v, "offload"))
			lo->xdp_mode = XDP_FLAGS_HW_MODE;
		else
			die("%s: mode must be auto, native, skb or hw", where);
		break;

	case T_GRACE:
		if (!parse_duration(v, &x))
			die("%s: grace wants a duration like 30s or 2m, got '%s'", where, v);
		lo->grace_sec = x;
		lo->grace_set = true;
		break;

	case T_IP4:
		if (!strcmp(v, "any")) {
			c->v4_addr = 0;
		} else if (inet_pton(AF_INET, v, &c->v4_addr) != 1) {
			die("%s: '%s' isn't an IPv4 address", where, v);
		}
		break;

	case T_IP6:
		if (!strcmp(v, "none")) {
			c->v6_set = 0;
			memset(c->v6_addr, 0, sizeof(c->v6_addr));
		} else if (inet_pton(AF_INET6, v, c->v6_addr) != 1) {
			die("%s: '%s' isn't an IPv6 address", where, v);
		} else {
			c->v6_set = 1;
		}
		break;

	case T_PORT: {
		const char *dash = strchr(v, '-');

		if (dash) {
			char lo_s[8];
			size_t n = (size_t)(dash - v);

			if (n == 0 || n >= sizeof(lo_s))
				die("%s: bad port range '%s'", where, v);
			memcpy(lo_s, v, n);
			lo_s[n] = '\0';
			c->port_lo = need_port("port", lo_s, where);
			c->port_hi = need_port("port", dash + 1, where);
		} else {
			c->port_lo = c->port_hi = need_port("port", v, where);
		}
		break;
	}
	case T_PORT_HI:
		c->port_hi = need_port(name, v, where);
		break;

	case T_AUX: {
		struct aux_ctx ac = { c, 0, where };

		memset(c->aux_ports, 0, sizeof(c->aux_ports));
		if (strcmp(v, "none"))
			each_csv(v, apply_aux, &ac);
		break;
	}

	case T_RATE:
		/* 0 is a legit "no per-source limit for this class" */
		c->refill_ns[t->arg] = ff_rate_to_ns(need_u64(name, v, where, 1000000000ULL));
		break;
	case T_BURST:
		x = need_u64(name, v, where, 1000000);
		if (!x)
			die("%s: %s must be at least 1", where, name);
		c->burst[t->arg] = (__u32)x;
		break;

	case T_U32:
		x = need_u64(name, v, where, 0xffffffffULL);
		memcpy((char *)c + t->arg, &(__u32){ (__u32)x }, sizeof(__u32));
		break;

	case T_DURATION:
		if (!parse_duration(v, &x))
			die("%s: %s wants a duration like 30s or 2m, got '%s'", where, name, v);
		x *= FF_NSEC_PER_SEC;
		memcpy((char *)c + t->arg, &x, sizeof(x));
		break;

	case T_CONN_PER_MIN:
		c->conn_per_window = (__u32)need_u64(name, v, where, 0xffffffffULL);
		c->conn_window_ns = 60 * FF_NSEC_PER_SEC;
		break;

	case T_ON:
	case T_OFF: {
		struct flag_ctx fc = { c, t->kind == T_ON, where };

		each_csv(v, apply_flag, &fc);
		break;
	}
	}

	if (c->port_hi < c->port_lo)
		c->port_hi = c->port_lo;
	return true;
}

int parse_tunable_args(int argc, char **argv, struct ff_config *c,
		       struct load_opts *lo, bool *any)
{
	int npos = 0;

	for (int i = 1; i < argc; i++) {
		char *a = argv[i], *eq, name[64];
		const char *val = NULL;

		if (!strcmp(a, "-i")) {
			if (++i >= argc)
				die("-i needs an interface");
			lo->iface = argv[i];
			if (any)
				*any = true;
			continue;
		}
		if (strncmp(a, "--", 2) || !a[2]) {
			argv[++npos] = a;	/* positional, keep it */
			continue;
		}

		snprintf(name, sizeof(name), "%s", a + 2);
		eq = strchr(name, '=');
		if (eq) {
			*eq = '\0';
			val = a + 2 + (eq - name) + 1;
		}
		if (!find(name))
			die("unknown option --%s (see `fivemctl help`)", name);
		if (!val && tunable_takes_value(name)) {
			if (++i >= argc)
				die("--%s needs a value", name);
			val = argv[i];
		}
		tunable_apply(name, val, c, lo, "command line");
		if (any)
			*any = true;
	}
	return npos;
}

void conf_load(const char *path, struct ff_config *c, struct load_opts *lo)
{
	FILE *f = fopen(path, "r");
	char line[512], where[600];
	int ln = 0;

	if (!f)
		die("cannot read %s: %s", path, strerror(errno));

	while (fgets(line, sizeof(line), f)) {
		char *k, *v, *p;

		ln++;
		snprintf(where, sizeof(where), "%s:%d", path, ln);
		if ((p = strchr(line, '#')))
			*p = '\0';
		for (k = line; isspace((unsigned char)*k); k++)
			;
		for (p = k + strlen(k); p > k && isspace((unsigned char)p[-1]); p--)
			*--p = '\0';
		if (!*k)
			continue;

		/* "key = value" or "key value"; both show up in the wild */
		v = k + strcspn(k, " \t=");
		if (*v) {
			*v++ = '\0';
			while (*v == ' ' || *v == '\t' || *v == '=')
				v++;
		}
		if (!strcmp(k, "config"))
			die("%s: config files can't include other config files", where);
		if (!tunable_apply(k, *v ? v : NULL, c, lo, where))
			die("%s: unknown setting '%s'", where, k);
	}
	fclose(f);
}

void tunables_help(FILE *f)
{
	fprintf(f, "Settings (as --name VALUE, or `name = value` in the config file):\n");
	for (size_t i = 0; i < ARRAY_SIZE(tunables); i++)
		fprintf(f, "  --%-16s %s%s\n", tunables[i].name, tunables[i].help,
			tunables[i].load_only ? " [load]" : "");
	fprintf(f, "\nFlags (for --on / --off):\n");
	for (size_t i = 0; i < ARRAY_SIZE(flags); i++)
		fprintf(f, "  %-16s %s%s\n", flags[i].name, flags[i].help,
			(FF_F_DEFAULT & flags[i].bit) ? " [default on]" : "");
}

static unsigned long long per_sec(__u64 refill_ns)
{
	return refill_ns ? FF_NSEC_PER_SEC / refill_ns : 0;
}

void config_print(FILE *f, const struct ff_config *c)
{
	char v4[INET_ADDRSTRLEN] = "any", v6[INET6_ADDRSTRLEN] = "none";
	static const char *cls[FF_B_MAX] = { "packets", "syn", "icmp echo", "oob queries" };
	__u64 now = mono_ns();

	if (c->v4_addr)
		inet_ntop(AF_INET, &c->v4_addr, v4, sizeof(v4));
	if (c->v6_set)
		inet_ntop(AF_INET6, c->v6_addr, v6, sizeof(v6));

	fprintf(f, "protecting       %s, %s\n", v4, v6);
	if (c->port_lo == c->port_hi)
		fprintf(f, "game port        %u", c->port_lo);
	else
		fprintf(f, "game ports       %u-%u", c->port_lo, c->port_hi);
	for (int i = 0; i < FF_MAX_AUX_PORTS; i++)
		if (c->aux_ports[i])
			fprintf(f, " +%u", c->aux_ports[i]);
	fputc('\n', f);

	for (int i = 0; i < FF_B_MAX; i++) {
		if (c->refill_ns[i])
			fprintf(f, "per-source       %-12s %llu/s, burst %u\n", cls[i],
				per_sec(c->refill_ns[i]), c->burst[i]);
		else
			fprintf(f, "per-source       %-12s unlimited\n", cls[i]);
	}
	fprintf(f, "new connections  %u per %llus per source%s\n", c->conn_per_window,
		(unsigned long long)(c->conn_window_ns / FF_NSEC_PER_SEC),
		c->conn_per_window ? "" : " (off)");
	fprintf(f, "global ceilings  %u syn/s, %u oob/s\n", c->global_syn_pps, c->global_oob_pps);
	fprintf(f, "udp payload      %u-%u bytes, amp limit %u\n",
		c->udp_min_len, c->udp_max_len, c->amp_limit);
	fprintf(f, "timeouts         flow idle %llus, fragments %llus\n",
		(unsigned long long)(c->flow_idle_ns / FF_NSEC_PER_SEC),
		(unsigned long long)(c->frag_ttl_ns / FF_NSEC_PER_SEC));
	fprintf(f, "log sample       1 in %u\n", c->log_sample);
	if (c->tcp_learn_until_ns > now)
		fprintf(f, "tcp grace        %llus left\n",
			(unsigned long long)((c->tcp_learn_until_ns - now) / FF_NSEC_PER_SEC));

	fprintf(f, "flags           ");
	for (size_t i = 0; i < ARRAY_SIZE(flags); i++)
		if (c->flags & flags[i].bit)
			fprintf(f, " %s", flags[i].name);
	fputc('\n', f);
}
