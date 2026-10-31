// SPDX-License-Identifier: GPL-2.0-only
/*
 * fivemctl - load, tune and watch fivem-filter.
 *
 * Everything except `load` works off the pins under FF_PIN_DIR, so none of
 * it needs the object file or remembers anything between runs.
 */
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>

#include "ctl.h"

static const struct {
	const char *name;
	int (*fn)(int, char **);
	const char *usage;
} cmds[] = {
	{ "load",     cmd_load,     "load -i IFACE --ip ADDR [--config FILE] [settings]" },
	{ "unload",   cmd_unload,   "unload [-i IFACE] [--purge] [--force]" },
	{ "reload",   cmd_reload,   "reload [--config FILE] [settings]   re-apply the config file live" },
	{ "status",   cmd_status,   "status" },
	{ "config",   cmd_config,   "config [settings]                    show, or change only what you name" },
	{ "stats",    cmd_stats,    "stats [--watch [SEC]] [--json] [--all] [--reset]" },
	{ "block",    cmd_rule,     "block ADDR|CIDR... [--ttl 1h]" },
	{ "allow",    cmd_rule,     "allow ADDR|CIDR... [--ttl 1h]" },
	{ "unblock",  cmd_rule,     "unblock ADDR|CIDR..." },
	{ "unallow",  cmd_rule,     "unallow ADDR|CIDR..." },
	{ "list",     cmd_list,     "list [block|allow] [--json]" },
	{ "reap",     cmd_reap,     "reap [--quiet]                       delete expired rules" },
	{ "save",     cmd_save,     "save FILE" },
	{ "restore",  cmd_restore,  "restore FILE|- [--replace] [--as block|allow]" },
	{ "log",      cmd_log,      "log [--json] [--reason KEY]          stream sampled drops" },
	{ "exporter", cmd_exporter, "exporter [--listen 127.0.0.1:9273]   Prometheus metrics" },
};

static void usage(FILE *f)
{
	fprintf(f, "fivemctl %s - XDP DDoS filter for FiveM / RedM servers\n\n", FF_VERSION);
	for (size_t i = 0; i < ARRAY_SIZE(cmds); i++)
		fprintf(f, "  fivemctl %s\n", cmds[i].usage);
	fputc('\n', f);
	tunables_help(f);
	fprintf(f,
		"\nExamples:\n"
		"  fivemctl load -i eth0 --ip 203.0.113.10 --on dry-run   # watch before you drop\n"
		"  fivemctl stats --watch 2\n"
		"  fivemctl config --off dry-run\n"
		"  fivemctl block 198.51.100.0/24 --ttl 6h\n"
		"  fivemctl allow 192.0.2.44                              # staff, crawlers\n");
}

/* libbpf is chatty at INFO about things nobody running this cares about */
static int libbpf_quiet(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	if (lvl == LIBBPF_DEBUG && !getenv("LIBBPF_LOG_LEVEL"))
		return 0;
	if (lvl == LIBBPF_INFO && !getenv("LIBBPF_LOG_LEVEL"))
		return 0;
	return vfprintf(stderr, fmt, ap);
}

int main(int argc, char **argv)
{
	const char *cmd;

	libbpf_set_print(libbpf_quiet);

	if (argc < 2) {
		usage(stderr);
		return 2;
	}
	cmd = argv[1];

	if (!strcmp(cmd, "help") || !strcmp(cmd, "-h") || !strcmp(cmd, "--help")) {
		usage(stdout);
		return 0;
	}
	if (!strcmp(cmd, "version") || !strcmp(cmd, "--version") || !strcmp(cmd, "-V")) {
		printf("fivemctl %s (abi %u)\n", FF_VERSION, FF_ABI_VERSION);
		return 0;
	}

	for (size_t i = 0; i < ARRAY_SIZE(cmds); i++)
		if (!strcmp(cmd, cmds[i].name))
			return cmds[i].fn(argc - 1, argv + 1);

	fprintf(stderr, "fivemctl: unknown command '%s'\n\n", cmd);
	usage(stderr);
	return 2;
}
