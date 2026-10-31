/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FF_CTL_H
#define FF_CTL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <linux/types.h>

#include "ff_abi.h"

#ifndef FF_VERSION
#define FF_VERSION "3.0.0-dev"
#endif
#ifndef FF_LIBDIR
#define FF_LIBDIR "/usr/local/lib/fivem-filter"
#endif

#define FF_RUN_DIR	"/run/fivem-filter"
#define FF_RUN_ATTACH	FF_RUN_DIR "/attached"
#define FF_DEFAULT_CONF	"/etc/fivem-filter.conf"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* ------------------------------------------------------------------ util.c */

void die(const char *fmt, ...) __attribute__((format(printf, 1, 2), noreturn));
void warnx(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

__u64 mono_ns(void);
__u64 wall_sec(void);

bool parse_u64(const char *s, __u64 *out);
bool parse_duration(const char *s, __u64 *out_sec);
void fmt_duration(__u64 sec, char *out, size_t n);
void fmt_count(__u64 v, char *out, size_t n);

/*
 * An address or prefix as the user typed it. Bare addresses become /32 or
 * /128, which is what makes "block 1.2.3.4" and "block 1.2.3.0/24" the same
 * operation on the same trie.
 */
struct prefix {
	int af;			/* FF_AF_INET or FF_AF_INET6 */
	__u32 len;
	__u8 addr[16];
};

bool parse_prefix(const char *s, struct prefix *p);
void fmt_prefix(const struct prefix *p, char *out, size_t n);
void fmt_addr(int af, const __u32 a[4], char *out, size_t n);

/* ------------------------------------------------------------------ pins.c */

int pin_open(const char *name);		/* dies with a useful message */
int pin_try_open(const char *name);	/* -1 if missing, no fuss */
bool filter_loaded(void);

void config_read(struct ff_config *cfg);
void config_write(const struct ff_config *cfg);

struct attach_info {
	char iface[64];
	__u32 xdp_flags;
	__u32 prog_id;
};
bool attach_info_read(struct attach_info *ai);
void attach_info_write(const struct attach_info *ai);
void attach_info_clear(void);

/* ---------------------------------------------------------------- tunables.c */

/* Loader-only knobs that don't live in the config map. */
struct load_opts {
	const char *iface;
	const char *obj;
	const char *conf;
	__u32 xdp_mode;		/* XDP_FLAGS_*_MODE, 0 = auto */
	__u64 grace_sec;
	bool grace_set;
	bool force;
};

void config_defaults(struct ff_config *c);
void config_print(FILE *f, const struct ff_config *c);

/*
 * One table drives the command line, the config file and `fivemctl help`.
 * Returns false for names it doesn't know.
 */
bool tunable_apply(const char *name, const char *value, struct ff_config *c,
		   struct load_opts *lo, const char *where);
bool tunable_takes_value(const char *name);
void tunables_help(FILE *f);
void conf_load(const char *path, struct ff_config *c, struct load_opts *lo);

/*
 * Walk argv for --name value / --name=value / -i IFACE, feeding every option
 * to tunable_apply(). Positional args are left in place and compacted to the
 * front; returns how many there are.
 */
int parse_tunable_args(int argc, char **argv, struct ff_config *c,
		       struct load_opts *lo, bool *any);

const char *flag_name(__u32 bit);
__u32 flag_bit(const char *name);

/* ---------------------------------------------------------------- commands */

int cmd_load(int argc, char **argv);
int cmd_unload(int argc, char **argv);
int cmd_reload(int argc, char **argv);
int cmd_status(int argc, char **argv);
int cmd_config(int argc, char **argv);
int cmd_stats(int argc, char **argv);
int cmd_rule(int argc, char **argv);	/* block / allow / unblock / unallow */
int cmd_list(int argc, char **argv);
int cmd_reap(int argc, char **argv);
int cmd_save(int argc, char **argv);
int cmd_restore(int argc, char **argv);
int cmd_log(int argc, char **argv);
int cmd_exporter(int argc, char **argv);

/* stats.c, shared with the exporter */
void stats_read(struct ff_counter *out);

#endif /* FF_CTL_H */
