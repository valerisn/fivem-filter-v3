// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include "ctl.h"

int pin_try_open(const char *name)
{
	char path[256];

	snprintf(path, sizeof(path), "%s/%s", FF_PIN_DIR, name);
	return bpf_obj_get(path);
}

int pin_open(const char *name)
{
	int fd = pin_try_open(name);

	if (fd < 0) {
		if (errno == ENOENT)
			die("filter isn't loaded (no %s/%s). Try `fivemctl load`.",
			    FF_PIN_DIR, name);
		if (errno == EPERM || errno == EACCES)
			die("permission denied opening %s/%s - run as root or with "
			    "CAP_BPF", FF_PIN_DIR, name);
		die("cannot open %s/%s: %s", FF_PIN_DIR, name, strerror(errno));
	}
	return fd;
}

bool filter_loaded(void)
{
	int fd = pin_try_open("config");

	if (fd < 0)
		return false;
	close(fd);
	return true;
}

void config_read(struct ff_config *cfg)
{
	int fd = pin_open("config");
	__u32 zero = 0;

	if (bpf_map_lookup_elem(fd, &zero, cfg))
		die("reading config map: %s", strerror(errno));
	close(fd);

	/*
	 * The thing v2 never checked. A mismatched binary reading this struct
	 * gets garbage; a mismatched binary *writing* it reprograms the filter
	 * with garbage, live.
	 */
	if (cfg->abi_version != FF_ABI_VERSION)
		die("loaded filter speaks ABI %u, this fivemctl speaks %u. "
		    "Reload the filter with this build (`fivemctl reload`) or use "
		    "the fivemctl that loaded it.", cfg->abi_version, FF_ABI_VERSION);
}

void config_write(const struct ff_config *cfg)
{
	int fd = pin_open("config");
	__u32 zero = 0;

	/* Single-element array update. Not atomic against a CPU mid-packet,
	 * so one packet might see half old / half new config. Every field is
	 * independently sane, so that's survivable. */
	if (bpf_map_update_elem(fd, &zero, cfg, BPF_ANY))
		die("writing config map: %s", strerror(errno));
	close(fd);
}

/*
 * Which interface and mode we attached with. bpffs only holds BPF objects,
 * so this goes in /run. Lets `unload` work without -i and detach in the
 * right mode - v2 always detached in default mode and silently did nothing
 * if the program had fallen back to skb.
 */
bool attach_info_read(struct attach_info *ai)
{
	FILE *f = fopen(FF_RUN_ATTACH, "r");
	unsigned flags = 0, id = 0;
	int n;

	memset(ai, 0, sizeof(*ai));
	if (!f)
		return false;
	n = fscanf(f, "%63s %u %u", ai->iface, &flags, &id);
	fclose(f);
	if (n < 2)
		return false;
	ai->xdp_flags = flags;
	ai->prog_id = id;
	return true;
}

void attach_info_write(const struct attach_info *ai)
{
	FILE *f;

	if (mkdir(FF_RUN_DIR, 0755) && errno != EEXIST) {
		warnx("cannot create %s: %s (unload will need -i)", FF_RUN_DIR,
		      strerror(errno));
		return;
	}
	f = fopen(FF_RUN_ATTACH, "w");
	if (!f) {
		warnx("cannot write %s: %s", FF_RUN_ATTACH, strerror(errno));
		return;
	}
	fprintf(f, "%s %u %u\n", ai->iface, ai->xdp_flags, ai->prog_id);
	fclose(f);
}

void attach_info_clear(void)
{
	unlink(FF_RUN_ATTACH);
}
