// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bucket.h"
#include "ctl.h"

/*
 * Rule tries survive unload/reload so a restart or an upgrade doesn't quietly
 * unban everyone. Everything else is per-load state and gets recreated.
 */
static const char *const fresh_maps[] = {
	"config", "state", "global", "flows", "frags", "stats", "events",
};
static const char *const kept_maps[] = { "rules4", "rules6" };

static const char *find_obj(void)
{
	static const char *const paths[] = {
		"build/filter.bpf.o",
		"./filter.bpf.o",
		FF_LIBDIR "/filter.bpf.o",
		"/usr/local/lib/fivem-filter/filter.bpf.o",
		"/usr/lib/fivem-filter/filter.bpf.o",
	};

	for (size_t i = 0; i < ARRAY_SIZE(paths); i++)
		if (!access(paths[i], R_OK))
			return paths[i];
	return NULL;
}

static void pin_path(char *out, size_t n, const char *name)
{
	snprintf(out, n, "%s/%s", FF_PIN_DIR, name);
}

static void unpin(const char *name)
{
	char p[256];

	pin_path(p, sizeof(p), name);
	unlink(p);
}

static __u32 random_seed(void)
{
	FILE *f = fopen("/dev/urandom", "rb");
	__u32 s = 0;

	if (!f || fread(&s, sizeof(s), 1, f) != 1)
		s = (__u32)mono_ns() ^ (__u32)getpid();
	if (f)
		fclose(f);
	return s;
}

static const char *mode_name(__u32 flags)
{
	if (flags & XDP_FLAGS_HW_MODE)  return "hw";
	if (flags & XDP_FLAGS_SKB_MODE) return "skb";
	if (flags & XDP_FLAGS_DRV_MODE) return "native";
	return "auto";
}

/* Settings come from: defaults, then the config file, then the command line. */
static void gather(int argc, char **argv, struct ff_config *cfg, struct load_opts *lo)
{
	struct load_opts cli = { 0 };
	struct ff_config scratch;

	config_defaults(cfg);

	/* first pass only to find --config; the real parse happens after the
	 * file so the command line wins. argv copy because the parser
	 * compacts positionals in place */
	{
		char **dup = calloc((size_t)argc + 1, sizeof(*dup));

		memcpy(dup, argv, (size_t)argc * sizeof(*dup));
		config_defaults(&scratch);
		parse_tunable_args(argc, dup, &scratch, &cli, NULL);
		free(dup);
	}
	if (cli.conf)
		conf_load(cli.conf, cfg, lo);

	if (parse_tunable_args(argc, argv, cfg, lo, NULL))
		die("unexpected argument '%s'", argv[1]);
}

static int do_attach(int ifindex, int prog_fd, struct load_opts *lo, __u32 *used)
{
	__u32 base = lo->force ? 0 : XDP_FLAGS_UPDATE_IF_NOEXIST;
	int err;

	*used = lo->xdp_mode;
	err = bpf_xdp_attach(ifindex, prog_fd, base | lo->xdp_mode, NULL);
	if (err == -EBUSY || err == -EEXIST)
		die("%s already has an XDP program attached. If that's an old "
		    "fivem-filter, `fivemctl unload` it first; to replace "
		    "whatever it is, pass --force.", lo->iface);

	if (err && !lo->xdp_mode) {
		warnx("native XDP unavailable on %s (%s), falling back to skb mode. "
		      "It works, but most of the speed win is gone.",
		      lo->iface, strerror(-err));
		*used = XDP_FLAGS_SKB_MODE;
		err = bpf_xdp_attach(ifindex, prog_fd, base | XDP_FLAGS_SKB_MODE, NULL);
	}
	return err;
}

int cmd_load(int argc, char **argv)
{
	struct load_opts lo = { .grace_sec = 30 };
	struct attach_info ai = { 0 };
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct ff_config cfg;
	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
	__u32 zero = 0, used_mode;
	struct bpf_prog_info pinfo = { 0 };
	__u32 pinfo_len = sizeof(pinfo);
	int ifindex, prog_fd, cfd, err, ncpu;
	char path[256];

	gather(argc, argv, &cfg, &lo);

	if (!lo.iface)
		die("load needs an interface: -i eth0 (or `interface = eth0` in the config)");
	ifindex = (int)if_nametoindex(lo.iface);
	if (!ifindex)
		die("no such interface: %s", lo.iface);
	if (!cfg.v4_addr && !cfg.v6_set)
		warnx("no --ip given: game ports on every address on %s get filtered",
		      lo.iface);
	if (filter_loaded() && !lo.force)
		die("filter is already loaded. Use `fivemctl reload` to apply new "
		    "settings, or `fivemctl unload` first.");

	if (!lo.obj && !(lo.obj = find_obj()))
		die("cannot find filter.bpf.o - build it with `make` or pass --obj");

	ncpu = libbpf_num_possible_cpus();
	cfg.nr_cpus = ncpu > 0 ? (__u32)ncpu : 1;
	cfg.hash_seed = random_seed();	/* nobody gets to precompute collisions */
	cfg.abi_version = FF_ABI_VERSION;
	cfg.tcp_learn_until_ns = lo.grace_sec ? mono_ns() + lo.grace_sec * FF_NSEC_PER_SEC : 0;

	/* pre-5.11 kernels charge maps to memlock; the state table alone is 9 MiB */
	setrlimit(RLIMIT_MEMLOCK, &rl);

	if (mkdir(FF_PIN_DIR, 0700) && errno != EEXIST)
		die("cannot create %s: %s. Is bpffs mounted on /sys/fs/bpf?",
		    FF_PIN_DIR, strerror(errno));

	obj = bpf_object__open_file(lo.obj, NULL);
	if (!obj)
		die("cannot open %s: %s", lo.obj, strerror(errno));

	for (size_t i = 0; i < ARRAY_SIZE(fresh_maps); i++) {
		struct bpf_map *m = bpf_object__find_map_by_name(obj, fresh_maps[i]);

		if (!m)
			die("%s has no map '%s' - wrong object file?", lo.obj, fresh_maps[i]);
		unpin(fresh_maps[i]);
		pin_path(path, sizeof(path), fresh_maps[i]);
		bpf_map__set_pin_path(m, path);
	}
	/* libbpf reuses an existing pin here if it's compatible, which is the
	 * whole persistence trick */
	for (size_t i = 0; i < ARRAY_SIZE(kept_maps); i++) {
		struct bpf_map *m = bpf_object__find_map_by_name(obj, kept_maps[i]);

		if (!m)
			die("%s has no map '%s' - wrong object file?", lo.obj, kept_maps[i]);
		pin_path(path, sizeof(path), kept_maps[i]);
		bpf_map__set_pin_path(m, path);
	}

	if (bpf_object__load(obj)) {
		err = errno;
		if (err == EINVAL)
			die("loading failed. If the rule maps came from an older version, "
			    "`fivemctl unload --purge` and try again. Otherwise rerun with "
			    "LIBBPF_LOG_LEVEL=debug for the verifier log.");
		die("loading %s failed: %s (LIBBPF_LOG_LEVEL=debug for the verifier log)",
		    lo.obj, strerror(err));
	}

	prog = bpf_object__find_program_by_name(obj, "fivem_filter");
	if (!prog)
		die("%s has no fivem_filter program", lo.obj);
	prog_fd = bpf_program__fd(prog);

	/* config before attach, or the first packets see an all-zero config
	 * (which is "disabled", so harmless, but confusing in stats) */
	cfd = bpf_map__fd(bpf_object__find_map_by_name(obj, "config"));
	if (bpf_map_update_elem(cfd, &zero, &cfg, BPF_ANY))
		die("seeding config: %s", strerror(errno));

	err = do_attach(ifindex, prog_fd, &lo, &used_mode);
	if (err)
		die("attaching to %s: %s", lo.iface, strerror(-err));

	unpin("prog");
	pin_path(path, sizeof(path), "prog");
	if (bpf_obj_pin(prog_fd, path))
		warnx("pinning program: %s", strerror(errno));

	bpf_obj_get_info_by_fd(prog_fd, &pinfo, &pinfo_len);
	snprintf(ai.iface, sizeof(ai.iface), "%s", lo.iface);
	ai.xdp_flags = used_mode;
	ai.prog_id = pinfo.id;
	attach_info_write(&ai);

	printf("attached to %s (%s mode, prog id %u)\n\n", lo.iface,
	       mode_name(used_mode), pinfo.id);
	config_print(stdout, &cfg);
	if (cfg.flags & FF_F_DRY_RUN)
		printf("\nDRY RUN: nothing will actually be dropped.\n");
	if (lo.grace_sec)
		printf("\nAdopting pre-existing TCP connections for %llus.\n",
		       (unsigned long long)lo.grace_sec);

	bpf_object__close(obj);
	return 0;
}

static void detach(const char *iface, __u32 flags, __u32 want_id, bool force)
{
	int ifindex = (int)if_nametoindex(iface);
	LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
	__u32 cur = 0;

	if (!ifindex) {
		warnx("%s is gone; nothing to detach", iface);
		return;
	}

	/* Don't yank someone else's program. v2 detached whatever was there. */
	if (!bpf_xdp_query_id(ifindex, (int)flags, &cur) && want_id && cur &&
	    cur != want_id && !force)
		die("%s has XDP prog id %u attached but we loaded %u. Not touching "
		    "it; pass --force if you really mean it.", iface, cur, want_id);

	if (want_id && !force)
		opts.old_prog_fd = bpf_prog_get_fd_by_id(want_id);
	if (bpf_xdp_detach(ifindex, flags, opts.old_prog_fd > 0 ? &opts : NULL) &&
	    errno != ENOENT)
		warnx("detaching from %s: %s", iface, strerror(errno));
	if (opts.old_prog_fd > 0)
		close(opts.old_prog_fd);
}

int cmd_unload(int argc, char **argv)
{
	struct attach_info ai;
	const char *iface = NULL;
	bool purge = false, force = false, have;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-i") && i + 1 < argc)
			iface = argv[++i];
		else if (!strcmp(argv[i], "--purge"))
			purge = true;
		else if (!strcmp(argv[i], "--force"))
			force = true;
		else
			die("unload: unexpected '%s'", argv[i]);
	}

	have = attach_info_read(&ai);
	if (!iface && !have)
		die("don't know which interface the filter is on; pass -i");
	if (!iface)
		iface = ai.iface;

	detach(iface, have ? ai.xdp_flags : 0, have ? ai.prog_id : 0, force);

	for (size_t i = 0; i < ARRAY_SIZE(fresh_maps); i++)
		unpin(fresh_maps[i]);
	unpin("prog");
	if (purge)
		for (size_t i = 0; i < ARRAY_SIZE(kept_maps); i++)
			unpin(kept_maps[i]);
	rmdir(FF_PIN_DIR);	/* fails while rules are still pinned, which is fine */
	attach_info_clear();

	printf("detached from %s%s\n", iface,
	       purge ? ", rules purged" : " (rules kept; --purge to drop them)");
	return 0;
}

/*
 * Re-read settings and push them into the live config map without touching
 * the attachment. Per-source state, flows and stats all survive; the hash
 * seed and grace window stay as they were unless --grace is given.
 */
int cmd_reload(int argc, char **argv)
{
	struct load_opts lo = { 0 };
	struct ff_config live, cfg;
	const char *conf = NULL;
	char **rest = calloc((size_t)argc + 1, sizeof(*rest));
	int nrest = 1;

	rest[0] = argv[0];
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--config") && i + 1 < argc)
			conf = argv[++i];
		else
			rest[nrest++] = argv[i];
	}
	if (!conf && !access(FF_DEFAULT_CONF, R_OK))
		conf = FF_DEFAULT_CONF;
	/*
	 * Rebuilding from defaults with no file would quietly reset --ip to
	 * "any" on a live box. First draft did exactly that. Live tweaks
	 * without a file are what `fivemctl config` is for.
	 */
	if (!conf)
		die("nothing to reload from: no --config and no %s. "
		    "For live changes use `fivemctl config --name value`.",
		    FF_DEFAULT_CONF);

	config_read(&live);
	config_defaults(&cfg);
	conf_load(conf, &cfg, &lo);
	if (parse_tunable_args(nrest, rest, &cfg, &lo, NULL))
		die("unexpected argument '%s'", rest[1]);
	free(rest);

	cfg.hash_seed = live.hash_seed;
	cfg.nr_cpus = live.nr_cpus;
	cfg.tcp_learn_until_ns = lo.grace_set
		? (lo.grace_sec ? mono_ns() + lo.grace_sec * FF_NSEC_PER_SEC : 0)
		: live.tcp_learn_until_ns;
	if (lo.iface || lo.obj || lo.xdp_mode)
		warnx("interface/obj/mode only apply at load time; ignored by reload");

	config_write(&cfg);
	printf("reloaded%s%s\n\n", conf ? " from " : "", conf ? conf : "");
	config_print(stdout, &cfg);
	return 0;
}
