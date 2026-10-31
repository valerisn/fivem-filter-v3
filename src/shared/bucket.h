/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Token bucket arithmetic shared by the per-source and global limiters. No
 * locking in here: callers hold whatever lock guards *stamp and *tokens.
 * Pure arithmetic so tests/unit/test_bucket.c can hammer it without a kernel.
 */
#ifndef FF_BUCKET_H
#define FF_BUCKET_H

#include <linux/types.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/*
 * Take one token. Returns 1 if the packet is allowed, 0 if the bucket is dry.
 *
 * refill_ns == 0 means "no limit", not "no tokens ever" - the latter would
 * blackhole the port the moment someone fat-fingers a config.
 *
 * v2 reset the stamp to `now` on every refill, throwing away the fractional
 * token each time. At low rates that's noise, but a 1 token/100ms SYN bucket
 * hit every 150ms only ever saw one token per 150ms. Advancing the stamp by
 * exactly the time we converted keeps the remainder.
 */
static __always_inline int ff_tb_take(__u64 *stamp, __u32 *tokens, __u64 now,
				      __u64 refill_ns, __u32 burst)
{
	__u64 add;

	if (!refill_ns)
		return 1;
	if (!burst)
		burst = 1;
	/* burst can shrink under a live config update */
	if (*tokens > burst)
		*tokens = burst;
	/* fresh slot, or a clock that went backwards (it shouldn't, but a
	 * u64 underflow here would mint ~infinite tokens) */
	if (now < *stamp)
		*stamp = now;

	add = (now - *stamp) / refill_ns;
	if (add >= (__u64)(burst - *tokens)) {
		*tokens = burst;
		*stamp = now;
	} else if (add) {
		*tokens += (__u32)add;
		*stamp += add * refill_ns;
	}

	if (!*tokens)
		return 0;
	*tokens -= 1;
	return 1;
}

#define FF_NSEC_PER_SEC 1000000000ULL

/* pps -> refill interval. 0 stays 0 (unlimited). */
static __always_inline __u64 ff_rate_to_ns(__u64 per_sec)
{
	return per_sec ? FF_NSEC_PER_SEC / per_sec : 0;
}

#endif /* FF_BUCKET_H */
