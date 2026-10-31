// SPDX-License-Identifier: GPL-2.0-only
/*
 * Token bucket behaviour, driven with a fake clock. The interesting cases are
 * the ones that bit v2: long idle (u32 overflow), burst shrinking under a live
 * config change, and the fractional-token leak at awkward packet spacing.
 */
#include "check.h"
#include "bucket.h"

#define MS 1000000ULL

int main(void)
{
	__u64 stamp = 0;
	__u32 tok = 0;
	__u64 t;
	int ok, n;

	/* Fresh slot starts full. 10 burst, 10/sec. */
	t = 1000 * MS;
	for (n = 0; ff_tb_take(&stamp, &tok, t, 100 * MS, 10); n++)
		;
	CHECK(n == 10, "fresh bucket should allow exactly burst, got %d", n);

	/* 99ms later: still nothing. 100ms later: one. */
	CHECK(!ff_tb_take(&stamp, &tok, t + 99 * MS, 100 * MS, 10), "refilled early");
	CHECK(ff_tb_take(&stamp, &tok, t + 100 * MS, 100 * MS, 10), "no refill at interval");
	CHECK(!ff_tb_take(&stamp, &tok, t + 101 * MS, 100 * MS, 10), "double refill");

	/*
	 * The remainder leak. Drained bucket with headroom (burst 10), packets
	 * every 90ms against a 100ms refill: 90 tokens get minted over 9s, so
	 * exactly 90 of 100 should pass. v2 threw away the leftover 80ms each
	 * time it converted a token and only passed every other packet - 50%,
	 * on a source sending *under* the configured rate.
	 *
	 * (burst 1 would legitimately give 50% here - excess past a full bucket
	 * is supposed to be lost. Took me a minute to stop "fixing" that.)
	 */
	stamp = 0; tok = 0;
	t = 9000 * MS;
	while (ff_tb_take(&stamp, &tok, t, 100 * MS, 10))
		;
	n = 0;
	for (int i = 1; i <= 100; i++)
		n += ff_tb_take(&stamp, &tok, t + (__u64)i * 90 * MS, 100 * MS, 10);
	CHECK(n == 90, "90ms spacing vs 100ms refill: %d/100 passed, want 90", n);

	/* Under the rate with burst 1 still passes everything. */
	stamp = 0; tok = 0;
	t = 5000 * MS;
	while (ff_tb_take(&stamp, &tok, t, 100 * MS, 1))
		;
	n = 0;
	for (int i = 1; i <= 30; i++)
		n += ff_tb_take(&stamp, &tok, t + (__u64)i * 150 * MS, 100 * MS, 1);
	CHECK(n == 30, "150ms spacing vs 100ms refill: %d/30 passed", n);

	/* Long idle: years of elapsed time must clamp, not wrap. */
	stamp = 1; tok = 0;
	t = 1ULL << 62;
	n = 0;
	while (ff_tb_take(&stamp, &tok, t, 1, 40) && n < 1000)
		n++;
	CHECK(n == 40, "long idle should refill to burst, got %d", n);

	/* Burst shrinking live: tokens above the new burst get clamped. */
	stamp = 0; tok = 0;
	t = 100 * MS;
	ff_tb_take(&stamp, &tok, t, 100 * MS, 50);
	CHECK(tok == 49, "tok %u", tok);
	n = 0;
	while (ff_tb_take(&stamp, &tok, t, 100 * MS, 5) && n < 100)
		n++;
	CHECK(n == 5, "shrunk burst should cap at 5, got %d", n);

	/* refill 0 = unlimited, never touches state. */
	stamp = 7; tok = 3;
	ok = 1;
	for (int i = 0; i < 1000; i++)
		ok &= ff_tb_take(&stamp, &tok, 0, 0, 1);
	CHECK(ok && stamp == 7 && tok == 3, "refill 0 should be a no-op pass");

	/* burst 0 behaves as 1, not as "always drop". */
	stamp = 0; tok = 0;
	CHECK(ff_tb_take(&stamp, &tok, 10 * MS, 100 * MS, 0), "burst 0 dropped");

	/* Clock going backwards must not mint tokens. */
	stamp = 0; tok = 0;
	t = 1000 * MS;
	while (ff_tb_take(&stamp, &tok, t, 100 * MS, 3))
		;
	CHECK(!ff_tb_take(&stamp, &tok, t - 500 * MS, 100 * MS, 3), "backwards clock refilled");
	CHECK(!ff_tb_take(&stamp, &tok, t - 450 * MS, 100 * MS, 3), "backwards clock refilled (2)");

	CHECK(ff_rate_to_ns(0) == 0, "rate 0");
	CHECK(ff_rate_to_ns(200) == 5 * MS, "rate 200");

	CHECK_DONE("bucket");
}
