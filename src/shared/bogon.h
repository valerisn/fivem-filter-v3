/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Martian source classification. Pure arithmetic, no BPF helpers, so the unit
 * tests compile this exact file and poke at it from userspace. Every constant
 * here has been wrong at least once in v2's history (CGNAT and 198.18/15 both
 * shipped with a stray digit and never fired), so if you touch one, add the
 * edge cases to tests/unit/test_bogon.c in the same commit.
 */
#ifndef FF_BOGON_H
#define FF_BOGON_H

#include <linux/types.h>
#include <stdbool.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* src is host byte order. */
static __always_inline bool ff_bogon4(__u32 src)
{
	if ((src >> 24) == 0)			return true;	/* 0.0.0.0/8 */
	if ((src >> 24) == 10)			return true;	/* 10.0.0.0/8 */
	if ((src >> 22) == 0x191)		return true;	/* 100.64.0.0/10 */
	if ((src >> 24) == 127)			return true;	/* 127.0.0.0/8 */
	if ((src >> 16) == 0xa9fe)		return true;	/* 169.254.0.0/16 */
	if ((src >> 20) == 0xac1)		return true;	/* 172.16.0.0/12 */
	if ((src >> 8)  == 0xc00000)		return true;	/* 192.0.0.0/24 */
	if ((src >> 8)  == 0xc00002)		return true;	/* 192.0.2.0/24 */
	if ((src >> 16) == 0xc0a8)		return true;	/* 192.168.0.0/16 */
	if ((src >> 17) == 0x6309)		return true;	/* 198.18.0.0/15 */
	if ((src >> 8)  == 0xc63364)		return true;	/* 198.51.100.0/24 */
	if ((src >> 8)  == 0xcb0071)		return true;	/* 203.0.113.0/24 */
	if ((src >> 28) >= 0xe)			return true;	/* 224/4, 240/4, bcast */
	return false;
}

/*
 * w0..w3 are the four 32-bit words of the address, host byte order.
 * Deliberately conservative: 6to4 (2002::/16) and NAT64 (64:ff9b::/96) are
 * weird but real, so they get through.
 */
static __always_inline bool ff_bogon6(__u32 w0, __u32 w1, __u32 w2, __u32 w3)
{
	if (!w0 && !w1 && !w2 && w3 <= 1)	return true;	/* :: and ::1 */
	if (!w0 && !w1 && w2 == 0xffff)		return true;	/* ::ffff:0:0/96 */
	if (w0 == 0x01000000 && !w1)		return true;	/* 100::/64 discard */
	if (w0 == 0x20010db8)			return true;	/* 2001:db8::/32 */
	if ((w0 >> 12) == 0x3fff0)		return true;	/* 3fff::/20 doc */
	if ((w0 >> 25) == 0x7e)			return true;	/* fc00::/7 ULA */
	if ((w0 >> 22) == 0x3fa)		return true;	/* fe80::/10 */
	if ((w0 >> 24) == 0xff)			return true;	/* ff00::/8 */
	return false;
}

#endif /* FF_BOGON_H */
