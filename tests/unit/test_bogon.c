// SPDX-License-Identifier: GPL-2.0-only
/*
 * Exercises the real classifiers from src/shared/bogon.h. Every range is hit
 * at both edges and at the addresses just outside, because a wrong shift
 * constant fails silently: either the check never fires, or it starts eating
 * routable space. Neither shows up until someone's players can't connect.
 */
#include "check.h"
#include "bogon.h"

#define IP(a, b, c, d) (((__u32)(a) << 24) | ((__u32)(b) << 16) | \
			((__u32)(c) << 8) | (__u32)(d))

static const struct {
	__u32 ip;
	int want;
	const char *what;
} v4[] = {
	{ IP(0,0,0,0),			1, "this-network" },
	{ IP(0,255,255,255),		1, "0/8 top" },
	{ IP(10,0,0,1),			1, "10/8 bottom" },
	{ IP(10,255,255,255),		1, "10/8 top" },
	{ IP(100,64,0,0),		1, "cgnat bottom" },
	{ IP(100,127,255,255),		1, "cgnat top" },
	{ IP(127,0,0,1),		1, "loopback" },
	{ IP(169,254,0,1),		1, "link-local" },
	{ IP(172,16,0,0),		1, "172.16/12 bottom" },
	{ IP(172,31,255,255),		1, "172.16/12 top" },
	{ IP(192,0,0,8),		1, "192.0.0/24" },
	{ IP(192,0,2,5),		1, "TEST-NET-1" },
	{ IP(192,168,0,1),		1, "192.168/16" },
	{ IP(198,18,0,0),		1, "benchmark bottom" },
	{ IP(198,19,255,255),		1, "benchmark top" },
	{ IP(198,51,100,7),		1, "TEST-NET-2" },
	{ IP(203,0,113,9),		1, "TEST-NET-3" },
	{ IP(224,0,0,1),		1, "multicast bottom" },
	{ IP(239,255,255,255),		1, "multicast top" },
	{ IP(240,0,0,1),		1, "reserved" },
	{ IP(255,255,255,255),		1, "broadcast" },

	{ IP(1,1,1,1),			0, "1.1.1.1" },
	{ IP(8,8,8,8),			0, "8.8.8.8" },
	{ IP(9,255,255,255),		0, "below 10/8" },
	{ IP(11,0,0,0),			0, "above 10/8" },
	{ IP(100,63,255,255),		0, "below cgnat" },
	{ IP(100,128,0,0),		0, "above cgnat" },
	{ IP(126,255,255,255),		0, "below loopback" },
	{ IP(128,0,0,1),		0, "above loopback" },
	{ IP(169,253,255,255),		0, "below link-local" },
	{ IP(169,255,0,0),		0, "above link-local" },
	{ IP(172,15,255,255),		0, "below 172.16/12" },
	{ IP(172,32,0,0),		0, "above 172.16/12" },
	{ IP(192,0,1,1),		0, "between 192.0.0 and 192.0.2" },
	{ IP(192,0,3,1),		0, "above TEST-NET-1" },
	{ IP(192,167,255,255),		0, "below 192.168/16" },
	{ IP(192,169,0,0),		0, "above 192.168/16" },
	{ IP(198,17,255,255),		0, "below benchmark" },
	{ IP(198,20,0,0),		0, "above benchmark" },
	{ IP(198,51,99,255),		0, "below TEST-NET-2" },
	{ IP(198,51,101,0),		0, "above TEST-NET-2" },
	{ IP(203,0,112,255),		0, "below TEST-NET-3" },
	{ IP(203,0,114,0),		0, "above TEST-NET-3" },
	{ IP(223,255,255,255),		0, "below multicast" },
};

static const struct {
	__u32 w[4];
	int want;
	const char *what;
} v6[] = {
	{ { 0, 0, 0, 0 },				1, "::" },
	{ { 0, 0, 0, 1 },				1, "::1" },
	{ { 0, 0, 0xffff, 0x01020304 },			1, "::ffff:1.2.3.4" },
	{ { 0x01000000, 0, 0, 5 },			1, "100::5" },
	{ { 0x20010db8, 0, 0, 1 },			1, "2001:db8::1" },
	{ { 0x3fff0000, 0, 0, 1 },			1, "3fff::1" },
	{ { 0x3fff0fff, 0, 0, 1 },			1, "3fff:fff::1 (top of /20)" },
	{ { 0xfc000000, 0, 0, 1 },			1, "fc00::1" },
	{ { 0xfdffffff, 0, 0, 1 },			1, "fdff:ffff::1" },
	{ { 0xfe800000, 0, 0, 1 },			1, "fe80::1" },
	{ { 0xfebfffff, 0, 0, 1 },			1, "febf:ffff::1" },
	{ { 0xff020000, 0, 0, 1 },			1, "ff02::1" },

	{ { 0, 0, 0, 2 },				0, "::2 (v4-compat junk, but not ours to judge)" },
	{ { 0x01000000, 1, 0, 0 },			0, "100:0:0:1:: (outside discard /64)" },
	{ { 0x20010db9, 0, 0, 1 },			0, "2001:db9::1" },
	{ { 0x20014860, 0, 0, 0x8888 },			0, "2001:4860::8888" },
	{ { 0x26064700, 0, 0, 0x1111 },			0, "2606:4700::1111" },
	{ { 0x3fff1000, 0, 0, 1 },			0, "3fff:1000::1 (above doc /20)" },
	{ { 0xfbffffff, 0, 0, 1 },			0, "fbff:ffff::1" },
	{ { 0xfec00000, 0, 0, 1 },			0, "fec0::1 (site-local, deprecated but not martian)" },
	{ { 0x20020000, 0, 0, 1 },			0, "2002::1 (6to4)" },
	{ { 0x0064ff9b, 0, 0, 0x01020304 },		0, "64:ff9b::1.2.3.4 (NAT64)" },
};

int main(void)
{
	for (unsigned i = 0; i < sizeof(v4) / sizeof(v4[0]); i++)
		CHECK(ff_bogon4(v4[i].ip) == v4[i].want, "v4 %s: want %d",
		      v4[i].what, v4[i].want);

	for (unsigned i = 0; i < sizeof(v6) / sizeof(v6[0]); i++)
		CHECK(ff_bogon6(v6[i].w[0], v6[i].w[1], v6[i].w[2], v6[i].w[3]) ==
		      v6[i].want, "v6 %s: want %d", v6[i].what, v6[i].want);

	CHECK_DONE("bogon");
}
