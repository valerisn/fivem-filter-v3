/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Frame builder for the XDP tests. Append layers in order, call f_done() to
 * patch up the length fields. Checksums are left zero - XDP never looks at
 * them and neither do we.
 */
#ifndef FF_TEST_PKT_H
#define FF_TEST_PKT_H

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20

struct frame {
	uint8_t b[2048];
	size_t  n;
	size_t  ip_off;
	size_t  udp_off;
	int     af;
};

static void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put32(uint8_t *p, uint32_t v) { put16(p, v >> 16); put16(p + 2, v & 0xffff); }

static void f_eth(struct frame *f, uint16_t type)
{
	memset(f, 0, sizeof(*f));
	memcpy(f->b, "\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02", 12);
	put16(f->b + 12, type);
	f->n = 14;
}

/* Rewrites the ethertype we just wrote into a VLAN tag in front of it. */
static void f_vlan(struct frame *f, uint16_t vid)
{
	uint16_t inner = (f->b[f->n - 2] << 8) | f->b[f->n - 1];

	put16(f->b + f->n - 2, 0x8100);
	put16(f->b + f->n, vid & 0x0fff);
	put16(f->b + f->n + 2, inner);
	f->n += 4;
}

static void addr(int af, const char *s, void *out)
{
	if (inet_pton(af, s, out) != 1) {
		fprintf(stderr, "test bug: bad address %s\n", s);
		exit(2);
	}
}

/* frag: host-order frag_off field (flags | offset/8) */
static void f_ip4(struct frame *f, const char *src, const char *dst,
		  uint8_t proto, uint16_t frag, uint16_t id)
{
	uint8_t *ip = f->b + f->n;

	f->ip_off = f->n;
	f->af = 4;
	ip[0] = 0x45;
	put16(ip + 4, id);
	put16(ip + 6, frag);
	ip[8] = 64;
	ip[9] = proto;
	addr(AF_INET, src, ip + 12);
	addr(AF_INET, dst, ip + 16);
	f->n += 20;
}

/* Same, with one 4-byte NOP option block so ihl = 6. */
static void f_ip4_opts(struct frame *f, const char *src, const char *dst, uint8_t proto)
{
	f_ip4(f, src, dst, proto, 0, 1);
	f->b[f->ip_off] = 0x46;
	memset(f->b + f->n, 1, 4);
	f->n += 4;
}

static void f_ip6(struct frame *f, const char *src, const char *dst, uint8_t nexthdr)
{
	uint8_t *ip = f->b + f->n;

	f->ip_off = f->n;
	f->af = 6;
	ip[0] = 0x60;
	ip[6] = nexthdr;
	ip[7] = 64;
	addr(AF_INET6, src, ip + 8);
	addr(AF_INET6, dst, ip + 24);
	f->n += 40;
}

static void f_frag6(struct frame *f, uint8_t nexthdr, uint16_t off8, int mf, uint32_t id)
{
	uint8_t *h = f->b + f->n;

	h[0] = nexthdr;
	put16(h + 2, (uint16_t)((off8 << 3) | (mf ? 1 : 0)));
	put32(h + 4, id);
	f->n += 8;
}

static void f_udp(struct frame *f, uint16_t sport, uint16_t dport)
{
	uint8_t *u = f->b + f->n;

	f->udp_off = f->n;
	put16(u, sport);
	put16(u + 2, dport);
	f->n += 8;
}

static void f_tcp(struct frame *f, uint16_t sport, uint16_t dport, uint8_t flags)
{
	uint8_t *t = f->b + f->n;

	put16(t, sport);
	put16(t + 2, dport);
	put32(t + 4, 1000);
	t[12] = 5 << 4;
	t[13] = flags;
	put16(t + 14, 65535);
	f->n += 20;
}

static void f_icmp(struct frame *f, uint8_t type)
{
	f->b[f->n] = type;
	f->n += 8;
}

static void f_bytes(struct frame *f, const void *p, size_t len)
{
	memcpy(f->b + f->n, p, len);
	f->n += len;
}

static void f_fill(struct frame *f, size_t len, uint8_t v)
{
	memset(f->b + f->n, v, len);
	f->n += len;
}

static void f_done(struct frame *f)
{
	if (f->af == 4)
		put16(f->b + f->ip_off + 2, (uint16_t)(f->n - f->ip_off));
	else if (f->af == 6)
		put16(f->b + f->ip_off + 4, (uint16_t)(f->n - f->ip_off - 40));
	if (f->udp_off)
		put16(f->b + f->udp_off + 4, (uint16_t)(f->n - f->udp_off));
}

/* Ethernet minimum: pad *after* the length fields are final, like a NIC. */
static void f_pad(struct frame *f, size_t min)
{
	if (f->n < min) {
		memset(f->b + f->n, 0, min - f->n);
		f->n = min;
	}
}

#endif
