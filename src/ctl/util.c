// SPDX-License-Identifier: GPL-2.0-only
/*
 * No libbpf in this file on purpose: tests/unit/test_parse.c links it
 * directly, so everything here stays testable without root.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ctl.h"

void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fputs("fivemctl: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
	exit(1);
}

void warnx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fputs("fivemctl: warning: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

/* Same clock as bpf_ktime_get_ns(), which is the whole point. */
__u64 mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

__u64 wall_sec(void)
{
	return (__u64)time(NULL);
}

/*
 * strtoull with the edges sanded off: no sign, no trailing junk, no silent
 * wrap. v2 used bare strtoull and `--pps -1` became 18 quintillion pps.
 */
bool parse_u64(const char *s, __u64 *out)
{
	unsigned long long v;
	char *end;

	if (!s || !*s || *s == '-' || *s == '+' || isspace((unsigned char)*s))
		return false;
	errno = 0;
	v = strtoull(s, &end, 0);
	if (errno || *end)
		return false;
	*out = v;
	return true;
}

/* "90", "90s", "15m", "2h", "7d". Bare numbers are seconds. */
bool parse_duration(const char *s, __u64 *out_sec)
{
	unsigned long long v;
	__u64 mul = 1;
	char *end;

	if (!s || !*s || *s == '-' || *s == '+')
		return false;
	errno = 0;
	v = strtoull(s, &end, 10);
	if (errno || end == s)
		return false;

	switch (*end) {
	case '\0':
	case 's': mul = 1; break;
	case 'm': mul = 60; break;
	case 'h': mul = 3600; break;
	case 'd': mul = 86400; break;
	case 'w': mul = 604800; break;
	default:  return false;
	}
	if (*end && end[1])
		return false;
	if (v > (~0ULL / 1000000000ULL) / mul)
		return false;	/* has to survive * 1e9 later */
	*out_sec = v * mul;
	return true;
}

void fmt_duration(__u64 sec, char *out, size_t n)
{
	if (sec >= 86400)
		snprintf(out, n, "%llud%lluh", (unsigned long long)(sec / 86400),
			 (unsigned long long)(sec % 86400 / 3600));
	else if (sec >= 3600)
		snprintf(out, n, "%lluh%llum", (unsigned long long)(sec / 3600),
			 (unsigned long long)(sec % 3600 / 60));
	else if (sec >= 60)
		snprintf(out, n, "%llum%llus", (unsigned long long)(sec / 60),
			 (unsigned long long)(sec % 60));
	else
		snprintf(out, n, "%llus", (unsigned long long)sec);
}

/* 1234567 -> "1.23M". For humans; JSON gets raw numbers. */
void fmt_count(__u64 v, char *out, size_t n)
{
	static const char sfx[] = " kMGTP";
	double d = (double)v;
	int i = 0;

	while (d >= 1000.0 && i < 5) {
		d /= 1000.0;
		i++;
	}
	if (!i)
		snprintf(out, n, "%llu", (unsigned long long)v);
	else
		snprintf(out, n, "%.2f%c", d, sfx[i]);
}

/* Zero the host bits so 1.2.3.4/24 and 1.2.3.0/24 are the same trie key. */
static void mask_prefix(struct prefix *p)
{
	unsigned bytes = p->af == FF_AF_INET ? 4 : 16;

	for (unsigned i = 0; i < bytes; i++) {
		unsigned bit = i * 8;

		if (bit >= p->len)
			p->addr[i] = 0;
		else if (p->len - bit < 8)
			p->addr[i] &= (__u8)(0xff << (8 - (p->len - bit)));
	}
}

bool parse_prefix(const char *s, struct prefix *p)
{
	char buf[INET6_ADDRSTRLEN + 8];
	char *slash;
	__u64 len = 0;
	bool has_len = false;

	if (!s || strlen(s) >= sizeof(buf))
		return false;
	memset(p, 0, sizeof(*p));
	strcpy(buf, s);

	slash = strchr(buf, '/');
	if (slash) {
		*slash++ = '\0';
		/* parse_u64 accepts 0x.. which is cute but wrong here */
		if (!*slash || strspn(slash, "0123456789") != strlen(slash) ||
		    !parse_u64(slash, &len))
			return false;
		has_len = true;
	}

	if (strchr(buf, ':')) {
		if (inet_pton(AF_INET6, buf, p->addr) != 1)
			return false;
		p->af = FF_AF_INET6;
		if (has_len && len > 128)
			return false;
		p->len = has_len ? (__u32)len : 128;
	} else {
		if (inet_pton(AF_INET, buf, p->addr) != 1)
			return false;
		p->af = FF_AF_INET;
		if (has_len && len > 32)
			return false;
		p->len = has_len ? (__u32)len : 32;
	}
	mask_prefix(p);
	return true;
}

void fmt_prefix(const struct prefix *p, char *out, size_t n)
{
	char a[INET6_ADDRSTRLEN];
	bool host = p->len == (p->af == FF_AF_INET ? 32u : 128u);

	inet_ntop(p->af == FF_AF_INET ? AF_INET : AF_INET6, p->addr, a, sizeof(a));
	if (host)
		snprintf(out, n, "%s", a);
	else
		snprintf(out, n, "%s/%u", a, p->len);
}

void fmt_addr(int af, const __u32 a[4], char *out, size_t n)
{
	inet_ntop(af == FF_AF_INET6 ? AF_INET6 : AF_INET, a, out, (socklen_t)n);
}
