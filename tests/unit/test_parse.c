// SPDX-License-Identifier: GPL-2.0-only
/*
 * Parsers from src/ctl/util.c. These sit between an operator typing at 3am
 * and a map that drops packets, so they get to be strict.
 */
#include <string.h>
#include "check.h"
#include "ctl.h"

static int prefix_is(const char *in, const char *want)
{
	struct prefix p;
	char out[80];

	if (!parse_prefix(in, &p))
		return !want;
	if (!want)
		return 0;
	fmt_prefix(&p, out, sizeof(out));
	return !strcmp(out, want);
}

int main(void)
{
	__u64 v;

	CHECK(parse_u64("0", &v) && v == 0, "0");
	CHECK(parse_u64("30120", &v) && v == 30120, "30120");
	CHECK(parse_u64("0x10", &v) && v == 16, "hex");
	CHECK(!parse_u64("-1", &v), "negative must fail, v2 turned it into 2^64-1");
	CHECK(!parse_u64("+5", &v), "explicit plus");
	CHECK(!parse_u64("", &v), "empty");
	CHECK(!parse_u64("12abc", &v), "trailing junk");
	CHECK(!parse_u64(" 5", &v), "leading space");
	CHECK(!parse_u64("99999999999999999999999", &v), "overflow");

	CHECK(parse_duration("90", &v) && v == 90, "bare seconds");
	CHECK(parse_duration("90s", &v) && v == 90, "90s");
	CHECK(parse_duration("15m", &v) && v == 900, "15m");
	CHECK(parse_duration("2h", &v) && v == 7200, "2h");
	CHECK(parse_duration("7d", &v) && v == 604800, "7d");
	CHECK(parse_duration("1w", &v) && v == 604800, "1w");
	CHECK(!parse_duration("5x", &v), "bad unit");
	CHECK(!parse_duration("5mm", &v), "double unit");
	CHECK(!parse_duration("-5m", &v), "negative");
	CHECK(!parse_duration("m", &v), "unit only");
	CHECK(!parse_duration("99999999999999w", &v), "would overflow as ns");

	CHECK(prefix_is("1.2.3.4", "1.2.3.4"), "v4 host");
	CHECK(prefix_is("1.2.3.4/32", "1.2.3.4"), "v4 /32 prints as host");
	CHECK(prefix_is("1.2.3.4/24", "1.2.3.0/24"), "v4 host bits masked");
	CHECK(prefix_is("10.255.255.255/9", "10.128.0.0/9"), "v4 odd prefix masked");
	CHECK(prefix_is("0.0.0.0/0", "0.0.0.0/0"), "v4 default");
	CHECK(prefix_is("1.2.3.4/33", NULL), "v4 /33");
	CHECK(prefix_is("1.2.3.4/", NULL), "empty prefix length");
	CHECK(prefix_is("1.2.3.4/0x10", NULL), "hex prefix length");
	CHECK(prefix_is("1.2.3.4/-1", NULL), "negative prefix length");
	CHECK(prefix_is("1.2.3", NULL), "short v4");
	CHECK(prefix_is("256.1.1.1", NULL), "octet overflow");
	CHECK(prefix_is("2001:db8::1", "2001:db8::1"), "v6 host");
	CHECK(prefix_is("2001:db8::1/64", "2001:db8::/64"), "v6 masked");
	CHECK(prefix_is("2001:db8:abcd:12ff::/62", "2001:db8:abcd:12fc::/62"), "v6 /62 masks low bits");
	CHECK(prefix_is("2001:db8::1/129", NULL), "v6 /129");
	CHECK(prefix_is("2001:db8::1/128", "2001:db8::1"), "v6 /128 is a host");
	CHECK(prefix_is("not-an-ip", NULL), "garbage");
	CHECK(prefix_is("", NULL), "empty");

	{
		char b[32];

		fmt_duration(59, b, sizeof(b));
		CHECK(!strcmp(b, "59s"), "fmt 59s: %s", b);
		fmt_duration(3600 + 120, b, sizeof(b));
		CHECK(!strcmp(b, "1h2m"), "fmt 1h2m: %s", b);
		fmt_duration(86400 * 3 + 3600 * 5, b, sizeof(b));
		CHECK(!strcmp(b, "3d5h"), "fmt 3d5h: %s", b);
		fmt_count(999, b, sizeof(b));
		CHECK(!strcmp(b, "999"), "fmt 999: %s", b);
		fmt_count(1234567, b, sizeof(b));
		CHECK(!strcmp(b, "1.23M"), "fmt 1.23M: %s", b);
	}

	CHECK_DONE("parse");
}
