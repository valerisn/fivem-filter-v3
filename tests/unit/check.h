/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * The world's smallest test harness. Pulling in a framework for ~100 asserts
 * felt silly, and this keeps `make test` dependency-free.
 */
#ifndef FF_CHECK_H
#define FF_CHECK_H

#include <stdio.h>

static int check_failed;
static int check_total;

#define CHECK(cond, ...) do {						\
	check_total++;							\
	if (!(cond)) {							\
		check_failed++;						\
		fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);	\
		fprintf(stderr, __VA_ARGS__);				\
		fputc('\n', stderr);					\
	}								\
} while (0)

#define CHECK_DONE(name) do {						\
	printf("%-14s %d/%d passed\n", name,				\
	       check_total - check_failed, check_total);		\
	return check_failed ? 1 : 0;					\
} while (0)

#endif
