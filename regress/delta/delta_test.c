/*
 * Copyright (c) 2018 Stefan Sperling <stsp@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>

#include "got_error.h"

#include "delta.h"

static int
delta_combine()
{
	return 1;
}

#define RUN_TEST(expr, name) \
	{ test_ok = (expr);  \
	printf("test %s %s\n", (name), test_ok ? "ok" : "failed"); \
	failure = (failure || !test_ok); }

int
main(int argc, const char *argv[])
{
	int test_ok;
	int failure = 0;

	if (argc != 1) {
		fprintf(stderr, "usage: delta_test [REPO_PATH]\n");
		return 1;
	}

	RUN_TEST(delta_combine(), "delta_combine");

	return failure ? 1 : 0;
}
