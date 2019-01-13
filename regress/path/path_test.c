/*
 * Copyright (c) 2018, 2019 Stefan Sperling <stsp@openbsd.org>
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

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>

#include "got_error.h"

#include "got_lib_path.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

static int verbose;

void
test_printf(char *fmt, ...)
{
	va_list ap;

	if (!verbose)
		return;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static int
path_cmp(void)
{
	struct path_cmp_test {
		const char *path1;
		const char *path2;
		int expected;
	} test_data[] = {
		{ "", "", 0 },
		{ "/", "/", 0 },
		{ "/a", "/b", -1 },
		{ "x/a", "x.a", -1 },
		{ "x.a", "x/a", 1 },
		{ "//foo", "/bar", -1 },
		{ "/foo", "/bar", 1 },
		{ "/foo/sub", "/bar", 1 },
		{ "/foo", "/bar/sub", 1 },
		{ "/foo/", "/bar", 1 },
		{ "/foo", "/bar/", 1 },
		{ "/foo/", "/bar/", 1 },
		{ "/bar/", "/bar/", 0 },
		{ "/bar/sub", "/bar/", 1 },
		{ "/bar/sub/sub2", "/bar/", 1 },
		{ "/bar/sub/sub2", "/bar", 1 },
		{ "/bar.sub.sub2", "/bar", 1 },
		{ "/bar/sub/sub2", "/bar.c", -1 },
	};
	int i;

	for (i = 0; i < nitems(test_data); i++) {
		const char *path1 = test_data[i].path1;
		const char *path2 = test_data[i].path2;
		int expected = test_data[i].expected;
		int cmp = got_path_cmp(path1, path2);

		if (cmp != expected) {
			test_printf("%d: '%s' vs '%s' == %d; expected %d\n",
			    i, path1, path2, cmp, expected);
			return 0;
		}
	}

	return 1;
}

#define RUN_TEST(expr, name) \
	{ test_ok = (expr);  \
	printf("test_%s %s\n", (name), test_ok ? "ok" : "failed"); \
	failure = (failure || !test_ok); }

void
usage(void)
{
	fprintf(stderr, "usage: path_test [-v]\n");
}

int
main(int argc, char *argv[])
{
	int test_ok = 0, failure = 0;
	int ch;

#ifndef PROFILE
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "v")) != -1) {
		switch (ch) {
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
			return 1;
		}
	}
	argc -= optind;
	argv += optind;

	RUN_TEST(path_cmp(), "path_cmp");

	return failure ? 1 : 0;
}
