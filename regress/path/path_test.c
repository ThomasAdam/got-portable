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

#include <sys/queue.h>

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>

#include "got_error.h"
#include "got_path.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

static int verbose;
static int quiet;

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
		{ "//foo", "/bar", 1 },
		{ "/foo", "/bar", 1 },
		{ "foo", "bar", 1 },
		{ "/foo/sub", "/bar", 1 },
		{ "/foo", "/bar/sub", 1 },
		{ "/foo/", "/bar", 1 },
		{ "/foo", "/bar/", 1 },
		{ "/foo/", "/bar/", 1 },
		{ "/bar/", "/bar/", 0 },
		{ "/bar/", "/bar", 0 },
		{ "//bar//", "/bar/", 0 },
		{ "//bar//", "/bar////", 0 },
		{ "/bar/sub", "/bar.", -1 },
		{ "/bar/sub", "/bar/", 1 },
		{ "/bar/sub/", "/bar///", 1 },
		{ "/bar/sub/sub2", "/bar/", 1 },
		{ "/bar/sub/sub2", "/bar", 1 },
		{ "/bar.sub.sub2", "/bar", 1 },
		{ "/bar/sub/sub2", "/bar.c", -1 },
	};
	size_t i;

	for (i = 0; i < nitems(test_data); i++) {
		const char *path1 = test_data[i].path1;
		const char *path2 = test_data[i].path2;
		int expected = test_data[i].expected;
		int cmp = got_path_cmp(path1, path2,
		    strlen(path1), strlen(path2));

		if (cmp != expected) {
			test_printf("%d: '%s' vs '%s' == %d; expected %d\n",
			    i, path1, path2, cmp, expected);
			return 0;
		}
	}

	return 1;
}

const char *path_list_input[] = {
	"", "/", "a", "/b", "/bar", "bar/sub", "/bar/sub", "/bar/",
	"/bar.c", "/bar/sub/sub2", "/bar.sub.sub2", "/foo",
	"/foo/sub", "/foo/", "/foo/", "x/a",
};
const char *path_list_expected[] = {
	"",
	"a",
	"/b",
	"/bar",
	"bar/sub",
	"/bar/sub/sub2",
	"/bar.c",
	"/bar.sub.sub2",
	"/foo",
	"/foo/sub",
	"x/a",
};

/* If inserting pathlist_input in reverse the result is slightly different. */
const char *path_list_expected_reverse[] = {
	"/",
	"a",
	"/b",
	"/bar/",
	"/bar/sub",
	"/bar/sub/sub2",
	"/bar.c",
	"/bar.sub.sub2",
	"/foo/",
	"/foo/sub",
	"x/a",
};


static int
path_list(void)
{
	const struct got_error *err = NULL;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;
	size_t i;

	TAILQ_INIT(&paths);
	for (i = 0; i < nitems(path_list_input); i++) {
		err = got_pathlist_insert(NULL, &paths, path_list_input[i],
		    NULL);
		if (err) {
			test_printf("%s\n", __func__, err->msg);
			return 0;
		}
	}

	i = 0;
	TAILQ_FOREACH(pe, &paths, entry) {
		test_printf("'%s' -- '%s'\n", pe->path, path_list_expected[i]);
		if (i >= nitems(path_list_expected)) {
			test_printf("too many elements on list\n");
			return 0;
		}
		if (strcmp(pe->path, path_list_expected[i]) != 0) {
			test_printf("unordered elements on list\n");
			return 0;
		}
		i++;
	}

	got_pathlist_free(&paths);
	return 1;
}

static int
path_list_reverse_input(void)
{
	const struct got_error *err = NULL;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;
	size_t i;

	TAILQ_INIT(&paths);
	for (i = nitems(path_list_input) - 1; i >= 0; i--) {
		err = got_pathlist_insert(NULL, &paths, path_list_input[i],
		    NULL);
		if (err) {
			test_printf("%s\n", __func__, err->msg);
			return 0;
		}
	}

	i = 0;
	TAILQ_FOREACH(pe, &paths, entry) {
		test_printf("'%s' -- '%s'\n", pe->path,
		    path_list_expected_reverse[i]);
		if (i >= nitems(path_list_expected_reverse)) {
			test_printf("too many elements on list\n");
			return 0;
		}
		if (strcmp(pe->path, path_list_expected_reverse[i]) != 0) {
			test_printf("unordered elements on list\n");
			return 0;
		}
		i++;
	}

	got_pathlist_free(&paths);
	return 1;
}

#define RUN_TEST(expr, name) \
	{ test_ok = (expr);  \
	if (!quiet) printf("test_%s %s\n", (name), test_ok ? "ok" : "failed"); \
	failure = (failure || !test_ok); }

void
usage(void)
{
	fprintf(stderr, "usage: path_test [-v] [-q]\n");
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

	while ((ch = getopt(argc, argv, "vq")) != -1) {
		switch (ch) {
		case 'v':
			verbose = 1;
			quiet = 0;
			break;
		case 'q':
			quiet = 1;
			verbose = 0;
			break;
		default:
			usage();
			return 1;
		}
	}
	argc -= optind;
	argv += optind;

	RUN_TEST(path_cmp(), "path_cmp");
	RUN_TEST(path_list(), "path_list");
	RUN_TEST(path_list_reverse_input(), "path_list_reverse_input");

	return failure ? 1 : 0;
}
