/*
 * Copyright (c) 2019 Stefan Sperling <stsp@openbsd.org>
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

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>

#include "got_error.h"

#include "got_lib_pathset.h"

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

static const char *path1 = "/", *path2 = "/usr", *path3 = "/usr/bin";
static const char *data1 = "data1", *data2 = "data2", *data3 = "data3";

static const struct got_error *
pathset_add_remove_iter_cb(const char *path, void *data, void *arg)
{
	test_printf("%s\n", path);
	if ((strcmp(path, path1) == 0 && data == (void *)data1) ||
	    (strcmp(path, path3) == 0 && data == (void *)data3))
		return NULL;
	abort();
	return NULL; /* not reached */
}

static int
pathset_add_remove_iter(void)
{
	const struct got_error *err = NULL;
	struct got_pathset *set;

	set = got_pathset_alloc();
	if (set == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	if (got_pathset_num_elements(set) != 0) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}


	err = got_pathset_add(set, path1, (void *)data1);
	if (err)
		goto done;
	if (got_pathset_num_elements(set) != 1) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}

	if (!got_pathset_contains(set, path1)) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}

	err = got_pathset_add(set, path2, (void *)data2);
	if (err)
		goto done;
	if (!got_pathset_contains(set, path2)) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}
	if (got_pathset_num_elements(set) != 2) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}

	err = got_pathset_add(set, path3, (void *)data3);
	if (err)
		goto done;
	if (got_pathset_get(set, path3) != (void *)data3) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}
	if (got_pathset_num_elements(set) != 3) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}

	err = got_pathset_remove(NULL, set, path2);
	if (err)
		goto done;
	if (got_pathset_num_elements(set) != 2) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}
	if (got_pathset_contains(set, path2)) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}
	if (got_pathset_get(set, path2) != NULL) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}

	got_pathset_for_each_safe(set, pathset_add_remove_iter_cb, NULL);
done:
	got_pathset_free(set);
	return (err == NULL);
}

static const struct got_error *
pathset_iter_order_cb(const char *path, void *data, void *arg)
{
	static int i;
	test_printf("%s\n", path);
	if (i == 0 && strcmp(path, "/") != 0)
		abort();
	if (i == 1 && strcmp(path, "/usr.bin") != 0)
		abort();
	if (i == 2 && strcmp(path, "/usr.bin/vi") != 0)
		abort();
	if (i == 3 && strcmp(path, "/usr.sbin") != 0)
		abort();
	if (i == 4 && strcmp(path, "/usr.sbin/unbound") != 0)
		abort();
	if (i == 5 && strcmp(path, "/usr.sbin/zic") != 0)
		abort();
	if (i > 5)
		abort();
	i++;
	return NULL;
}

static const struct got_error *
pathset_iter_reverse_order_cb(const char *path, void *data, void *arg)
{
	static int i;
	test_printf("%s\n", path);
	if (i == 0 && strcmp(path, "/usr.sbin/zic") != 0)
		abort();
	if (i == 1 && strcmp(path, "/usr.sbin/unbound") != 0)
		abort();
	if (i == 2 && strcmp(path, "/usr.sbin") != 0)
		abort();
	if (i == 3 && strcmp(path, "/usr.bin/vi") != 0)
		abort();
	if (i == 4 && strcmp(path, "/usr.bin") != 0)
		abort();
	if (i == 5 && strcmp(path, "/") != 0)
		abort();
	if (i > 5)
		abort();
	i++;
	return NULL;
}

static int
pathset_iter_order(void)
{
	const struct got_error *err = NULL;
	struct got_pathset *set;

	set = got_pathset_alloc();
	if (set == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	if (got_pathset_num_elements(set) != 0) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}


	err = got_pathset_add(set, "/usr.bin", (void *)data1);
	if (err)
		goto done;
	err = got_pathset_add(set, "/usr.sbin/unbound", (void *)data1);
	if (err)
		goto done;
	err = got_pathset_add(set, "/usr.bin/vi", (void *)data1);
	if (err)
		goto done;
	err = got_pathset_add(set, "/", (void *)data1);
	if (err)
		goto done;
	err = got_pathset_add(set, "/usr.sbin/zic", (void *)data1);
	if (err)
		goto done;
	err = got_pathset_add(set, "/usr.sbin", (void *)data1);
	if (err)
		goto done;

	test_printf("normal order:\n");
	got_pathset_for_each_safe(set, pathset_iter_order_cb, NULL);
	test_printf("reverse order:\n");
	got_pathset_for_each_reverse_safe(set, pathset_iter_reverse_order_cb,
	    NULL);
done:
	got_pathset_free(set);
	return (err == NULL);
}

#define RUN_TEST(expr, name) \
	{ test_ok = (expr);  \
	printf("test_%s %s\n", (name), test_ok ? "ok" : "failed"); \
	failure = (failure || !test_ok); }

void
usage(void)
{
	fprintf(stderr, "usage: pathset_test [-v]\n");
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

	RUN_TEST(pathset_add_remove_iter(), "pathset_add_remove_iter");
	RUN_TEST(pathset_iter_order(), "pathset_iter_order");

	return failure ? 1 : 0;
}
