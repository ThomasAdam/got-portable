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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <getopt.h>

#include "got_error.h"
#include "got_opentemp.h"
#include "got_path.h"

#include "got_lib_delta.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

struct delta_test {
	const char *base;
	size_t base_len;
	const char *delta;
	size_t delta_len;
	const char *expected;
	size_t result_len;
} delta_tests[] = {
	/* base len 0, target len 4, append 4 'x' */
	{ "", 0, "\x00\x04\x04xxxx", 7, "xxxx", 4 },
	/* copy 4 bytes at offset 0 from base, append 4 'x' */
	{ "aabbccdd", 8, "\x08\x08\x90\x04\x04xxxx", 9, "aabbxxxx", 8 },
	/* copy 4 bytes at offset 4 from base, append 4 'x' */
	{ "aabbccdd", 8, "\x08\x08\x91\x04\x04\x04xxxx", 10, "ccddxxxx", 8 },
	/* git 48fb7deb5 Fix big left-shifts of unsigned char, 2009-06-17) */
	{ "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	  16, "\x10\x10\xff\xff\xff\xff\xff\x10\00\00", 10 , NULL, 0 },
	/* libgit2 9844d38be delta: fix out-of-bounds read of delta */
	{ "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	  16, "\x10\x70\xff", 3, NULL, 0}
};

static int
delta_apply(void)
{
	const struct got_error *err = NULL;
	size_t i;
	FILE *result_file;

	result_file = got_opentemp();
	if (result_file == NULL)
		return 1;

	for (i = 0; i < nitems(delta_tests); i++) {
		struct delta_test *dt = &delta_tests[i];
		FILE *base_file;
		char buf[1024];
		size_t n, result_len;

		base_file = got_opentemp();
		if (base_file == NULL) {
			err = got_error_from_errno("got_opentemp");
			break;
		}

		n = fwrite(dt->base, 1, dt->base_len, base_file);
		if (n != dt->base_len) {
			err = got_ferror(base_file, GOT_ERR_IO);
			break;
		}
		rewind(base_file);

		err = got_delta_apply(base_file, dt->delta, dt->delta_len,
		    result_file, &result_len);
		if (fclose(base_file) != 0 && err == NULL)
			err = got_error_from_errno("fclose");
		if (dt->expected == NULL) {
			/* Invalid delta, expect an error. */
			if (err == NULL)
				err = got_error(GOT_ERR_EXPECTED);
			else if (err->code == GOT_ERR_BAD_DELTA)
				err = NULL;
		} else {
			if (err)
				break;
			if (result_len != dt->result_len) {
				err = got_ferror(result_file,
				    GOT_ERR_BAD_DELTA);
				break;
			}
			n = fread(buf, result_len, 1, result_file);
			if (n != 1 ||
			    strncmp(buf, dt->expected, result_len) != 0) {
				err = got_ferror(result_file,
				    GOT_ERR_BAD_DELTA);
				break;
			}
		}
		rewind(result_file);
	}

	fclose(result_file);
	return (err == NULL);
}

static int quiet;

#define RUN_TEST(expr, name) \
	{ test_ok = (expr);  \
	if (!quiet) printf("test_%s %s\n", (name), test_ok ? "ok" : "failed"); \
	failure = (failure || !test_ok); }

static void
usage(void)
{
	fprintf(stderr, "usage: delta_test [-q]\n");
}

int
main(int argc, char *argv[])
{
	int test_ok;
	int failure = 0;
	int ch;

	while ((ch = getopt(argc, argv, "q")) != -1) {
		switch (ch) {
		case 'q':
			quiet = 1;
			break;
		default:
			usage();
			return 1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0) {
		usage();
		return 1;
	}

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath unveil", NULL) == -1)
		err(1, "pledge");
#endif
	if (unveil(GOT_TMPDIR_STR, "rwc") != 0)
		err(1, "unveil");

	if (unveil(NULL, NULL) != 0)
		err(1, "unveil");

	RUN_TEST(delta_apply(), "delta_apply");

	return failure ? 1 : 0;
}
