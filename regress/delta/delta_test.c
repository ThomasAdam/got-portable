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
#include <string.h>
#include <err.h>
#include <unistd.h>

#include "got_error.h"
#include "got_opentemp.h"

#include "got_lib_delta.h"
#include "got_lib_path.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

struct delta_test {
	const char *base;
	const char *delta;
	size_t delta_len;
	const char *expected;
} delta_tests[] = {
	/* base len 0, target len 4, append 4 'x' */
	{ "", "\x00\x04\x04xxxx", 7, "xxxx" },
	/* copy 4 bytes at offset 0 from base, append 4 'x' */
	{ "aabbccdd", "\x08\x08\x90\x04\x04xxxx", 9, "aabbxxxx" },
	/* copy 4 bytes at offset 4 from base, append 4 'x' */
	{ "aabbccdd", "\x08\x08\x91\x04\x04\x04xxxx", 10, "ccddxxxx" },
};

static int
delta_apply()
{
	const struct got_error *err = NULL;
	int i;
	FILE *result_file;

	result_file = got_opentemp();
	if (result_file == NULL)
		return 1;

	for (i = 0; i < nitems(delta_tests); i++) {
		struct delta_test *dt = &delta_tests[i];
		FILE *base_file;
		char buf[1024];
		size_t n, len, result_len;

		len = strlen(dt->base);
		base_file = got_opentemp();
		if (base_file == NULL) {
			err = got_error_from_errno();
			break;
		}

		n = fwrite(dt->base, 1, len, base_file);
		if (n != len) {
			err = got_ferror(base_file, GOT_ERR_IO);
			break;
		}
		rewind(base_file);

		err = got_delta_apply(base_file, dt->delta, dt->delta_len,
		    result_file, &len);
		fclose(base_file);
		if (err)
			break;
		result_len = strlen(dt->expected);
		if (result_len != len) {
			err = got_ferror(result_file, GOT_ERR_BAD_DELTA);
			break;
		}
		n = fread(buf, result_len, 1, result_file);
		if (n != 1 || strncmp(buf, dt->expected, result_len) != 0) {
			err = got_ferror(result_file, GOT_ERR_BAD_DELTA);
			break;
		}
		rewind(result_file);
	}

	fclose(result_file);
	return (err == NULL);
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

	if (pledge("stdio rpath wpath cpath", NULL) == -1)
		err(1, "pledge");

	RUN_TEST(delta_apply(), "delta_apply");

	return failure ? 1 : 0;
}
