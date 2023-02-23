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

#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <sha1.h>
#include <sha2.h>
#include <zlib.h>
#include <time.h>

#include "got_error.h"
#include "got_object.h"

#include "got_lib_object_idset.h"
#include "got_lib_hash.h"
#include "got_lib_inflate.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"

static int verbose;
static int quiet;

static const char *id_str1 = "1111111111111111111111111111111111111111";
static const char *id_str2 = "2222222222222222222222222222222222222222";
static const char *id_str3 = "ffffffffffffffffffffffffffffffffffffffff";
static struct got_object_id id1, id2, id3;
static const char *data1 = "data1", *data2 = "data2", *data3 = "data3";

static const struct got_error *
idset_cb(struct got_object_id *id, void *data, void *arg) {
	if ((got_object_id_cmp(id, &id1) == 0 && data == (void *)data1) ||
	    (got_object_id_cmp(id, &id3) == 0 && data == (void *)data3))
		return NULL;
	abort();
	return NULL; /* not reached */
}

static int
idset_add_remove_iter(void)
{
	const struct got_error *err = NULL;
	struct got_object_idset *set;

	set = got_object_idset_alloc();
	if (set == NULL) {
		err = got_error_from_errno("got_object_idset_alloc");
		goto done;
	}
	if (got_object_idset_num_elements(set) != 0) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	if (!got_parse_sha1_digest(id1.sha1, id_str1)) {
		err = got_error(GOT_ERR_BAD_OBJ_ID_STR);
		goto done;
	}
	if (!got_parse_sha1_digest(id2.sha1, id_str2)) {
		err = got_error(GOT_ERR_BAD_OBJ_ID_STR);
		goto done;
	}
	if (!got_parse_sha1_digest(id3.sha1, id_str3)) {
		err = got_error(GOT_ERR_BAD_OBJ_ID_STR);
		goto done;
	}

	err = got_object_idset_add(set, &id1, (void *)data1);
	if (err)
		goto done;
	if (got_object_idset_num_elements(set) != 1) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	if (!got_object_idset_contains(set, &id1)) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	err = got_object_idset_add(set, &id2, (void *)data2);
	if (err)
		goto done;

	if (!got_object_idset_contains(set, &id1)) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}
	if (!got_object_idset_contains(set, &id2)) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}
	if (got_object_idset_num_elements(set) != 2) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	err = got_object_idset_add(set, &id3, (void *)data3);
	if (err)
		goto done;

	if (got_object_idset_get(set, &id1) != (void *)data1) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}
	if (got_object_idset_get(set, &id2) != (void *)data2) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}
	if (got_object_idset_get(set, &id3) != (void *)data3) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}
	if (got_object_idset_num_elements(set) != 3) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	err = got_object_idset_remove(NULL, set, &id2);
	if (err)
		goto done;
	if (got_object_idset_num_elements(set) != 2) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}
	if (got_object_idset_contains(set, &id2)) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}
	if (got_object_idset_get(set, &id2) != NULL) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	got_object_idset_for_each(set, idset_cb, NULL);
done:
	got_object_idset_free(set);
	return (err == NULL);
}

#define RUN_TEST(expr, name) \
	{ test_ok = (expr);  \
	if (!quiet) printf("test_%s %s\n", (name), test_ok ? "ok" : "failed"); \
	failure = (failure || !test_ok); }

static void
usage(void)
{
	fprintf(stderr, "usage: id_test [-v] [-q]\n");
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

	while ((ch = getopt(argc, argv, "qv")) != -1) {
		switch (ch) {
		case 'q':
			quiet = 1;
			verbose = 0;
			break;
		case 'v':
			verbose = 1;
			quiet = 0;
			break;
		default:
			usage();
			return 1;
		}
	}
	argc -= optind;
	argv += optind;

	RUN_TEST(idset_add_remove_iter(), "idset_add_remove_iter");

	return failure ? 1 : 0;
}
