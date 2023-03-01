/*
 * Copyright (c) 2021 Stefan Sperling <stsp@openbsd.org>
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

#include "got_compat.h"

#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <getopt.h>

#include "got_error.h"
#include "got_opentemp.h"

#include "got_lib_deltify.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

static int
deltify_abc_axc(void)
{
	const struct got_error *err = NULL;
	size_t i;
	FILE *base_file, *derived_file, *result_file;
	struct got_delta_table *dt;
	struct got_delta_instruction *deltas;
	int ndeltas;
	int have_nblocks = 0;
	uint32_t seed;

	seed = arc4random();

	base_file = got_opentemp();
	if (base_file == NULL)
		return 1;

	derived_file = got_opentemp();
	if (derived_file == NULL)
		return 1;

	result_file = got_opentemp();
	if (result_file == NULL)
		return 1;

	for (i = 0; i < GOT_DELTIFY_MAXCHUNK; i++) {
		fputc('a', base_file);
		fputc('a', derived_file);
	}
	for (i = 0; i < GOT_DELTIFY_MAXCHUNK; i++) {
		fputc('b', base_file);
		fputc('x', derived_file);
	}
	for (i = 0; i < GOT_DELTIFY_MAXCHUNK; i++) {
		fputc('c', base_file);
		fputc('c', derived_file);
	}

	rewind(base_file);
	rewind(derived_file);

	err = got_deltify_init(&dt, base_file, 0, 3 * GOT_DELTIFY_MAXCHUNK,
	    seed);
	if (err)
		goto done;

	for (i = 0; i < dt->nalloc; i++) {
		if (dt->blocks[i].len > 0)
			have_nblocks++;
	}
	if (have_nblocks != dt->nblocks) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}

	err = got_deltify(&deltas, &ndeltas, derived_file, 0,
	    3 * GOT_DELTIFY_MAXCHUNK, seed, dt, base_file, 0,
	    3 * GOT_DELTIFY_MAXCHUNK);
	if (err)
		goto done;

	if (ndeltas != 3) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}
	/* Copy 'aaaa...' from base file. */
	if (!(deltas[0].copy == 1 && deltas[0].offset == 0 &&
	    deltas[0].len == GOT_DELTIFY_MAXCHUNK)) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}
	/* Copy 'xxxx...' from derived file. */
	if (!(deltas[1].copy == 0 && deltas[1].offset == GOT_DELTIFY_MAXCHUNK &&
	    deltas[1].len == GOT_DELTIFY_MAXCHUNK)) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}
	/* Copy 'ccccc...' from base file. */
	if (!(deltas[2].copy == 1 &&
	    deltas[2].offset == 2 * GOT_DELTIFY_MAXCHUNK &&
	    deltas[2].len == GOT_DELTIFY_MAXCHUNK)) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}

done:
	got_deltify_free(dt);
	fclose(base_file);
	fclose(derived_file);
	fclose(result_file);
	return (err == NULL);
}

static int
deltify_abc_axc_file_mem(void)
{
	const struct got_error *err = NULL;
	size_t i;
	uint8_t base_data[3 * GOT_DELTIFY_MAXCHUNK];
	FILE *derived_file, *result_file;
	struct got_delta_table *dt;
	struct got_delta_instruction *deltas;
	int ndeltas;
	int have_nblocks = 0;
	uint32_t seed;

	seed = arc4random();

	derived_file = got_opentemp();
	if (derived_file == NULL)
		return 1;

	result_file = got_opentemp();
	if (result_file == NULL)
		return 1;

	for (i = 0; i < GOT_DELTIFY_MAXCHUNK; i++) {
		base_data[i] = 'a';
		fputc('a', derived_file);
	}
	for (i = 0; i < GOT_DELTIFY_MAXCHUNK; i++) {
		base_data[GOT_DELTIFY_MAXCHUNK + i] = 'b';
		fputc('x', derived_file);
	}
	for (i = 0; i < GOT_DELTIFY_MAXCHUNK; i++) {
		base_data[2 * GOT_DELTIFY_MAXCHUNK + i] = 'c';
		fputc('c', derived_file);
	}

	rewind(derived_file);

	err = got_deltify_init_mem(&dt, base_data, 0, 3 * GOT_DELTIFY_MAXCHUNK,
	    seed);
	if (err)
		goto done;

	for (i = 0; i < dt->nalloc; i++) {
		if (dt->blocks[i].len > 0)
			have_nblocks++;
	}
	if (have_nblocks != dt->nblocks) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}

	err = got_deltify_file_mem(&deltas, &ndeltas, derived_file, 0,
	    3 * GOT_DELTIFY_MAXCHUNK, seed, dt, base_data, 0,
	    3 * GOT_DELTIFY_MAXCHUNK);
	if (err)
		goto done;

	if (ndeltas != 3) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}
	/* Copy 'aaaa...' from base file. */
	if (!(deltas[0].copy == 1 && deltas[0].offset == 0 &&
	    deltas[0].len == GOT_DELTIFY_MAXCHUNK)) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}
	/* Copy 'xxxx...' from derived file. */
	if (!(deltas[1].copy == 0 && deltas[1].offset == GOT_DELTIFY_MAXCHUNK &&
	    deltas[1].len == GOT_DELTIFY_MAXCHUNK)) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}
	/* Copy 'ccccc...' from base file. */
	if (!(deltas[2].copy == 1 &&
	    deltas[2].offset == 2 * GOT_DELTIFY_MAXCHUNK &&
	    deltas[2].len == GOT_DELTIFY_MAXCHUNK)) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}

done:
	got_deltify_free(dt);
	fclose(derived_file);
	fclose(result_file);
	return (err == NULL);
}

static int
deltify_abc_axc_mem_file(void)
{
	const struct got_error *err = NULL;
	size_t i;
	FILE *base_file, *result_file;
	uint8_t derived_file[3 * GOT_DELTIFY_MAXCHUNK];
	struct got_delta_table *dt;
	struct got_delta_instruction *deltas;
	int ndeltas;
	int have_nblocks = 0;
	uint32_t seed;

	seed = arc4random();

	base_file = got_opentemp();
	if (base_file == NULL)
		return 1;

	result_file = got_opentemp();
	if (result_file == NULL)
		return 1;

	for (i = 0; i < GOT_DELTIFY_MAXCHUNK; i++) {
		fputc('a', base_file);
		derived_file[i] = 'a';
	}
	for (i = 0; i < GOT_DELTIFY_MAXCHUNK; i++) {
		fputc('b', base_file);
		derived_file[GOT_DELTIFY_MAXCHUNK + i] = 'x';
	}
	for (i = 0; i < GOT_DELTIFY_MAXCHUNK; i++) {
		fputc('c', base_file);
		derived_file[2 * GOT_DELTIFY_MAXCHUNK + i] = 'c';
	}

	rewind(base_file);

	err = got_deltify_init(&dt, base_file, 0, 3 * GOT_DELTIFY_MAXCHUNK,
	    seed);
	if (err)
		goto done;

	for (i = 0; i < dt->nalloc; i++) {
		if (dt->blocks[i].len > 0)
			have_nblocks++;
	}
	if (have_nblocks != dt->nblocks) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}

	err = got_deltify_mem_file(&deltas, &ndeltas, derived_file, 0,
	    3 * GOT_DELTIFY_MAXCHUNK, seed, dt, base_file, 0,
	    3 * GOT_DELTIFY_MAXCHUNK);
	if (err)
		goto done;

	if (ndeltas != 3) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}
	/* Copy 'aaaa...' from base file. */
	if (!(deltas[0].copy == 1 && deltas[0].offset == 0 &&
	    deltas[0].len == GOT_DELTIFY_MAXCHUNK)) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}
	/* Copy 'xxxx...' from derived file. */
	if (!(deltas[1].copy == 0 && deltas[1].offset == GOT_DELTIFY_MAXCHUNK &&
	    deltas[1].len == GOT_DELTIFY_MAXCHUNK)) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}
	/* Copy 'ccccc...' from base file. */
	if (!(deltas[2].copy == 1 &&
	    deltas[2].offset == 2 * GOT_DELTIFY_MAXCHUNK &&
	    deltas[2].len == GOT_DELTIFY_MAXCHUNK)) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}

done:
	got_deltify_free(dt);
	fclose(base_file);
	fclose(result_file);
	return (err == NULL);
}

static int
deltify_abc_axc_mem_mem(void)
{
	const struct got_error *err = NULL;
	size_t i;
	FILE *result_file;
	uint8_t base_file[3 * GOT_DELTIFY_MAXCHUNK];
	uint8_t derived_file[3 * GOT_DELTIFY_MAXCHUNK];
	struct got_delta_table *dt;
	struct got_delta_instruction *deltas;
	int ndeltas;
	int have_nblocks = 0;
	uint32_t seed;

	seed = arc4random();

	result_file = got_opentemp();
	if (result_file == NULL)
		return 1;

	for (i = 0; i < GOT_DELTIFY_MAXCHUNK; i++) {
		base_file[i] = 'a';
		derived_file[i] = 'a';
	}
	for (i = 0; i < GOT_DELTIFY_MAXCHUNK; i++) {
		base_file[GOT_DELTIFY_MAXCHUNK + i] = 'b';
		derived_file[GOT_DELTIFY_MAXCHUNK + i] = 'x';
	}
	for (i = 0; i < GOT_DELTIFY_MAXCHUNK; i++) {
		base_file[2 * GOT_DELTIFY_MAXCHUNK + i] = 'c';
		derived_file[2 * GOT_DELTIFY_MAXCHUNK + i] = 'c';
	}

	err = got_deltify_init_mem(&dt, base_file, 0, 3 * GOT_DELTIFY_MAXCHUNK,
	    seed);
	if (err)
		goto done;

	for (i = 0; i < dt->nalloc; i++) {
		if (dt->blocks[i].len > 0)
			have_nblocks++;
	}
	if (have_nblocks != dt->nblocks) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}

	err = got_deltify_mem_mem(&deltas, &ndeltas, derived_file, 0,
	    3 * GOT_DELTIFY_MAXCHUNK, seed, dt, base_file, 0,
	    3 * GOT_DELTIFY_MAXCHUNK);
	if (err)
		goto done;

	if (ndeltas != 3) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}
	/* Copy 'aaaa...' from base file. */
	if (!(deltas[0].copy == 1 && deltas[0].offset == 0 &&
	    deltas[0].len == GOT_DELTIFY_MAXCHUNK)) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}
	/* Copy 'xxxx...' from derived file. */
	if (!(deltas[1].copy == 0 && deltas[1].offset == GOT_DELTIFY_MAXCHUNK &&
	    deltas[1].len == GOT_DELTIFY_MAXCHUNK)) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}
	/* Copy 'ccccc...' from base file. */
	if (!(deltas[2].copy == 1 &&
	    deltas[2].offset == 2 * GOT_DELTIFY_MAXCHUNK &&
	    deltas[2].len == GOT_DELTIFY_MAXCHUNK)) {
		err = got_error(GOT_ERR_BAD_DELTA);
		goto done;
	}

done:
	got_deltify_free(dt);
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

	RUN_TEST(deltify_abc_axc(), "deltify_abc_axc");
	RUN_TEST(deltify_abc_axc_file_mem(), "deltify_abc_axc_file_mem");
	RUN_TEST(deltify_abc_axc_mem_file(), "deltify_abc_axc_mem_file");
	RUN_TEST(deltify_abc_axc_mem_mem(), "deltify_abc_axc_mem_mem");

	return failure ? 1 : 0;
}
