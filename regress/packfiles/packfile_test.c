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

#include <sys/stat.h>
#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <sha1.h>
#include <zlib.h>

#include "got_error.h"
#include "got_object.h"
#include "pack.h"

#define GOT_REPO_PATH "../../../"

static int
packfile_read_idx(const char *repo_path)
{
	const struct got_error *err;
	struct got_packidx_v2_hdr *packidx;
	const char *pack_checksum = "5414c35e56c54294d2515863832bf46ad0e321d7";
	const char *pack_prefix = ".git/objects/pack/pack";
	char *fullpath;
	int ret = 1;

	if (asprintf(&fullpath, "%s/%s-%s.idx", repo_path, pack_prefix,
	    pack_checksum) == -1)
		return 0;

	err = got_packidx_open(&packidx, fullpath);
	if (err) {
		printf("got_packidx_open: %s\n", err->msg);
		ret = 0;
	}

	got_packidx_close(packidx);
	free(fullpath);
	return ret;
}

#define RUN_TEST(expr, name) \
	{ test_ok = (expr);  \
	printf("test %s %s\n", (name), test_ok ? "ok" : "failed"); \
	failure = (failure || !test_ok); }

int
main(int argc, const char *argv[])
{
	int test_ok = 0, failure = 0;
	const char *repo_path;

	if (argc == 1)
		repo_path = GOT_REPO_PATH;
	else if (argc == 2)
		repo_path = argv[1];
	else {
		fprintf(stderr, "usage: repository_test [REPO_PATH]\n");
		return 1;
	}

	RUN_TEST(packfile_read_idx(repo_path), "packfile_read_idx");

	return failure ? 1 : 0;
}
