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

struct got_delta_cache_entry {
	off_t data_offset;
	uint8_t *delta_buf;
	size_t delta_len;
};

#define GOT_DELTA_CACHE_SIZE	1024

struct got_delta_cache {
	char *path_packfile;
	struct got_delta_cache_entry deltas[GOT_DELTA_CACHE_SIZE];
};

#define GOT_PACK_CACHE_SIZE	64

struct got_pack_cache {
	struct got_packidx_v2_hdr *packidx;
	char *path_packfile;
	FILE *packfile;
};

struct got_repository {
	char *path;
	char *path_git_dir;

	/* 
	 * The pack cache speeds up search for packed objects and
	 * avoids duplicate open file handles to pack files.
	 */
	struct got_pack_cache pack_cache[GOT_PACK_CACHE_SIZE];

	/* The delta cache speeds up reconstruction of packed objects. */
	struct got_delta_cache delta_cache[GOT_PACK_CACHE_SIZE];
};

