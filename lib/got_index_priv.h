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

/* 
 * Meta data about a tracked on-disk file.
 *
 * Note that some fields are results from stat(2). These are only used in
 * order to detect modifications made to on-disk files, they are never
 * applied back to the filesystem.
 */
struct got_index_entry {
	struct timespec ctime;
	struct timespec mtime;
	uint32_t mode;
#define GOT_INDEX_ENTRY_MODE_OBJ_TYPE	0x0000000f
#define GOT_INDEX_ENTRY_MODE_PERMS	0x0000ff10
	uint32_t uid;
	uint32_t gid;
	uint32_t size;

	uint8_t obj_sha1[SHA1_DIGEST_LENGTH];
	uint32_t flags;
#define GOT_INDEX_ENTRY_F_NAME_LEN	0x00000fff
#define GOT_INDEX_ENTRY_F_STAGE		0x00003000
#define GOT_INDEX_ENTRY_F_EXTENDED	0x00004000
#define GOT_INDEX_ENTRY_F_ASSUME_VALID	0x00008000

	/* This is a unix-style path relative to top level directory. */
	const char *path;
};

struct got_index {
	uint32_t signature;
	uint32_t version;
	uint32_t nentries;
	struct got_index_entry *entries;
	/* extensions go here */
	uint8_t sha1[SHA1_DIGEST_LENGTH];
};
