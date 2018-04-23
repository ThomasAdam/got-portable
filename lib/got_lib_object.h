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

struct got_object_id {
	u_int8_t sha1[SHA1_DIGEST_LENGTH];
};

struct got_object {
	int type;
	int flags;
#define GOT_OBJ_FLAG_PACKED		0x01
#define GOT_OBJ_FLAG_DELTIFIED		0x02

	size_t hdrlen;
	size_t size;
	struct got_object_id id;

	char *path_packfile;	/* if packed */
	off_t pack_offset;	/* if packed */
	struct got_delta_chain deltas; /* if deltified */
};

struct got_blob_object {
	FILE *f;
	struct got_zstream_buf zb;
	size_t hdrlen;
	size_t blocksize;
	uint8_t *read_buf;
	int flags;
#define GOT_BLOB_F_COMPRESSED	0x01
	struct got_object_id id;
};

struct got_commit_object *got_object_commit_alloc_partial(void);
