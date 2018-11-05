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
	int pack_idx;		/* if packed */
	off_t pack_offset;	/* if packed */
	struct got_delta_chain deltas; /* if deltified */
	int refcnt;		/* > 0 if open and/or cached */
};

struct got_tree_object {
	struct got_tree_entries entries;
	int refcnt;
};

struct got_blob_object {
	FILE *f;
	struct got_zstream_buf zb;
	size_t hdrlen;
	size_t blocksize;
	uint8_t *read_buf;
	struct got_object_id id;
};

/* Small version of got_commit_object. Used by commit graph. */
struct got_commit_object_mini {
	struct got_object_id *tree_id;
	unsigned int nparents;
	struct got_object_id_queue parent_ids;
	struct tm tm_committer;	/* UTC */
};

const struct got_error *
got_object_open_mini_commit(struct got_commit_object_mini **,
    struct got_repository *, struct got_object_id *);
void got_object_mini_commit_close(struct got_commit_object_mini *);
