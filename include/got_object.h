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

struct got_zstream_buf {
	z_stream z;
	char *inbuf;
	size_t inlen;
	char *outbuf;
	size_t outlen;
	int flags;
#define GOT_ZSTREAM_F_HAVE_MORE 0x01
};

struct got_object_id {
	u_int8_t sha1[SHA1_DIGEST_LENGTH];
};

struct got_blob_object {
	FILE *f;
	struct got_zstream_buf zb;
	size_t hdrlen;
	struct got_object_id id;
};

struct got_tree_entry {
	SIMPLEQ_ENTRY(got_tree_entry) entry;
	mode_t mode;
	char *name;
	struct got_object_id id;
};

struct got_tree_object {
	int nentries;
	SIMPLEQ_HEAD(, got_tree_entry) entries;
};

struct got_parent_id {
	SIMPLEQ_ENTRY(got_parent_id) entry;
	struct got_object_id id;
};

SIMPLEQ_HEAD(got_parent_id_list, got_parent_id);

struct got_commit_object {
	struct got_object_id tree_id;
	unsigned int nparents;
	SIMPLEQ_HEAD(, got_parent_id) parent_ids;
	char *author;
	char *committer;
	char *logmsg;
};

struct got_object {
	int type;
#define GOT_OBJ_TYPE_COMMIT		1
#define GOT_OBJ_TYPE_TREE		2
#define GOT_OBJ_TYPE_BLOB		3
#define GOT_OBJ_TYPE_TAG		4
/* 5 is reserved */
#define GOT_OBJ_TYPE_OFFSET_DELTA	6
#define GOT_OBJ_TYPE_REF_DELTA		7

	int flags;
#define GOT_OBJ_FLAG_PACKED		0x01

	size_t hdrlen;
	size_t size;
	struct got_object_id id;

	char *path_packfile;
	off_t pack_offset;
};

struct got_repository;

char *got_object_id_str(struct got_object_id *, char *, size_t);
int got_object_id_cmp(struct got_object_id *, struct got_object_id *);
const char *got_object_get_type_tag(int);
const struct got_error *got_object_open(struct got_object **,
    struct got_repository *, struct got_object_id *);
void got_object_close(struct got_object *);
const struct got_error *got_object_commit_open(struct got_commit_object **,
    struct got_repository *, struct got_object *);
void got_object_commit_close(struct got_commit_object *);
const struct got_error *got_object_tree_open(struct got_tree_object **,
    struct got_repository *, struct got_object *);
void got_object_tree_close(struct got_tree_object *);
const struct got_error *got_object_blob_open(struct got_blob_object **,
    struct got_repository *, struct got_object *, size_t);
void got_object_blob_close(struct got_blob_object *);
const struct got_error *got_object_blob_read_block(struct got_blob_object *,
    size_t *);
