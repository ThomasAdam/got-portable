/*
 * Copyright (c) 2017 Stefan Sperling <stsp@openbsd.org>
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

struct got_blob_object {
	char *dummy;
};

struct got_tree_object {
	char *dummy;
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
#define GOT_OBJ_TYPE_COMMIT 	1
#define GOT_OBJ_TYPE_TREE	2
#define GOT_OBJ_TYPE_BLOB	3

	size_t hdrlen;
	size_t size;
	struct got_object_id id;
	union {
		struct got_blob_object blob;
		struct got_tree_object tree;
		struct got_commit_object commit;
	} obj;
};

struct got_repository;

const char * got_object_id_str(struct got_object_id *, char *, size_t);
const struct got_error *got_object_open(struct got_object **,
    struct got_repository *, struct got_object_id *);
void got_object_close(struct got_object *);
const struct got_error *got_object_commit_open(struct got_commit_object **,
    struct got_repository *, struct got_object *);
void got_object_commit_close(struct got_commit_object *);

