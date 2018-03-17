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

struct got_object_id;

struct got_blob_object;

struct got_tree_entry {
	SIMPLEQ_ENTRY(got_tree_entry) entry;
	mode_t mode;
	char *name;
	struct got_object_id *id;
};

struct got_tree_object {
	int nentries;
	SIMPLEQ_HEAD(, got_tree_entry) entries;
};

struct got_parent_id {
	SIMPLEQ_ENTRY(got_parent_id) entry;
	struct got_object_id *id;
};

struct got_commit_object {
	struct got_object_id *tree_id;
	unsigned int nparents;
	SIMPLEQ_HEAD(, got_parent_id) parent_ids;
	char *author;
	char *committer;
	char *logmsg;
};

struct got_object;
#define GOT_OBJ_TYPE_COMMIT		1
#define GOT_OBJ_TYPE_TREE		2
#define GOT_OBJ_TYPE_BLOB		3
#define GOT_OBJ_TYPE_TAG		4
/* 5 is reserved */
#define GOT_OBJ_TYPE_OFFSET_DELTA	6
#define GOT_OBJ_TYPE_REF_DELTA		7

struct got_repository;

const struct got_error *got_object_id_str(char **, struct got_object_id *);
int got_object_id_cmp(struct got_object_id *, struct got_object_id *);
struct got_object_id *got_object_id_dup(struct got_object_id *);
int got_object_get_type(struct got_object *);
const struct got_error *got_object_open(struct got_object **,
    struct got_repository *, struct got_object_id *);
const struct got_error *got_object_open_by_id_str(struct got_object **,
    struct got_repository *, const char *); 
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
char *got_object_blob_id_str(struct got_blob_object*, char *, size_t);
size_t got_object_blob_get_hdrlen(struct got_blob_object *);
const uint8_t *got_object_blob_get_read_buf(struct got_blob_object *);
const struct got_error *got_object_blob_read_block(size_t *,
    struct got_blob_object *);
