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
struct got_tree_object;

struct got_tree_entry {
	SIMPLEQ_ENTRY(got_tree_entry) entry;
	mode_t mode;
	char *name;
	struct got_object_id *id;
};

SIMPLEQ_HEAD(got_tree_entries_queue, got_tree_entry);

struct got_tree_entries {
	int nentries;
	struct got_tree_entries_queue head;
};

struct got_object_qid {
	SIMPLEQ_ENTRY(got_object_qid) entry;
	struct got_object_id *id;
};

SIMPLEQ_HEAD(got_object_id_queue, got_object_qid);

const struct got_error *got_object_qid_alloc(struct got_object_qid **,
    struct got_object_id *);
void got_object_qid_free(struct got_object_qid *);

struct got_commit_object {
	struct got_object_id *tree_id;
	unsigned int nparents;
	struct got_object_id_queue parent_ids;
	char *author;
	struct tm tm_author;	/* UTC */
	char *committer;
	struct tm tm_committer;	/* UTC */
	char *logmsg;

	int refcnt; /* for internal use only */
};

/* A generic object. Used as a handle which holds an ID and an object type. */
struct got_object;
#define GOT_OBJ_TYPE_COMMIT		1
#define GOT_OBJ_TYPE_TREE		2
#define GOT_OBJ_TYPE_BLOB		3
#define GOT_OBJ_TYPE_TAG		4
/* 5 is reserved */
#define GOT_OBJ_TYPE_OFFSET_DELTA	6
#define GOT_OBJ_TYPE_REF_DELTA		7

struct got_repository;

/*
 * Obtain a string representation of an object ID. The output depends on
 * the hash function used by the repository format (currently SHA1).
 */
const struct got_error *got_object_id_str(char **, struct got_object_id *);

/*
 * Compare two object IDs. Return value behaves like memcmp(3).
 */
int got_object_id_cmp(struct got_object_id *, struct got_object_id *);

/*
 * Created a newly allocated copy of an object ID.
 * The caller should dispose of it with free(3).
 */
struct got_object_id *got_object_id_dup(struct got_object_id *);

/*
 * Get a newly allocated copy of an object's ID.
 * The caller must treat the ID as read-only and must not call free(3) on it.
 * Use got_object_id_dup() to get a writable copy.
 */
struct got_object_id *got_object_get_id(struct got_object *);

/*
 * Get a newly allocated copy of an object's ID string.
 * The caller should dispose of it with free(3).
 */
const struct got_error *got_object_get_id_str(char **, struct got_object *);

/*
 * Get a newly allocated ID of the object which resides at the specified
 * path in the tree of the specified commit.
 * The caller should dispose of it with free(3).
 */
const struct got_error *
got_object_id_by_path(struct got_object_id **, struct got_repository *,
    struct got_object_id *, const char *);

/*
 * Obtain the type of an object.
 * Returns one of the GOT_OBJ_TYPE_x values (see above).
 */
int got_object_get_type(struct got_object *);

/*
 * Attempt to open the object in a repository with the provided ID.
 * Caller must dispose of it with got_object_close().
 */
const struct got_error *got_object_open(struct got_object **,
    struct got_repository *, struct got_object_id *);

/*
 * Attempt to map the provided ID string to an object ID and then
 * attempt to open the object in a repository with this ID.
 * The form of an ID string depends on the hash function used by the
 * repository format (currently SHA1).
 * Caller must dispose of the object with got_object_close().
 */
const struct got_error *got_object_open_by_id_str(struct got_object **,
    struct got_repository *, const char *);

/* Dispose of an object. */
void got_object_close(struct got_object *);

/*
 * Attempt to open a commit object in a repository.
 * The provided object must be of type GOT_OBJ_TYPE_COMMIT.
 * The caller must dispose of the commit with got_object_commit_close().
 */
const struct got_error *got_object_commit_open(struct got_commit_object **,
    struct got_repository *, struct got_object *);

/* Dispose of a commit object. */
void got_object_commit_close(struct got_commit_object *);

/*
 * Attempt to open a tree object in a repository.
 * The provided object must be of type GOT_OBJ_TYPE_TREE.
 * The caller must dispose of the tree with got_object_tree_close().
 */
const struct got_error *got_object_tree_open(struct got_tree_object **,
    struct got_repository *, struct got_object *);

/* Dispose of a tree object. */
void got_object_tree_close(struct got_tree_object *);

/* Get the entries of a tree object. */
const struct got_tree_entries *got_object_tree_get_entries(
    struct got_tree_object *);

/*
 * Compare two trees and indicate whether the entry at the specified path
 * differs between them. The path must not be the root path "/"; the function
 * got_object_id_cmp() should be used instead to compare the tree roots.
 */
const struct got_error *got_object_tree_path_changed(int *,
    struct got_tree_object *, struct got_tree_object *, const char *,
    struct got_repository *);

/*
 * Attempt to open a blob object in a repository.
 * The provided object must be of type GOT_OBJ_TYPE_BLOB.
 * The size_t argument specifies the block size of an associated read buffer.
 * The caller must dispose of the blob with got_object_blob_close().
 */
const struct got_error *got_object_blob_open(struct got_blob_object **,
    struct got_repository *, struct got_object *, size_t);

/* Dispose of a blob object. */
void got_object_blob_close(struct got_blob_object *);

/*
 * Write the string representation of the object ID of a blob to a buffer.
 * The size_t argument speficies the size of the buffer. In the current
 * implementation, it must be at least SHA1_DIGEST_STRING_LENGTH bytes.
 * XXX This is a bad API, use got_object_id_str() instead.
 */
char *got_object_blob_id_str(struct got_blob_object*, char *, size_t);

/*
 * Get the length of header data at the beginning of the blob's read buffer.
 * Note that header data is only present upon the first invocation of
 * got_object_blob_read_block() after the blob is opened.
 */
size_t got_object_blob_get_hdrlen(struct got_blob_object *);

/*
 * Get a pointer to the blob's read buffer.
 * The read buffer is filled by got_object_blob_read_block().
 */
const uint8_t *got_object_blob_get_read_buf(struct got_blob_object *);

/*
 * Read the next chunk of data from a blob, up to the blob's read buffer
 * block size. The size_t output argument indicates how many bytes have
 * been read into the blob's read buffer. Zero bytes will be reported if
 * all data in the blob has been read.
 */
const struct got_error *got_object_blob_read_block(size_t *,
    struct got_blob_object *);

/*
 * Read the entire content of a blob and write it to the specified file.
 * Flush and rewind the file as well. Indicate the amount of bytes
 * written in the first size_t output argument, and the number of lines
 * in the file in the second size_t output argument (NULL can be passed
 * for either output argument).
 */
const struct got_error *got_object_blob_dump_to_file(size_t *, size_t *,
    FILE *, struct got_blob_object *);

const struct got_error *
got_object_open_as_commit(struct got_commit_object **,
    struct got_repository *, struct got_object_id *);
const struct got_error *
got_object_open_as_tree(struct got_tree_object **,
    struct got_repository *, struct got_object_id *);
const struct got_error *
got_object_open_as_blob(struct got_blob_object **,
    struct got_repository *, struct got_object_id *, size_t);

const struct got_error *got_object_commit_add_parent(struct got_commit_object *,
    const char *);
