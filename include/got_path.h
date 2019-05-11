/*
 * Copyright (c) 2018, 2019 Stefan Sperling <stsp@openbsd.org>
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

/* Utilities for dealing with filesystem paths. */

#define GOT_DEFAULT_FILE_MODE	(S_IRUSR|S_IWUSR | S_IRGRP | S_IROTH)
#define GOT_DEFAULT_DIR_MODE	(S_IRWXU | S_IRGRP|S_IXGRP | S_IROTH|S_IXOTH)

/* Determine whether a path is an absolute path. */
int got_path_is_absolute(const char *);

/*
 * Return an absolute version of a relative path.
 * The result is allocated with malloc(3).
 */
char *got_path_get_absolute(const char *);

/* 
 * Normalize a path for internal processing.
 * The result is allocated with malloc(3).
 */
char *got_path_normalize(const char *);

/*
 * Canonicalize absolute paths by removing redundant path separators
 * and resolving references to parent directories ("/../").
 * Relative paths are copied from input to buf as-is.
 */
const struct got_error *got_canonpath(const char *, char *, size_t);

/*
 * Get child part of two absolute paths. The second path must equal the first
 * path up to some path component, and must be longer than the first path.
 * The result is allocated with malloc(3).
 */
const struct got_error *got_path_skip_common_ancestor(char **, const char *,
    const char *);

/* Determine whether a path points to the root directory "/" . */
int got_path_is_root_dir(const char *);

/* Determine whether a path is a path-wise child of another path. */
int got_path_is_child(const char *, const char *, size_t);

/*
 * Like strcmp() but orders children in subdirectories directly after
 * their parents.
 */
int got_path_cmp(const char *, const char *);

/*
 * Path lists allow for predictable concurrent iteration over multiple lists
 * of paths obtained from disparate sources which don't all provide the same
 * ordering guarantees (e.g. git trees, file index, and on-disk directories).
 */
struct got_pathlist_entry {
	TAILQ_ENTRY(got_pathlist_entry) entry;
	const char *path;
	void *data; /* data pointer provided to got_pathlist_insert() */
};
TAILQ_HEAD(got_pathlist_head, got_pathlist_entry);

/*
 * Insert a path into the list of paths in a predictable order.
 * The caller should already have initialized the list head. This list stores
 * the pointer to the path as-is, i.e. the path is not copied internally and
 * must remain available until the list is freed with got_pathlist_free().
 * If the first argument is not NULL, set it to a pointer to the newly inserted
 * element, or to a NULL pointer in case the path was already on the list.
 */
const struct got_error *got_pathlist_insert(struct got_pathlist_entry **,
    struct got_pathlist_head *, const char *, void *);

/* Free resources allocated for a path list. */
void got_pathlist_free(struct got_pathlist_head *);

/* Attempt to create a directory at a given path. */
const struct got_error *got_path_mkdir(const char *);

/* dirname(3) with error handling and dynamically allocated result. */
const struct got_error *got_path_dirname(char **, const char *);
