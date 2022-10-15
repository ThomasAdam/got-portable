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

#define GOT_DEFAULT_FILE_MODE	(S_IFREG | \
	S_IRUSR|S_IWUSR | S_IRGRP | S_IROTH)
#define GOT_DEFAULT_DIR_MODE	(S_IFDIR | \
	S_IRWXU | S_IRGRP|S_IXGRP | S_IROTH|S_IXOTH)

struct dirent;

/* Determine whether a path is an absolute path. */
int got_path_is_absolute(const char *);

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

/*
 * Remove leading components from path.  It's an error to strip more
 * component than present.  The result is allocated dynamically.
 */
const struct got_error *got_path_strip(char **, const char *, int);

/* Determine whether a path points to the root directory "/" . */
int got_path_is_root_dir(const char *);

/* Determine whether a path is a path-wise child of another path. */
int got_path_is_child(const char *, const char *, size_t);

/*
 * Like strcmp() but orders children in subdirectories directly after
 * their parents. String lengths must also be passed in.
 */
int got_path_cmp(const char *, const char *, size_t, size_t);

/*
 * Path lists allow for predictable concurrent iteration over multiple lists
 * of paths obtained from disparate sources which don't all provide the same
 * ordering guarantees (e.g. git trees, file index, and on-disk directories).
 */
struct got_pathlist_entry {
	TAILQ_ENTRY(got_pathlist_entry) entry;
	const char *path;
	size_t path_len;
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

/*
 * Append a path to the list of paths.
 * The caller should already have initialized the list head. This list stores
 * the pointer to the path as-is, i.e. the path is not copied internally and
 * must remain available until the list is freed with got_pathlist_free().
 */
const struct got_error *got_pathlist_append(struct got_pathlist_head *,
    const char *, void *);

/* Free resources allocated for a path list. */
void got_pathlist_free(struct got_pathlist_head *);

/* Attempt to create a directory at a given path. */
const struct got_error *got_path_mkdir(const char *);

/* Determine whether a directory has no files or directories in it. */
int got_path_dir_is_empty(const char *);

/*
 * dirname(3) with error handling, dynamically allocated result, and
 * unmodified input.
 */
const struct got_error *got_path_dirname(char **, const char *);

/*
 * Obtain the file type of a given directory entry.
 *
 * If the entry has some type other than DT_UNKNOWN, resolve to this type.
 *
 * Otherwise, attempt to resolve the type of a DT_UNKNOWN directory
 * entry with lstat(2), though the result may still be DT_UNKNOWN.
 * This is a fallback to accommodate filesystems which do not provide
 * directory entry type information.
 * DT_UNKNOWN directory entries occur on NFS mounts without "readdir plus" RPC.
 */
const struct got_error *got_path_dirent_type(int *, const char *,
    struct dirent *);

/* basename(3) with dynamically allocated result and unmodified input. */
const struct got_error *got_path_basename(char **, const char *);

/* Strip trailing slashes from a path; path will be modified in-place. */
void got_path_strip_trailing_slashes(char *);

/* Look up the absolute path of a program in $PATH */
const struct got_error *got_path_find_prog(char **, const char *);

/* Create a new file at a specified path, with optional content. */
const struct got_error *got_path_create_file(const char *, const char *);

/*
 * Attempt to move an existing file to a new path, creating missing parent
 * directories at the destination path if necessary.
 * (Cross-mount-point moves are not yet implemented.)
 */
const struct got_error *got_path_move_file(const char *, const char *);
