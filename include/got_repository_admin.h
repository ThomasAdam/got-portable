/*
 * Copyright (c) 2021 Stefan Sperling <stsp@openbsd.org>
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

/* A callback function which gets invoked with progress information to print. */
typedef const struct got_error *(*got_pack_progress_cb)(void *arg,
    int ncolored, int nfound, int ntrees, off_t packfile_size, int ncommits,
    int nobj_total, int obj_deltify, int nobj_written);

/*
 * Attempt to pack objects reachable via 'include_refs' into a new packfile.
 * If 'excluded_refs' is not an empty list, do not pack any objects
 * reachable from the listed references.
 * If loose_obj_only is zero, pack reachable objects even if they are
 * already packed in another packfile. Otherwise, add only loose
 * objects to the new pack file.
 * Return an open file handle for the generated pack file.
 * Return the SHA1 digest of the resulting pack file in pack_hash which
 * must freed by the caller when done.
 */
const struct got_error *
got_repo_pack_objects(FILE **packfile, struct got_object_id **pack_hash,
    struct got_reflist_head *include_refs,
    struct got_reflist_head *exclude_refs, struct got_repository *repo,
    int loose_obj_only, int force_refdelta,
    got_pack_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg);

/*
 * Attempt to open a pack file at the specified path. Return an open
 * file handle and the expected hash of pack file contents.
 */
const struct got_error *
got_repo_find_pack(FILE **packfile, struct got_object_id **pack_hash,
    struct got_repository *repo, const char *packfile_path);

/* A callback function which gets invoked with progress information to print. */
typedef const struct got_error *(*got_pack_index_progress_cb)(void *arg,
    off_t packfile_size, int nobj_total, int nobj_indexed,
    int nobj_loose, int nobj_resolved);

/* (Re-)Index the pack file identified by the given hash. */
const struct got_error *
got_repo_index_pack(FILE *packfile, struct got_object_id *pack_hash,
    struct got_repository *repo,
    got_pack_index_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg);

typedef const struct got_error *(*got_pack_list_cb)(void *arg,
    struct got_object_id *id, int type, off_t offset, off_t size,
    off_t base_offset, struct got_object_id *base_id);

/* List the pack file identified by the given hash. */
const struct got_error *
got_repo_list_pack(FILE *packfile, struct got_object_id *pack_hash,
    struct got_repository *repo, got_pack_list_cb list_cb, void *list_arg,
    got_cancel_cb cancel_cb, void *cancel_arg);

/* A callback function which gets invoked with cleanup information to print. */
typedef const struct got_error *(*got_cleanup_progress_cb)(void *arg,
    int nloose, int ncommits, int npurged);

/*
 * Walk objects reachable via references to determine whether any loose
 * objects can be removed from disk. Do remove such objects from disk
 * unless the dry_run parameter is set.
 * Do not remove objects with a modification timestamp above an
 * implementation-defined timestamp threshold, unless ignore_mtime is set.
 * Return the disk space size occupied by loose objects before and after
 * the operation.
 * Return the number of loose objects which are also stored in a pack file.
 */
const struct got_error *
got_repo_purge_unreferenced_loose_objects(struct got_repository *repo,
    off_t *size_before, off_t *size_after, int *npacked, int dry_run,
    int ignore_mtime, got_cleanup_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg);

/* A callback function which gets invoked with cleanup information to print. */
typedef const struct got_error *(*got_lonely_packidx_progress_cb)(void *arg,
    const char *path);

/* Remove pack index files which do not have a corresponding pack file. */
const struct got_error *
got_repo_remove_lonely_packidx(struct got_repository *repo, int dry_run,
    got_lonely_packidx_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg);
