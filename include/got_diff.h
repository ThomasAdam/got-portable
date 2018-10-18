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
 * Compute the differences between two blobs and write unified diff text
 * to the provided output FILE. Two const char * diff header labels may
 * be provided which will be used to identify each blob in the diff output.
 * If a label is NULL, use the blob's SHA1 checksum instead.
 * The number of context lines to show in the diff must be specified as well.
 */
const struct got_error *got_diff_blob(struct got_blob_object *,
    struct got_blob_object *, const char *, const char *, int, FILE *);

/*
 * Compute the differences between two trees and write unified diff text
 * to the provided output FILE. Two const char * diff header labels may
 * be provided which will be used to identify each blob in the diff output.
 * If a label is NULL, use the blob's SHA1 checksum instead.
 * The number of context lines to show in the diff must be specified as well.
 */
const struct got_error *got_diff_tree(struct got_tree_object *,
    struct got_tree_object *, const char *label1, const char *label2,
    int, struct got_repository *, FILE *);

/*
 * Diff two objects, assuming both objects are blobs. Two const char * diff
 * header labels may be provided which will be used to identify each blob in
 * the diff output. If a label is NULL, use the blob's SHA1 checksum instead.
 * The number of context lines to show in the diff must be specified as well.
 * Write unified diff text to the provided output FILE.
 */
const struct got_error *got_diff_objects_as_blobs(struct got_object *,
    struct got_object *, const char *, const char *, int,
    struct got_repository *, FILE *);

/*
 * Diff two objects, assuming both objects are trees. Two const char * diff
 * header labels may be provided which will be used to identify each blob in
 * the trees. If a label is NULL, use the blob's SHA1 checksum instead.
 * The number of context lines to show in diffs must be specified.
 * Write unified diff text to the provided output FILE.
 */
const struct got_error *got_diff_objects_as_trees(struct got_object *,
    struct got_object *, char *, char *, int, struct got_repository *, FILE *);

/*
 * Diff two objects, assuming both objects are commits.
 * The number of context lines to show in diffs must be specified.
 * Write unified diff text to the provided output FILE.
 */
const struct got_error *got_diff_objects_as_commits(struct got_object *,
    struct got_object *, int, struct got_repository *, FILE *);

#define GOT_DIFF_MAX_CONTEXT	64
