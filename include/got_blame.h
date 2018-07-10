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
 * Write an annotated version of a file at a given in-repository path,
 * as found in the commit specified by ID, to the specified output file.
 */
const struct got_error *got_blame(const char *, struct got_object_id *,
    struct got_repository *, FILE *);

/*
 * Like got_blame() but instead of generating an output file invoke
 * a callback whenever an annotation has been computed for a line.
 *
 * The callback receives the provided void * argument, the total number
 * of lines of the annotated file, a line number, and the ID of the commit
 * which last changed this line.
 *
 * The callback is invoked for each commit as history is traversed.
 * If no changes to the file were made in a commit, line number -1 will
 * be reported.
 *
 * If the callback returns GOT_ERR_ITER_COMPLETED, the blame operation
 * will be aborted and this function returns NULL.
 * If the callback returns any other error, the blame operation will be
 * aborted and the callback's error is returned from this function.
 */
const struct got_error *got_blame_incremental(const char *,
    struct got_object_id *, struct got_repository *,
    const struct got_error *(*cb)(void *, int, int, struct got_object_id *),
    void *);
