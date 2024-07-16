/*
 * Copyright (c) 2019 Stefan Sperling <stsp@openbsd.org>
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

const struct got_error *got_object_blob_file_create(struct got_object_id **,
    FILE **, off_t *, const char *, struct got_repository *);
const struct got_error *got_object_blob_create(struct got_object_id **,
    const char *, struct got_repository *);

const struct got_error *got_object_tree_create(struct got_object_id **,
    struct got_pathlist_head *, int, struct got_repository *);

const struct got_error *got_object_commit_create(struct got_object_id **,
    struct got_object_id *, struct got_object_id_queue *, int,
    const char *, time_t, const char *, time_t, const char *,
    struct got_repository *);
