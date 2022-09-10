/*
 * Copyright (c) 2018, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
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

struct got_commit_graph;

const struct got_error *got_commit_graph_open(struct got_commit_graph **,
    const char *, int);
void got_commit_graph_close(struct got_commit_graph *);

const struct got_error *got_commit_graph_iter_start(
    struct got_commit_graph *, struct got_object_id *, struct got_repository *,
    got_cancel_cb, void *);
const struct got_error *got_commit_graph_iter_next(struct got_object_id *,
    struct got_commit_graph *, struct got_repository *, got_cancel_cb, void *);
const struct got_error *got_commit_graph_intersect(struct got_object_id **,
    struct got_commit_graph *, struct got_commit_graph *,
    struct got_repository *);

/* Find the youngest common ancestor of two commits. */
const struct got_error *got_commit_graph_find_youngest_common_ancestor(
    struct got_object_id **, struct got_object_id *, struct got_object_id *,
    int, struct got_repository *, got_cancel_cb, void *);
