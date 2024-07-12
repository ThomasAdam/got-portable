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

struct got_pathlist_head;

const struct got_error *got_object_type_label(const char **, int);

struct got_commit_object *got_object_commit_alloc_partial(void);
struct got_tree_entry *got_alloc_tree_entry_partial(void);

const struct got_error *got_object_parse_commit(struct got_commit_object **,
    char *, size_t);
const struct got_error *got_object_read_commit(struct got_commit_object **, int,
    struct got_object_id *, size_t);

struct got_parsed_tree_entry {
	const char *name; /* Points to name in parsed buffer */
	size_t namelen; /* strlen(name) */
	mode_t mode; /* Mode parsed from tree buffer. */
	uint8_t *id; /* Points to ID in parsed tree buffer. */
};
const struct got_error *got_object_parse_tree_entry(
    struct got_parsed_tree_entry *, size_t *, char *, size_t, size_t);
const struct got_error *got_object_parse_tree(struct got_parsed_tree_entry **,
    size_t *, size_t *, uint8_t *, size_t);
const struct got_error *got_object_read_tree(struct got_parsed_tree_entry **,
    size_t *, size_t *, uint8_t **, int, struct got_object_id *);

const struct got_error *got_object_parse_tag(struct got_tag_object **,
    uint8_t *, size_t);
const struct got_error *got_object_read_tag(struct got_tag_object **, int,
    struct got_object_id *, size_t);

struct got_pack;
struct got_packidx;
struct got_inflate_checksum;

const struct got_error *got_object_parse_header(struct got_object **, char *,
    size_t);
const struct got_error *got_object_read_header(struct got_object **, int);
const struct got_error *got_object_read_raw(uint8_t **, off_t *,
    size_t *, size_t, int, struct got_object_id *, int);
