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

/* A reference which points to an arbitrary object. */
struct got_reference;

/* Well-known reference names. */
#define GOT_REF_HEAD		"HEAD"
#define GOT_REF_ORIG_HEAD	"ORIG_HEAD"
#define GOT_REF_MERGE_HEAD	"MERGE_HEAD"
#define GOT_REF_FETCH_HEAD	"FETCH_HEAD"

struct got_repository;
struct got_object_id;

/*
 * Attempt to open the reference with the provided name in a repository.
 * The caller must dispose of it with got_ref_close().
 */
const struct got_error * got_ref_open(struct got_reference **,
    struct got_repository *, const char *);

/*
 * Allocate a new reference for a given object ID.
 * The caller must dispose of it with got_ref_close().
 */
const struct got_error *got_ref_alloc(struct got_reference **, const char *,
    struct got_object_id *);

/* Dispose of a reference. */
void got_ref_close(struct got_reference *);

/* Get the name of the reference. */
const char *got_ref_get_name(struct got_reference *);

/*
 * Create a duplicate copy of a reference.
 * The caller must dispose of this copy with got_ref_close().
 */
struct got_reference *got_ref_dup(struct got_reference *);

/* Attempt to resolve a reference to an object ID. */
const struct got_error *got_ref_resolve(struct got_object_id **,
    struct got_repository *, struct got_reference *);

/*
 * Return a string representation of a reference.
 * The caller must dispose of it with free(3).
 */
char *got_ref_to_str(struct got_reference *);

/* A list of references and the object ID which they resolve to. */
struct got_reflist_entry {
	SIMPLEQ_ENTRY(got_reflist_entry) entry;
	struct got_reference *ref;
	struct got_object_id *id;
};
SIMPLEQ_HEAD(got_reflist_head, got_reflist_entry);

/* Append all known references to a caller-provided ref list head. */
const struct got_error *got_ref_list(struct got_reflist_head *,
    struct got_repository *);

/* Write a reference to its on-disk path in the repository. */
const struct got_error *got_ref_write(struct got_reference *,
    struct got_repository *);
