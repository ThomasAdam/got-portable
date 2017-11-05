/*
 * Copyright (c) 2017 Stefan Sperling <stsp@openbsd.org>
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

/* A symbolic reference. */
struct got_symref {
	char *name;
	char *ref;
};

/* A non-symbolic reference (there is no better designation). */
struct got_ref {
	char *name;
	u_int8_t sha1[SHA1_DIGEST_LENGTH];
};

/* A reference which points to an arbitrary object. */
struct got_reference {
	unsigned int flags;
#define GOT_REF_IS_SYMBOLIC	0x01

	union {
		struct got_ref ref;
		struct got_symref symref;
	} ref;
};

/* Well-known reference names. */
#define GOT_REF_HEAD		"HEAD"
#define GOT_REF_ORIG_HEAD	"ORIG_HEAD"
#define GOT_REF_MERGE_HEAD	"MERGE_HEAD"

const struct got_error *
got_ref_open(struct got_reference **, const char *, const char *);

void got_ref_close(struct got_reference *);

