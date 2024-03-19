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

/* Utilities for opening temporary files. */

#ifndef GOT_TMPDIR
#define GOT_TMPDIR /tmp
#endif
#define GOT_STRINGIFY_TMP(x) #x
#define GOT_STRINGVAL_TMP(x) GOT_STRINGIFY_TMP(x)
#define GOT_TMPDIR_STR GOT_STRINGVAL_TMP(GOT_TMPDIR)

/* Open a file descriptor to a new temporary file for writing.
 * The file is not visible in the filesystem. */
int got_opentempfd(void);

/* Open a new temporary file for writing.
 * The file is not visible in the filesystem. */
FILE *got_opentemp(void);

/* Open a new temporary file for writing.
 * The file is visible in the filesystem. */
const struct got_error *got_opentemp_named(char **, FILE **, const char *,
    const char *);

/* Like got_opentemp_named() but returns a file descriptor instead of a FILE. */
const struct got_error *got_opentemp_named_fd(char **, int *, const char *,
    const char *);

/* Truncate a file. This is useful for re-using open temporary files. */
const struct got_error *got_opentemp_truncate(FILE *);

/* Truncate a file via a file descriptor. */
const struct got_error *got_opentemp_truncatefd(int);
