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

struct got_repository;

/* Open and close repositories. */
const struct got_error *got_repo_open(struct got_repository**, const char *);
void got_repo_close(struct got_repository*);

/*
 * Obtain paths to various directories within a repository.
 * The caller must dispose of a path with free(3).
 */
char *got_repo_get_path(struct got_repository *);
char *got_repo_get_path_git_dir(struct got_repository *);
char *got_repo_get_path_objects(struct got_repository *);
char *got_repo_get_path_objects_pack(struct got_repository *);
char *got_repo_get_path_refs(struct got_repository *);

struct got_reference;

/*
 * Obtain a reference, by name, from a repository.
 * The caller must dispose of it with got_ref_close().
 */
const struct got_error *got_repo_get_reference(struct got_reference **,
    struct got_repository *, const char *);


/* Indicate whether this is a bare repositiry (contains no git working tree). */
int got_repo_is_bare(struct got_repository *);

/* Attempt to map an arbitrary path to a path within the repository. */
const struct got_error *got_repo_map_path(char **, struct got_repository *,
    const char *);
