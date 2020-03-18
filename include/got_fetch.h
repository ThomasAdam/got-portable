/*
 * Copyright (c) 2018, 2019 Ori Bernstein <ori@openbsd.org>
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

/* IANA assigned */
#define GOT_DEFAULT_GIT_PORT		9418
#define GOT_DEFAULT_GIT_PORT_STR	"9418"

/*
 * Attempt to parse a URI into the following parts:
 * A protocol scheme, hostname, port number (as a string), path on server,
 * and a repository name. If the URI lacks some of this information return
 * default values where applicable.
 * The results of this function must be passed to other functions below.
 * The caller should dispose of the returned values with free(3).
 */
const struct got_error *got_fetch_parse_uri(char **, char **, char **,
    char **, char **, const char *);

/*
 * Attempt to open a connection to a server using the provided protocol
 * scheme, hostname port number (as a string) and server-side path.
 * If successful return an open file descriptor for the connection which can
 * be passed to other functions below, and must be disposed of with close(2).
 */
const struct got_error *got_fetch_connect(int *, const char *, const char *,
    const char *, const char *);

/* A callback function which gets invoked with progress information to print. */
typedef const struct got_error *(*got_fetch_progress_cb)(void *,
    const char *, off_t, int, int);

/*
 * Attempt to fetch a packfile from a server. This pack file will contain
 * objects which that are not yet contained in the provided repository.
 * Return the hash of the packfile (in form of an object ID) and lists of
 * references and symbolic references learned from the server.
 */
const struct got_error *got_fetch_pack(struct got_object_id **,
	struct got_pathlist_head *, struct got_pathlist_head *, int,
	struct got_repository *, got_fetch_progress_cb, void *);
