/*
 * Copyright (c) 2018, 2019 Ori Bernstein <ori@openbsd.org>
 * Copyright (c) 2021 Stefan Sperling <stsp@openbsd.org>
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

#define GOT_SEND_DEFAULT_REMOTE_NAME	"origin"

/*
 * Attempt to open a connection to a server using the provided protocol
 * scheme, hostname port number (as a string) and server-side path.
 * A verbosity level can be specified; it currently controls the amount
 * of -v options passed to ssh(1). If the level is -1 ssh(1) will be run
 * with the -q option.
 *
 * If successful return an open file descriptor for the connection which can
 * be passed to other functions below, and must be disposed of with close(2).
 * A jumphost can be specified which will be passed to ssh(1) via -J.
 * An identity file can be specified which will be passed to ssh(1) via -i.
 *
 * If an ssh(1) process was started return its PID as well, in which case
 * the caller should eventually send SIGTERM to the procress and wait for
 * the process to exit with waitpid(2). Otherwise, return PID -1.
 */
const struct got_error *got_send_connect(pid_t *, int *, const char *,
    const char *, const char *, const char *, const char *, const char *, int);

/* A callback function which gets invoked with progress information to print. */
typedef const struct got_error *(*got_send_progress_cb)(void *,
    int ncolored, int nfound, int ntrees, off_t packfile_size, int ncommits,
    int nobj_total, int nobj_deltify, int nobj_written, off_t bytes_sent,
    const char *refname, const char *, int success);

/*
 * Attempt to generate a pack file and sent it to a server.
 * This pack file will contain objects which are reachable in the local
 * repository via the specified branches and tags. Any objects which are
 * already present in the remote repository will be omitted from the
 * pack file.
 *
 * If the server supports deletion of references, attempt to delete
 * branches on the specified delete_branches list from the server.
 * Such branches are not required to exist in the local repository.
 * Requesting deletion of branches results in an error if the server
 * does not support this feature.
 */
const struct got_error *got_send_pack(const char *remote_name,
    struct got_pathlist_head *branch_names,
    struct got_pathlist_head *tag_names,
    struct got_pathlist_head *delete_branches, int verbosity,
    int overwrite_refs, int sendfd, struct got_repository *repo,
    got_send_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg);
