/*
 * Copyright (c) 2019 Ori Bernstein <ori@openbsd.org>
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

#define GOT_DIAL_CMD_SEND	"git-receive-pack"
#define GOT_DIAL_CMD_FETCH	"git-upload-pack"

const struct got_error *got_dial_git(int *newfd, const char *host,
    const char *port, const char *path, const char *command);

const struct got_error *got_dial_ssh(pid_t *newpid, int *newfd,
    const char *host, const char *port, const char *path,
    const char *command, int verbosity);

const struct got_error *got_dial_http(pid_t *newpid, int *newfd,
    const char *host, const char *port, const char *path, int, int);

const struct got_error *got_dial_parse_command(char **command,
    char **repo_path, const char *gitcmd);
