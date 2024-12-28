/*
 * Copyright (c) 2019, 2022 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <imsg.h>
#include <unistd.h>

#include "got_compat.h"
#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_path.h"

#include "got_lib_delta.h"
#include "got_lib_hash.h"
#include "got_lib_object.h"
#include "got_lib_object_cache.h"
#include "got_lib_privsep.h"
#include "got_lib_pack.h"
#include "got_lib_repository.h"

const struct got_error *
got_repo_read_gitconfig(int *gitconfig_repository_format_version,
    char **gitconfig_author_name, char **gitconfig_author_email,
    struct got_remote_repo **remotes, int *nremotes,
    char **gitconfig_owner, char ***extnames, char ***extvals,
    int *nextensions, const char *gitconfig_path)
{
	const struct got_error *err = NULL, *child_err = NULL;
	int fd = -1;
	int imsg_fds[2] = { -1, -1 };
	pid_t pid;
	struct imsgbuf *ibuf;

	*gitconfig_repository_format_version = 0;
	if (extnames)
		*extnames = NULL;
	if (extvals)
		*extvals = NULL;
	if (nextensions)
		*nextensions = 0;
	*gitconfig_author_name = NULL;
	*gitconfig_author_email = NULL;
	if (remotes)
		*remotes = NULL;
	if (nremotes)
		*nremotes = 0;
	if (gitconfig_owner)
		*gitconfig_owner = NULL;

	fd = open(gitconfig_path, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		if (errno == ENOENT)
			return NULL;
		return got_error_from_errno2("open", gitconfig_path);
	}

	ibuf = calloc(1, sizeof(*ibuf));
	if (ibuf == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds) == -1) {
		err = got_error_from_errno("socketpair");
		goto done;
	}

	pid = fork();
	if (pid == -1) {
		err = got_error_from_errno("fork");
		goto done;
	} else if (pid == 0) {
		got_privsep_exec_child(imsg_fds, GOT_PATH_PROG_READ_GITCONFIG,
		    gitconfig_path);
		/* not reached */
	}

	if (close(imsg_fds[1]) == -1) {
		err = got_error_from_errno("close");
		goto wait;
	}
	imsg_fds[1] = -1;
	if (imsgbuf_init(ibuf, imsg_fds[0]) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto wait;
	}
	imsgbuf_allow_fdpass(ibuf);

	err = got_privsep_send_gitconfig_parse_req(ibuf, fd);
	if (err)
		goto wait;
	fd = -1;

	err = got_privsep_send_gitconfig_repository_format_version_req(ibuf);
	if (err)
		goto wait;

	err = got_privsep_recv_gitconfig_int(
	    gitconfig_repository_format_version, ibuf);
	if (err)
		goto wait;

	if (extnames && extvals && nextensions) {
		err = got_privsep_send_gitconfig_repository_extensions_req(
		    ibuf);
		if (err)
			goto wait;
		err = got_privsep_recv_gitconfig_int(nextensions, ibuf);
		if (err)
			goto wait;
		if (*nextensions > 0) {
			int i;
			*extnames = calloc(*nextensions, sizeof(char *));
			if (*extnames == NULL) {
				err = got_error_from_errno("calloc");
				goto wait;
			}
			*extvals = calloc(*nextensions, sizeof(char *));
			if (*extvals == NULL) {
				err = got_error_from_errno("calloc");
				goto wait;
			}
			for (i = 0; i < *nextensions; i++) {
				char *ext, *val;
				err = got_privsep_recv_gitconfig_pair(&ext,
				    &val, ibuf);
				if (err)
					goto wait;
				(*extnames)[i] = ext;
				(*extvals)[i] = val;
			}
		}
	}

	err = got_privsep_send_gitconfig_author_name_req(ibuf);
	if (err)
		goto wait;

	err = got_privsep_recv_gitconfig_str(gitconfig_author_name, ibuf);
	if (err)
		goto wait;

	err = got_privsep_send_gitconfig_author_email_req(ibuf);
	if (err)
		goto wait;

	err = got_privsep_recv_gitconfig_str(gitconfig_author_email, ibuf);
	if (err)
		goto wait;

	if (remotes && nremotes) {
		err = got_privsep_send_gitconfig_remotes_req(ibuf);
		if (err)
			goto wait;

		err = got_privsep_recv_gitconfig_remotes(remotes,
		    nremotes, ibuf);
		if (err)
			goto wait;
	}

	if (gitconfig_owner) {
		err = got_privsep_send_gitconfig_owner_req(ibuf);
		if (err)
			goto wait;
		err = got_privsep_recv_gitconfig_str(gitconfig_owner, ibuf);
		if (err)
			goto wait;
	}
wait:
	if (imsg_fds[0] != -1)
		got_privsep_send_stop(imsg_fds[0]);
	child_err = got_privsep_wait_for_child(pid);
	if (child_err && err == NULL)
		err = child_err;
done:
	if (imsg_fds[0] != -1 && close(imsg_fds[0]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (imsg_fds[1] != -1 && close(imsg_fds[1]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", gitconfig_path);
	imsgbuf_clear(ibuf);
	free(ibuf);
	return err;
}
