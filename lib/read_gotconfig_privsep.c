/*
 * Copyright (c) 2020 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <imsg.h>
#include <limits.h>

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"

#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_privsep.h"
#include "got_lib_gotconfig.h"

#include "got_gotconfig.h"

const struct got_error *
got_gotconfig_read(struct got_gotconfig **conf, const char *gotconfig_path)
{
	const struct got_error *err = NULL, *child_err = NULL;
	int fd = -1;
	int imsg_fds[2] = { -1, -1 };
	pid_t pid;
	struct imsgbuf *ibuf;

	*conf = calloc(1, sizeof(**conf));
	if (*conf == NULL)
		return got_error_from_errno("calloc");

	fd = open(gotconfig_path, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		if (errno == ENOENT)
			return NULL;
		return got_error_from_errno2("open", gotconfig_path);
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
		got_privsep_exec_child(imsg_fds, GOT_PATH_PROG_READ_GOTCONFIG,
		    gotconfig_path);
		/* not reached */
	}

	if (close(imsg_fds[1]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	imsg_fds[1] = -1;
	imsg_init(ibuf, imsg_fds[0]);

	err = got_privsep_send_gotconfig_parse_req(ibuf, fd);
	if (err)
		goto done;
	fd = -1;

	err = got_privsep_send_gotconfig_author_req(ibuf);
	if (err)
		goto done;

	err = got_privsep_recv_gotconfig_str(&(*conf)->author, ibuf);
	if (err)
		goto done;

	err = got_privsep_send_gotconfig_allowed_signers_req(ibuf);
	if (err)
		goto done;

	err = got_privsep_recv_gotconfig_str(&(*conf)->allowed_signers_file,
	    ibuf);
	if (err)
		goto done;

	err = got_privsep_send_gotconfig_revoked_signers_req(ibuf);
	if (err)
		goto done;

	err = got_privsep_recv_gotconfig_str(&(*conf)->revoked_signers_file,
	    ibuf);
	if (err)
		goto done;

	err = got_privsep_send_gotconfig_signer_id_req(ibuf);
	if (err)
		goto done;

	err = got_privsep_recv_gotconfig_str(&(*conf)->signer_id, ibuf);
	if (err)
		goto done;

	err = got_privsep_send_gotconfig_remotes_req(ibuf);
	if (err)
		goto done;

	err = got_privsep_recv_gotconfig_remotes(&(*conf)->remotes,
	    &(*conf)->nremotes, ibuf);
	if (err)
		goto done;

	err = got_privsep_send_stop(imsg_fds[0]);
	child_err = got_privsep_wait_for_child(pid);
	if (child_err && err == NULL)
		err = child_err;
done:
	if (imsg_fds[0] != -1 && close(imsg_fds[0]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (imsg_fds[1] != -1 && close(imsg_fds[1]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", gotconfig_path);
	if (err) {
		got_gotconfig_free(*conf);
		*conf = NULL;
	}
	free(ibuf);
	return err;
}
