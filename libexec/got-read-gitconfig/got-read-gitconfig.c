/*
 * Copyright (c) 2019 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/time.h>
#include <sys/syslimits.h>

#include <stdint.h>
#include <imsg.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <zlib.h>

#include "got_error.h"
#include "got_object.h"

#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_privsep.h"
#include "got_lib_gitconfig.h"

static volatile sig_atomic_t sigint_received;

static void
catch_sigint(int signo)
{
	sigint_received = 1;
}

static const struct got_error *
gitconfig_num_request(struct imsgbuf *ibuf, struct got_gitconfig *gitconfig,
    char *section, char *tag, int def)
{
	int value;

	if (gitconfig == NULL)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	value = got_gitconfig_get_num(gitconfig, section, tag, def);
	return got_privsep_send_gitconfig_int(ibuf, value);
}

static const struct got_error *
gitconfig_str_request(struct imsgbuf *ibuf, struct got_gitconfig *gitconfig,
    char *section, char *tag)
{
	char *value;

	if (gitconfig == NULL)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	value = got_gitconfig_get_str(gitconfig, section, tag);
	return got_privsep_send_gitconfig_str(ibuf, value);
}

int
main(int argc, char *argv[])
{
	const struct got_error *err = NULL;
	struct imsgbuf ibuf;
	size_t datalen;
	struct got_gitconfig *gitconfig = NULL;
#if 0
	static int attached;

	while (!attached)
		sleep(1);
#endif
	signal(SIGINT, catch_sigint);

	imsg_init(&ibuf, GOT_IMSG_FD_CHILD);

#ifndef PROFILE
	/* revoke access to most system calls */
	if (pledge("stdio recvfd", NULL) == -1) {
		err = got_error_from_errno("pledge");
		got_privsep_send_error(&ibuf, err);
		return 1;
	}
#endif

	for (;;) {
		struct imsg imsg;

		memset(&imsg, 0, sizeof(imsg));
		imsg.fd = -1;

		if (sigint_received) {
			err = got_error(GOT_ERR_CANCELLED);
			break;
		}

		err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
		if (err) {
			if (err->code == GOT_ERR_PRIVSEP_PIPE)
				err = NULL;
			break;
		}

		if (imsg.hdr.type == GOT_IMSG_STOP)
			break;

		switch (imsg.hdr.type) {
		case GOT_IMSG_GITCONFIG_PARSE_REQUEST:
			datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
			if (datalen != 0) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			if (imsg.fd == -1){
				err = got_error(GOT_ERR_PRIVSEP_NO_FD);
				break;
			}

			if (gitconfig)
				got_gitconfig_close(gitconfig);
			err = got_gitconfig_open(&gitconfig, imsg.fd);
			break;
		case GOT_IMSG_GITCONFIG_REPOSITORY_FORMAT_VERSION_REQUEST:
			err = gitconfig_num_request(&ibuf, gitconfig, "core",
			    "repositoryformatversion", 0);
			break;
		case GOT_IMSG_GITCONFIG_AUTHOR_NAME_REQUEST:
			err = gitconfig_str_request(&ibuf, gitconfig, "user",
			    "name");
			break;
		case GOT_IMSG_GITCONFIG_AUTHOR_EMAIL_REQUEST:
			err = gitconfig_str_request(&ibuf, gitconfig, "user",
			    "email");
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		if (imsg.fd != -1) {
			if (close(imsg.fd) == -1 && err == NULL)
				err = got_error_from_errno("close");
		}

		imsg_free(&imsg);
		if (err)
			break;
	}

	imsg_clear(&ibuf);
	if (err) {
		if (!sigint_received && err->code != GOT_ERR_PRIVSEP_PIPE) {
			fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
			got_privsep_send_error(&ibuf, err);
		}
	}
	if (close(GOT_IMSG_FD_CHILD) != 0 && err == NULL)
		err = got_error_from_errno("close");
	return err ? 1 : 0;
}
