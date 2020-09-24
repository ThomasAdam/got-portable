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
#include <sys/time.h>

#include <stdint.h>
#include <imsg.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <unistd.h>
#include <zlib.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"
#include "got_repository.h"

#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_privsep.h"

#include "gotconfig.h"

/* parse.y */
static volatile sig_atomic_t sigint_received;

static void
catch_sigint(int signo)
{
	sigint_received = 1;
}

static const struct got_error *
make_repo_url(char **url, struct gotconfig_remote_repo *repo)
{
	const struct got_error *err = NULL;
	char *s = NULL, *p = NULL;

	*url = NULL;

	if (asprintf(&s, "%s://", repo->protocol) == -1)
		return got_error_from_errno("asprintf");

	if (repo->server) {
		p = s;
		s = NULL;
		if (asprintf(&s, "%s%s", p, repo->server) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		free(p);
		p = NULL;
	}

	if (repo->port) {
		p = s;
		s = NULL;
		if (asprintf(&s, "%s:%d", p, repo->port) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		free(p);
		p = NULL;
	}

	if (repo->repository) {
		char *repo_path = repo->repository;
		while (repo_path[0] == '/')
			repo_path++;
		p = s;
		s = NULL;
		if (asprintf(&s, "%s/%s", p, repo_path) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		free(p);
		p = NULL;
	}

	got_path_strip_trailing_slashes(s);
done:
	if (err) {
		free(s);
		free(p);
	} else
		*url = s;
	return err;
}

static const struct got_error *
send_gotconfig_str(struct imsgbuf *ibuf, const char *value)
{
	size_t len = value ? strlen(value) : 0;

	if (imsg_compose(ibuf, GOT_IMSG_GOTCONFIG_STR_VAL, 0, 0, -1,
	    value, len) == -1)
		return got_error_from_errno("imsg_compose GOTCONFIG_STR_VAL");

	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
send_gotconfig_remotes(struct imsgbuf *ibuf,
    struct gotconfig_remote_repo_list *remotes, int nremotes)
{
	const struct got_error *err = NULL;
	struct got_imsg_remotes iremotes;
	struct gotconfig_remote_repo *repo;
	char *url = NULL;

	iremotes.nremotes = nremotes;
	if (imsg_compose(ibuf, GOT_IMSG_GOTCONFIG_REMOTES, 0, 0, -1,
	    &iremotes, sizeof(iremotes)) == -1)
		return got_error_from_errno("imsg_compose GOTCONFIG_REMOTES");

	err = got_privsep_flush_imsg(ibuf);
	imsg_clear(ibuf);
	if (err)
		return err;

	TAILQ_FOREACH(repo, remotes, entry) {
		struct got_imsg_remote iremote;
		size_t len = sizeof(iremote);
		struct ibuf *wbuf;

		iremote.mirror_references = repo->mirror_references;

		iremote.name_len = strlen(repo->name);
		len += iremote.name_len;

		err = make_repo_url(&url, repo);
		if (err)
			break;
		iremote.url_len = strlen(url);
		len += iremote.url_len;

		wbuf = imsg_create(ibuf, GOT_IMSG_GOTCONFIG_REMOTE, 0, 0, len);
		if (wbuf == NULL) {
			err = got_error_from_errno(
			    "imsg_create GOTCONFIG_REMOTE");
			break;
		}

		if (imsg_add(wbuf, &iremote, sizeof(iremote)) == -1) {
			err = got_error_from_errno(
			    "imsg_add GOTCONFIG_REMOTE");
			ibuf_free(wbuf);
			break;
		}

		if (imsg_add(wbuf, repo->name, iremote.name_len) == -1) {
			err = got_error_from_errno(
			    "imsg_add GOTCONFIG_REMOTE");
			ibuf_free(wbuf);
			break;
		}
		if (imsg_add(wbuf, url, iremote.url_len) == -1) {
			err = got_error_from_errno(
			    "imsg_add GOTCONFIG_REMOTE");
			ibuf_free(wbuf);
			break;
		}

		wbuf->fd = -1;
		imsg_close(ibuf, wbuf);
		err = got_privsep_flush_imsg(ibuf);
		if (err)
			break;

		free(url);
		url = NULL;
	}

	free(url);
	return err;
}

static const struct got_error *
validate_config(struct gotconfig *gotconfig)
{
	struct gotconfig_remote_repo *repo, *repo2;
	static char msg[512];

	TAILQ_FOREACH(repo, &gotconfig->remotes, entry) {
		if (repo->name == NULL) {
			return got_error_msg(GOT_ERR_PARSE_CONFIG,
			    "name required for remote repository");
		}

		TAILQ_FOREACH(repo2, &gotconfig->remotes, entry) {
			if (repo == repo2 ||
			    strcmp(repo->name, repo2->name) != 0)
				continue;
			snprintf(msg, sizeof(msg),
			    "duplicate remote repository name '%s'",
			    repo->name);
			return got_error_msg(GOT_ERR_PARSE_CONFIG, msg);
		}

		if (repo->server == NULL) {
			snprintf(msg, sizeof(msg),
			    "server required for remote repository \"%s\"",
			    repo->name);
			return got_error_msg(GOT_ERR_PARSE_CONFIG, msg);
		}

		if (repo->protocol == NULL) {
			snprintf(msg, sizeof(msg),
			    "protocol required for remote repository \"%s\"",
			    repo->name);
			return got_error_msg(GOT_ERR_PARSE_CONFIG, msg);
		}
		if (strcmp(repo->protocol, "ssh") != 0 &&
		    strcmp(repo->protocol, "git+ssh") != 0 &&
		    strcmp(repo->protocol, "git") != 0) {
			snprintf(msg, sizeof(msg),"unknown protocol \"%s\" "
			    "for remote repository \"%s\"", repo->protocol,
			    repo->name);
			return got_error_msg(GOT_ERR_PARSE_CONFIG, msg);
		}

		if (repo->repository == NULL) {
			snprintf(msg, sizeof(msg),
			    "repository path required for remote "
			    "repository \"%s\"", repo->name);
			return got_error_msg(GOT_ERR_PARSE_CONFIG, msg);
		}
	}

	return NULL;
}

int
main(int argc, char *argv[])
{
	const struct got_error *err = NULL;
	struct imsgbuf ibuf;
	struct gotconfig *gotconfig = NULL;
	size_t datalen;
	const char *filename = "got.conf";
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

	if (argc > 1)
		filename = argv[1];

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
		case GOT_IMSG_GOTCONFIG_PARSE_REQUEST:
			datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
			if (datalen != 0) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			if (imsg.fd == -1){
				err = got_error(GOT_ERR_PRIVSEP_NO_FD);
				break;
			}

			if (gotconfig)
				gotconfig_free(gotconfig);
			err = gotconfig_parse(&gotconfig, filename, &imsg.fd);
			if (err)
				break;
			err = validate_config(gotconfig);
			break;
		case GOT_IMSG_GOTCONFIG_AUTHOR_REQUEST:
			if (gotconfig == NULL) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = send_gotconfig_str(&ibuf,
			    gotconfig->author ?  gotconfig->author : "");
			break;
		case GOT_IMSG_GOTCONFIG_REMOTES_REQUEST:
			if (gotconfig == NULL) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = send_gotconfig_remotes(&ibuf,
			    &gotconfig->remotes, gotconfig->nremotes);
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
