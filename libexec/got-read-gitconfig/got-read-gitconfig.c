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

#include <stdint.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "got_compat.h"

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"

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
send_gitconfig_int(struct imsgbuf *ibuf, int value)
{
	if (imsg_compose(ibuf, GOT_IMSG_GITCONFIG_INT_VAL, 0, 0, -1,
	    &value, sizeof(value)) == -1)
		return got_error_from_errno("imsg_compose GITCONFIG_INT_VAL");

	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
gitconfig_num_request(struct imsgbuf *ibuf, struct got_gitconfig *gitconfig,
    const char *section, const char *tag, int def)
{
	int value;

	if (gitconfig == NULL)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	value = got_gitconfig_get_num(gitconfig, section, tag, def);
	return send_gitconfig_int(ibuf, value);
}

static const struct got_error *
send_gitconfig_str(struct imsgbuf *ibuf, const char *value)
{
	size_t len = value ? strlen(value) : 0;

	if (imsg_compose(ibuf, GOT_IMSG_GITCONFIG_STR_VAL, 0, 0, -1,
	    value, len) == -1)
		return got_error_from_errno("imsg_compose GITCONFIG_STR_VAL");

	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
send_gitconfig_pair(struct imsgbuf *ibuf, const char *key, const char *val)
{
	struct ibuf *wbuf;
	size_t klen = key ? strlen(key) : 0;
	size_t vlen = val ? strlen(val) : 0;
	size_t tot = sizeof(klen) + sizeof(vlen) + klen + vlen;

	if (tot > MAX_IMSGSIZE - IMSG_HEADER_SIZE)
		return got_error(GOT_ERR_NO_SPACE);

	wbuf = imsg_create(ibuf, GOT_IMSG_GITCONFIG_PAIR, 0, 0, tot);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create GITCONFIG_PAIR");

	/* Keep in sync with got_imsg_gitconfig_pair */
	if (imsg_add(wbuf, &klen, sizeof(klen)) == -1)
		return got_error_from_errno("imsg_add GITCONFIG_PAIR");
	if (imsg_add(wbuf, &vlen, sizeof(vlen)) == -1)
		return got_error_from_errno("imsg_add GITCONFIG_PAIR");
	if (imsg_add(wbuf, key, klen) == -1)
		return got_error_from_errno("imsg_add GITCONFIG_PAIR");
	if (imsg_add(wbuf, val, vlen) == -1)
		return got_error_from_errno("imsg_add GITCONFIG_PAIR");

	wbuf->fd = -1;
	imsg_close(ibuf, wbuf);
	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
gitconfig_str_request(struct imsgbuf *ibuf, struct got_gitconfig *gitconfig,
    const char *section, const char *tag)
{
	char *value;

	if (gitconfig == NULL)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	value = got_gitconfig_get_str(gitconfig, section, tag);
	return send_gitconfig_str(ibuf, value);
}

static const struct got_error *
send_gitconfig_remotes(struct imsgbuf *ibuf, struct got_remote_repo *remotes,
    int nremotes)
{
	const struct got_error *err = NULL;
	struct got_imsg_remotes iremotes;
	int i;

	iremotes.nremotes = nremotes;
	if (imsg_compose(ibuf, GOT_IMSG_GITCONFIG_REMOTES, 0, 0, -1,
	    &iremotes, sizeof(iremotes)) == -1)
		return got_error_from_errno("imsg_compose GITCONFIG_REMOTES");

	err = got_privsep_flush_imsg(ibuf);
	imsg_clear(ibuf);
	if (err)
		return err;

	for (i = 0; i < nremotes; i++) {
		struct got_imsg_remote iremote;
		size_t len = sizeof(iremote);
		struct ibuf *wbuf;

		iremote.mirror_references = remotes[i].mirror_references;
		iremote.name_len = strlen(remotes[i].name);
		len += iremote.name_len;
		iremote.fetch_url_len = strlen(remotes[i].fetch_url);
		len += iremote.fetch_url_len;
		iremote.send_url_len = strlen(remotes[i].send_url);
		len += iremote.send_url_len;

		wbuf = imsg_create(ibuf, GOT_IMSG_GITCONFIG_REMOTE, 0, 0, len);
		if (wbuf == NULL)
			return got_error_from_errno(
			    "imsg_create GITCONFIG_REMOTE");

		if (imsg_add(wbuf, &iremote, sizeof(iremote)) == -1)
			return got_error_from_errno(
			    "imsg_add GITCONFIG_REMOTE");

		if (imsg_add(wbuf, remotes[i].name, iremote.name_len) == -1)
			return got_error_from_errno(
			    "imsg_add GITCONFIG_REMOTE");
		if (imsg_add(wbuf, remotes[i].fetch_url, iremote.fetch_url_len) == -1)
			return got_error_from_errno(
			    "imsg_add GITCONFIG_REMOTE");
		if (imsg_add(wbuf, remotes[i].send_url, iremote.send_url_len) == -1)
			return got_error_from_errno(
			    "imsg_add GITCONFIG_REMOTE");

		wbuf->fd = -1;
		imsg_close(ibuf, wbuf);
		err = got_privsep_flush_imsg(ibuf);
		if (err)
			return err;
	}

	return NULL;
}

static int
get_boolean_val(char *val)
{
    return (strcasecmp(val, "true") == 0 ||
	strcasecmp(val, "on") == 0 ||
	strcasecmp(val, "yes") == 0 ||
	strcmp(val, "1") == 0);
}

static int
skip_node(struct got_gitconfig *gitconfig, struct got_gitconfig_list_node *node)
{
	/*
	 * Skip config nodes which do not describe remotes, and remotes
	 * which do not have a fetch URL defined (as used by git-annex).
	 */
	return (strncasecmp("remote \"", node->field, 8) != 0 ||
	    got_gitconfig_get_str(gitconfig, node->field, "url") == NULL);
}

static const struct got_error *
gitconfig_remotes_request(struct imsgbuf *ibuf, struct got_gitconfig *gitconfig)
{
	const struct got_error *err = NULL;
	struct got_gitconfig_list *sections;
	struct got_gitconfig_list_node *node;
	struct got_remote_repo *remotes = NULL;
	int nremotes = 0, i;

	if (gitconfig == NULL)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	err = got_gitconfig_get_section_list(&sections, gitconfig);
	if (err)
		return err;

	TAILQ_FOREACH(node, &sections->fields, link) {
		if (skip_node(gitconfig, node))
			continue;
		nremotes++;
	}

	if (nremotes == 0) {
		err = send_gitconfig_remotes(ibuf, NULL, 0);
		goto done;
	}

	remotes = recallocarray(NULL, 0, nremotes, sizeof(*remotes));
	if (remotes == NULL) {
		err = got_error_from_errno("recallocarray");
		goto done;
	}

	i = 0;
	TAILQ_FOREACH(node, &sections->fields, link) {
		char *name, *end, *mirror;

		if (skip_node(gitconfig, node))
			continue;

		name = strdup(node->field + 8);
		if (name == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
		end = strrchr(name, '"');
		if (end)
			*end = '\0';
		remotes[i].name = name;

		remotes[i].fetch_url = got_gitconfig_get_str(gitconfig,
		    node->field, "url");

		remotes[i].send_url = got_gitconfig_get_str(gitconfig,
		    node->field, "pushurl");
		if (remotes[i].send_url == NULL)
			remotes[i].send_url = remotes[i].fetch_url;

		remotes[i].mirror_references = 0;
		mirror = got_gitconfig_get_str(gitconfig, node->field,
		    "mirror");
		if (mirror != NULL && get_boolean_val(mirror))
			remotes[i].mirror_references = 1;

		i++;
	}

	err = send_gitconfig_remotes(ibuf, remotes, nremotes);
done:
	for (i = 0; i < nremotes; i++)
		free(remotes[i].name);
	free(remotes);
	got_gitconfig_free_list(sections);
	return err;
}

static const struct got_error *
gitconfig_owner_request(struct imsgbuf *ibuf, struct got_gitconfig *gitconfig)
{
	char *value;

	if (gitconfig == NULL)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	value = got_gitconfig_get_str(gitconfig, "gotweb", "owner");
	if (value)
		return send_gitconfig_str(ibuf, value);
	value = got_gitconfig_get_str(gitconfig, "gitweb", "owner");
	return send_gitconfig_str(ibuf, value);
}

static const struct got_error *
gitconfig_extensions_request(struct imsgbuf *ibuf,
    struct got_gitconfig *gitconfig)
{
	const struct got_error *err = NULL;
	struct got_gitconfig_list *tags;
	struct got_gitconfig_list_node *node;
	int nextensions = 0;
	char *val;

	if (gitconfig == NULL)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	tags = got_gitconfig_get_tag_list(gitconfig, "extensions");
	if (tags == NULL)
		return send_gitconfig_int(ibuf, 0);

	TAILQ_FOREACH(node, &tags->fields, link)
		nextensions++;

	err = send_gitconfig_int(ibuf, nextensions);
	if (err)
		goto done;

	TAILQ_FOREACH(node, &tags->fields, link) {
		val = got_gitconfig_get_str(gitconfig, "extensions",
		    node->field);
		err = send_gitconfig_pair(ibuf, node->field, val);
		if (err)
			goto done;
	}
done:
	got_gitconfig_free_list(tags);
	return err;
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

	/* revoke fs access */
	if (landlock_no_fs() == -1) {
		err = got_error_from_errno("landlock_no_fs");
		got_privsep_send_error(&ibuf, err);
		return 1;
	}
	if (cap_enter() == -1) {
		err = got_error_from_errno("cap_enter");
		got_privsep_send_error(&ibuf, err);
		return 1;
	}
#endif

	for (;;) {
		struct imsg imsg;
		int fd = -1;

		memset(&imsg, 0, sizeof(imsg));

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
			fd = imsg_get_fd(&imsg);
			if (fd == -1) {
				err = got_error(GOT_ERR_PRIVSEP_NO_FD);
				break;
			}

			if (gitconfig)
				got_gitconfig_close(gitconfig);
			err = got_gitconfig_open(&gitconfig, fd);
			break;
		case GOT_IMSG_GITCONFIG_REPOSITORY_FORMAT_VERSION_REQUEST:
			err = gitconfig_num_request(&ibuf, gitconfig, "core",
			    "repositoryformatversion", 0);
			break;
		case GOT_IMSG_GITCONFIG_REPOSITORY_EXTENSIONS_REQUEST:
			err = gitconfig_extensions_request(&ibuf, gitconfig);
			break;
		case GOT_IMSG_GITCONFIG_AUTHOR_NAME_REQUEST:
			err = gitconfig_str_request(&ibuf, gitconfig, "user",
			    "name");
			break;
		case GOT_IMSG_GITCONFIG_AUTHOR_EMAIL_REQUEST:
			err = gitconfig_str_request(&ibuf, gitconfig, "user",
			    "email");
			break;
		case GOT_IMSG_GITCONFIG_REMOTES_REQUEST:
			err = gitconfig_remotes_request(&ibuf, gitconfig);
			break;
		case GOT_IMSG_GITCONFIG_OWNER_REQUEST:
			err = gitconfig_owner_request(&ibuf, gitconfig);
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		if (fd != -1) {
			if (close(fd) == -1 && err == NULL)
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
	if (close(GOT_IMSG_FD_CHILD) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err ? 1 : 0;
}
