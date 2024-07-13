/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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

#include "got_compat.h"

#include <sys/queue.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_path.h"

#include "got_lib_gitconfig.h"
#include "got_lib_delta.h"
#include "got_lib_hash.h"
#include "got_lib_object.h"
#include "got_lib_object_cache.h"
#include "got_lib_privsep.h"
#include "got_lib_pack.h"
#include "got_lib_repository.h"

static int
get_boolean_val(char *val)
{
    return (strcasecmp(val, "true") == 0 ||
	strcasecmp(val, "on") == 0 ||
	strcasecmp(val, "yes") == 0 ||
	strcmp(val, "1") == 0);
}

static int
skip_node(struct got_gitconfig *gitconfig,
    struct got_gitconfig_list_node *node)
{
	/*
	 * Skip config nodes which do not describe remotes, and remotes
	 * which do not have a fetch URL defined (as used by git-annex).
	 */
	return (strncasecmp("remote \"", node->field, 8) != 0 ||
	    got_gitconfig_get_str(gitconfig, node->field, "url") == NULL);
}

const struct got_error *
got_repo_read_gitconfig(int *gitconfig_repository_format_version,
    char **gitconfig_author_name, char **gitconfig_author_email,
    struct got_remote_repo **remotes, int *nremotes,
    char **gitconfig_owner, char ***extnames, char ***extvals,
    int *nextensions, const char *gitconfig_path)
{
	const struct got_error *err = NULL;
	struct got_gitconfig *gitconfig = NULL;
	struct got_gitconfig_list *tags;
	struct got_gitconfig_list_node *node;
	int fd, i;
	const char *author, *email, *owner;

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

	err = got_gitconfig_open(&gitconfig, fd);
	if (err)
		goto done;

	*gitconfig_repository_format_version = got_gitconfig_get_num(gitconfig,
	    "core", "repositoryformatversion", 0);

	tags = got_gitconfig_get_tag_list(gitconfig, "extensions");
	if (extnames && extvals && nextensions && tags) {
		size_t numext = 0;
		TAILQ_FOREACH(node, &tags->fields, link) {
			char *ext = node->field;
			char *val = got_gitconfig_get_str(gitconfig,
			    "extensions", ext);
			if (get_boolean_val(val))
				numext++;
		}
		*extnames = calloc(numext, sizeof(char *));
		if (*extnames == NULL) {
			err = got_error_from_errno("calloc");
			goto done;
		}
		*extvals = calloc(numext, sizeof(char *));
		if (*extvals == NULL) {
			err = got_error_from_errno("calloc");
			goto done;
		}
		TAILQ_FOREACH(node, &tags->fields, link) {
			char *ext = node->field;
			char *val = got_gitconfig_get_str(gitconfig,
			    "extensions", ext);
			if (get_boolean_val(val)) {
				char *extstr = NULL, *valstr = NULL;

				extstr = strdup(ext);
				if (extstr == NULL) {
					err = got_error_from_errno("strdup");
					goto done;
				}
				valstr = strdup(val);
				if (valstr == NULL) {
					err = got_error_from_errno("strdup");
					goto done;
				}
				(*extnames)[(*nextensions)] = extstr;
				(*extvals)[(*nextensions)] = valstr;
				(*nextensions)++;
			}
		}
	}

	author = got_gitconfig_get_str(gitconfig, "user", "name");
	if (author) {
		*gitconfig_author_name = strdup(author);
		if (*gitconfig_author_name == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}

	email = got_gitconfig_get_str(gitconfig, "user", "email");
	if (email) {
		*gitconfig_author_email = strdup(email);
		if (*gitconfig_author_email == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}

	if (gitconfig_owner) {
		owner = got_gitconfig_get_str(gitconfig, "gotweb", "owner");
		if (owner == NULL)
			owner = got_gitconfig_get_str(gitconfig, "gitweb",
			    "owner");
		if (owner) {
			*gitconfig_owner = strdup(owner);
			if (*gitconfig_owner == NULL) {
				err = got_error_from_errno("strdup");
				goto done;
			}

		}
	}

	if (remotes && nremotes) {
		struct got_gitconfig_list *sections;
		size_t nalloc = 0;
		err = got_gitconfig_get_section_list(&sections, gitconfig);
		if (err)
			return err;
		TAILQ_FOREACH(node, &sections->fields, link) {
			if (skip_node(gitconfig, node))
				continue;
			nalloc++;
		}

		*remotes = recallocarray(NULL, 0, nalloc, sizeof(**remotes));
		if (*remotes == NULL) {
			err = got_error_from_errno("recallocarray");
			goto done;
		}

		i = 0;
		TAILQ_FOREACH(node, &sections->fields, link) {
			struct got_remote_repo *remote;
			char *name, *end, *mirror;
			const char *fetch_url, *send_url;

			if (skip_node(gitconfig, node) != 0)
				continue;

			remote = &(*remotes)[i];

			name = strdup(node->field + 8);
			if (name == NULL) {
				err = got_error_from_errno("strdup");
				goto done;
			}
			end = strrchr(name, '"');
			if (end)
				*end = '\0';
			remote->name = name;

			fetch_url = got_gitconfig_get_str(gitconfig,
			    node->field, "url");
			remote->fetch_url = strdup(fetch_url);
			if (remote->fetch_url == NULL) {
				err = got_error_from_errno("strdup");
				free(remote->name);
				remote->name = NULL;
				goto done;
			}

			send_url = got_gitconfig_get_str(gitconfig,
			    node->field, "pushurl");
			if (send_url == NULL)
				send_url = got_gitconfig_get_str(gitconfig,
				    node->field, "url");
			remote->send_url = strdup(send_url);
			if (remote->send_url == NULL) {
				err = got_error_from_errno("strdup");
				free(remote->name);
				remote->name = NULL;
				free(remote->fetch_url);
				remote->fetch_url = NULL;
				goto done;
			}

			remote->mirror_references = 0;
			mirror = got_gitconfig_get_str(gitconfig, node->field,
			    "mirror");
			if (mirror != NULL && get_boolean_val(mirror))
				remote->mirror_references = 1;

			i++;
			(*nremotes)++;
		}
	}
done:
	if (fd != -1)
		close(fd);
	if (gitconfig)
		got_gitconfig_close(gitconfig);
	if (err) {
		if (extnames && extvals && nextensions) {
			for (i = 0; i < (*nextensions); i++) {
				free((*extnames)[i]);
				free((*extvals)[i]);
			}
			free(*extnames);
			*extnames = NULL;
			free(*extvals);
			*extvals = NULL;
			*nextensions = 0;
		}
		if (remotes && nremotes) {
			for (i = 0; i < (*nremotes); i++) {
				struct got_remote_repo *remote;
				remote = &(*remotes)[i];
				free(remote->name);
				free(remote->fetch_url);
				free(remote->send_url);
			}
			free(*remotes);
			*remotes = NULL;
			*nremotes = 0;
		}
	}
	return err;
}
