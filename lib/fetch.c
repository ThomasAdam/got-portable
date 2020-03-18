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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syslimits.h>
#include <sys/resource.h>
#include <sys/socket.h>

#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sha1.h>
#include <zlib.h>
#include <ctype.h>
#include <limits.h>
#include <imsg.h>
#include <time.h>
#include <uuid.h>
#include <netdb.h>
#include <netinet/in.h>

#include "got_error.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_path.h"
#include "got_cancel.h"
#include "got_worktree.h"
#include "got_object.h"
#include "got_opentemp.h"
#include "got_fetch.h"

#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_object_create.h"
#include "got_lib_pack.h"
#include "got_lib_sha1.h"
#include "got_lib_privsep.h"
#include "got_lib_object_cache.h"
#include "got_lib_repository.h"

#define GOT_PROTOMAX	64
#define GOT_HOSTMAX	256
#define GOT_PATHMAX	512
#define GOT_REPOMAX	256
#define GOT_PORTMAX	16
#define GOT_URIMAX	1024

static int
hassuffix(char *base, char *suf)
{
	int nb, ns;

	nb = strlen(base);
	ns = strlen(suf);
	if (ns <= nb && strcmp(base + (nb - ns), suf) == 0)
		return 1;
	return 0;
}

static const struct got_error *
dial_ssh(int *fetchfd, const char *host, const char *port, const char *path,
    const char *direction)
{
	const struct got_error *error = NULL;
	int pid, pfd[2];
	char cmd[64];

	*fetchfd = -1;

	if (pipe(pfd) == -1)
		return got_error_from_errno("pipe");

	pid = fork();
	if (pid == -1) {
		error = got_error_from_errno("fork");
		close(pfd[0]);
		close(pfd[1]);
		return error;
	} else if (pid == 0) {
		int n;
		close(pfd[1]);
		dup2(pfd[0], 0);
		dup2(pfd[0], 1);
		n = snprintf(cmd, sizeof(cmd), "git-%s-pack", direction);
		if (n < 0 || n >= sizeof(cmd))
			err(1, "snprintf");
		if (execlp("ssh", "ssh", host, cmd, path, NULL) == -1)
			err(1, "execlp");
		abort(); /* not reached */
	} else {
		close(pfd[0]);
		*fetchfd = pfd[1];
		return NULL;
	}
}

static const struct got_error *
dial_git(int *fetchfd, const char *host, const char *port, const char *path,
    const char *direction)
{
	const struct got_error *err = NULL;
	struct addrinfo hints, *servinfo, *p;
	char *cmd = NULL, *pkt = NULL;
	int fd = -1, totlen, r, eaicode;

	*fetchfd = -1;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	eaicode = getaddrinfo(host, port, &hints, &servinfo);
	if (eaicode)
		return got_error_msg(GOT_ERR_ADDRINFO, gai_strerror(eaicode));

	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((fd = socket(p->ai_family, p->ai_socktype,
		    p->ai_protocol)) == -1)
			continue;
		if (connect(fd, p->ai_addr, p->ai_addrlen) == 0)
			break;
		err = got_error_from_errno("connect");
		close(fd);
	}
	if (p == NULL)
		goto done;

	if (asprintf(&cmd, "git-%s-pack %s", direction, path) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	totlen = 4 + strlen(cmd) + 1 + strlen("host=") + strlen(host) + 1;
	if (asprintf(&pkt, "%04x%s", totlen, cmd) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	r = write(fd, pkt, strlen(pkt) + 1);
	if (r == -1) {
		err = got_error_from_errno("write");
		goto done;
	}
	if (asprintf(&pkt, "host=%s", host) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	r = write(fd, pkt, strlen(pkt) + 1);
	if (r == -1) {
		err = got_error_from_errno("write");
		goto done;
	}
done:
	free(cmd);
	free(pkt);
	if (err) {
		if (fd != -1)
			close(fd);
	} else
		*fetchfd = fd;
	return err;
}

const struct got_error *
got_fetch_parse_uri(char **proto, char **host, char **port,
    char **server_path, char **repo_name, const char *uri)
{
	const struct got_error *err = NULL;
	char *s, *p, *q;
	int n, hasport;

	*proto = *host = *port = *server_path = *repo_name = NULL;

	p = strstr(uri, "://");
	if (!p) {
		return got_error(GOT_ERR_PARSE_URI);
	}
	*proto = strndup(uri, p - uri);
	if (proto == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}

	hasport = (strcmp(*proto, "git") == 0 ||
	    strstr(*proto, "http") == *proto);
	s = p + 3;
	p = NULL;
	if (!hasport) {
		p = strstr(s, ":");
		if (p != NULL)
			p++;
	}
	if (p == NULL)
		p = strstr(s, "/");
	if (p == NULL || strlen(p) == 1) {
		err = got_error(GOT_ERR_PARSE_URI);
		goto done;
	}

	q = memchr(s, ':', p - s);
	if (q) {
		*host = strndup(s, q - s);
		if (*host == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		*port = strndup(q + 1, p - (q + 1));
		if (*port == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
	} else {
		*host = strndup(s, p - s);
		if (*host == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (asprintf(port, "%u", GOT_DEFAULT_GIT_PORT) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
	}

	*server_path = strdup(p);
	if (*server_path == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	p = strrchr(p, '/') + 1;
	if (!p || strlen(p) == 0) {
		//werrstr("missing repository in uri");
		err = got_error(GOT_ERR_PARSE_URI);
		goto done;
	}
	n = strlen(p);
	if (hassuffix(p, ".git"))
		n -= 4;
	*repo_name = strndup(p, (p + n) - p);
	if (*repo_name == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
done:
	if (err) {
		free(*proto);
		*proto = NULL;
		free(*host);
		*host = NULL;
		free(*port);
		*port = NULL;
		free(*server_path);
		*server_path = NULL;
		free(*repo_name);
		*repo_name = NULL;
	}
	return err;
}

const struct got_error*
got_fetch(const char *proto, const char *host, const char *port,
    const char *server_path, const char *repo_name,
    const char *branch_filter, const char *destdir)
{
	int imsg_fetchfds[2], imsg_idxfds[2], fetchfd = -1;
	int packfd = -1, npackfd = -1, idxfd = -1, nidxfd = -1;
	int status, done = 0;
	struct got_object_id *packhash = NULL;
	const struct got_error *err;
	struct imsgbuf ibuf;
	pid_t pid;
	char *tmppackpath = NULL, *tmpidxpath = NULL, *default_destdir = NULL;
	char *packpath = NULL, *idxpath = NULL, *id_str = NULL;
	const char *repo_path;
	struct got_pathlist_head symrefs;
	struct got_pathlist_entry *pe;
	struct got_repository *repo = NULL;
	char *path;

	TAILQ_INIT(&symrefs);

	fetchfd = -1;
	if (destdir == NULL) {
		if (asprintf(&default_destdir, "%s.git", repo_name) == -1)
			return got_error_from_errno("asprintf");
		repo_path = default_destdir;
	} else
		repo_path = destdir;
	err = got_repo_init(repo_path);
	if (err != NULL)
		goto done;
	if (asprintf(&path, "%s/objects/path", repo_path) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	err = got_path_mkdir(path);
	free(path);
	if (err)
		goto done;
	if (asprintf(&path, "%s/objects/path/fetching.pack", repo_path) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	err = got_opentemp_named_fd(&tmppackpath, &packfd, path);
	free(path);
	if (err)
		goto done;
	npackfd = dup(packfd);
	if (npackfd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}
	if (asprintf(&path, "%s/objects/path/fetching.idx", repo_path) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	err = got_opentemp_named_fd(&tmpidxpath, &idxfd, path);
	free(path);
	if (err)
		goto done;
	nidxfd = dup(idxfd);
	if (nidxfd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}

	if (strcmp(proto, "ssh") == 0 || strcmp(proto, "git+ssh") == 0)
		err = dial_ssh(&fetchfd, host, port, server_path, "upload");
	else if (strcmp(proto, "git") == 0)
		err = dial_git(&fetchfd, host, port, server_path, "upload");
	else if (strcmp(proto, "http") == 0 || strcmp(proto, "git+http") == 0)
		err = got_error(GOT_ERR_BAD_PROTO);
	else
		err = got_error(GOT_ERR_BAD_PROTO);
	if (err)
		goto done;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fetchfds) == -1) {
		err = got_error_from_errno("socketpair");
		goto done;
	}

	pid = fork();
	if (pid == -1) {
		err = got_error_from_errno("fork");
		goto done;
	} else if (pid == 0){
		got_privsep_exec_child(imsg_fetchfds,
		    GOT_PATH_PROG_FETCH_PACK, ".");
	}

	if (close(imsg_fetchfds[1]) != 0) {
		err = got_error_from_errno("close");
		goto done;
	}
	imsg_init(&ibuf, imsg_fetchfds[0]);
	err = got_privsep_send_fetch_req(&ibuf, fetchfd);
	if (err != NULL)
		goto done;
	fetchfd = -1;
	err = got_privsep_send_tmpfd(&ibuf, npackfd);
	if (err != NULL)
		goto done;
	npackfd = dup(packfd);
	if (npackfd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}

	err = got_repo_open(&repo, repo_path, NULL);
	if (err)
		goto done;

	while (!done) {
		struct got_object_id *id;
		char *refname;

		err = got_privsep_recv_fetch_progress(&done,
		    &id, &refname, &symrefs, &ibuf);
		if (err != NULL)
			goto done;
		if (done) {
			packhash = got_object_id_dup(id);
			if (packhash == NULL) {
				err = got_error_from_errno(
				    "got_object_id_dup");
				goto done;
			}
			printf("symrefs:");
			TAILQ_FOREACH(pe, &symrefs, entry) {
				printf(" %s:%s", pe->path,
				    (const char *)pe->data);
			}
			printf("\n");
		} else if (refname && id) {
			struct got_reference *ref;
			char *id_str;
			/* TODO Use a progress callback */
			err = got_object_id_str(&id_str, id);
			if (err)
				goto done;
			printf( "%.12s %s\n", id_str, refname);

			err = got_ref_alloc(&ref, refname, id);
			if (err)
				goto done;

			err = got_ref_write(ref, repo);
			got_ref_close(ref);
			if (err)
				goto done;
		}
	}
	if (waitpid(pid, &status, 0) == -1) {
		err = got_error_from_errno("waitpid");
		goto done;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_idxfds) == -1) {
		err = got_error_from_errno("socketpair");
		goto done;
	}
	pid = fork();
	if (pid == -1) {
		err= got_error_from_errno("fork");
		goto done;
	} else if (pid == 0)
		got_privsep_exec_child(imsg_idxfds,
		    GOT_PATH_PROG_INDEX_PACK, ".");
	if (close(imsg_idxfds[1]) != 0) {
		err = got_error_from_errno("close");
		goto done;
	}
	imsg_init(&ibuf, imsg_idxfds[0]);

	err = got_privsep_send_index_pack_req(&ibuf, npackfd, packhash);
	if (err != NULL)
		goto done;
	npackfd = -1;
	err = got_privsep_send_tmpfd(&ibuf, nidxfd);
	if (err != NULL)
		goto done;
	nidxfd = -1;
	err = got_privsep_wait_index_pack_done(&ibuf);
	if (err != NULL)
		goto done;
	imsg_clear(&ibuf);
	if (close(imsg_idxfds[0]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	if (waitpid(pid, &status, 0) == -1) {
		err = got_error_from_errno("waitpid");
		goto done;
	}

	err = got_object_id_str(&id_str, packhash);
	if (err)
		goto done;
	if (asprintf(&packpath, "%s/objects/pack/pack-%s.pack",
	    repo_path, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (asprintf(&idxpath, "%s/objects/pack/pack-%s.idx",
	    repo_path, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (rename(tmppackpath, packpath) == -1) {
		err = got_error_from_errno3("rename", tmppackpath, packpath);
		goto done;
	}
	if (rename(tmpidxpath, idxpath) == -1) {
		err = got_error_from_errno3("rename", tmpidxpath, idxpath);
		goto done;
	}

	/* Set the HEAD reference if the server provided one. */
	TAILQ_FOREACH(pe, &symrefs, entry) {
		struct got_reference *symref, *target_ref;
		const char *refname = pe->path;
		const char *target = pe->data;

		if (strcmp(refname, GOT_REF_HEAD) != 0)
			continue;

		err = got_ref_open(&target_ref, repo, target, 0);
		if (err) {
			if (err->code == GOT_ERR_NOT_REF)
				continue;
			goto done;
		}

		err = got_ref_alloc_symref(&symref, GOT_REF_HEAD, target_ref);
		got_ref_close(target_ref);
		if (err)
			goto done;

		err = got_ref_write(symref, repo);
		got_ref_close(symref);
		if (err)
			goto done;
		break;
	}

done:
	if (fetchfd != -1 && close(fetchfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (npackfd != -1 && close(npackfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (idxfd != -1 && close(idxfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (repo)
		got_repo_close(repo);
	free(tmppackpath);
	free(tmpidxpath);
	free(idxpath);
	free(packpath);
	free(default_destdir);
	free(packhash);
	TAILQ_FOREACH(pe, &symrefs, entry) {
		free((void *)pe->path);
		free(pe->data);
	}
	got_pathlist_free(&symrefs);

	return err;
}
