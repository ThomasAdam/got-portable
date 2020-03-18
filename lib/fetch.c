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
got_fetch_connect(int *fetchfd, const char *proto, const char *host,
    const char *port, const char *server_path)
{
	const struct got_error *err = NULL;

	*fetchfd = -1;

	if (strcmp(proto, "ssh") == 0 || strcmp(proto, "git+ssh") == 0)
		err = dial_ssh(fetchfd, host, port, server_path, "upload");
	else if (strcmp(proto, "git") == 0)
		err = dial_git(fetchfd, host, port, server_path, "upload");
	else if (strcmp(proto, "http") == 0 || strcmp(proto, "git+http") == 0)
		err = got_error_path(proto, GOT_ERR_NOT_IMPL);
	else
		err = got_error_path(proto, GOT_ERR_BAD_PROTO);
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

static const struct got_error *
check_pack_hash(int fd, size_t sz, uint8_t *hcomp)
{
	SHA1_CTX ctx;
	uint8_t hexpect[SHA1_DIGEST_LENGTH];
	uint8_t buf[32 * 1024];
	ssize_t n, r, nr;

	if (sz < sizeof(struct got_packfile_hdr) + SHA1_DIGEST_LENGTH)
		return got_error_msg(GOT_ERR_BAD_PACKFILE, "short packfile");

	n = 0;
	SHA1Init(&ctx);
	while (n < sz - 20) {
		nr = sizeof(buf);
		if (sz - n - 20 < sizeof(buf))
			nr = sz - n - 20;
		r = read(fd, buf, nr);
		if (r == -1)
			return got_error_from_errno("read");
		if (r != nr)
			return got_error_msg(GOT_ERR_BAD_PACKFILE,
			    "short pack file");
		SHA1Update(&ctx, buf, nr);
		n += r;
	}
	SHA1Final(hcomp, &ctx);

	r = read(fd, hexpect, sizeof(hexpect));
	if (r == -1)
		return got_error_from_errno("read");
	if (r != sizeof(hexpect))
		return got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "short pack file");

	if (memcmp(hcomp, hexpect, SHA1_DIGEST_LENGTH) != 0)
		return got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "packfile checksum mismatch");

	return NULL;
}

const struct got_error*
got_fetch_pack(struct got_object_id **pack_hash, struct got_pathlist_head *refs,
    struct got_pathlist_head *symrefs, int fetchfd, struct got_repository *repo,
    got_fetch_progress_cb progress_cb, void *progress_arg)
{
	int imsg_fetchfds[2], imsg_idxfds[2];
	int packfd = -1, npackfd = -1, idxfd = -1, nidxfd = -1, nfetchfd = -1;
	int tmpfd = -1;
	int fetchstatus, idxstatus, done = 0;
	const struct got_error *err;
	struct imsgbuf fetchibuf, idxibuf;
	pid_t fetchpid, idxpid;
	char *tmppackpath = NULL, *tmpidxpath = NULL;
	char *packpath = NULL, *idxpath = NULL, *id_str = NULL;
	const char *repo_path = got_repo_get_path(repo);
	struct got_pathlist_head have_refs;
	struct got_pathlist_entry *pe;
	off_t packfile_size = 0;
	char *path;

	*pack_hash = NULL;

	TAILQ_INIT(&have_refs);

	if (asprintf(&path, "%s/%s/fetching.pack",
	    repo_path, GOT_OBJECTS_PACK_DIR) == -1) {
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
	if (asprintf(&path, "%s/%s/fetching.idx",
	    repo_path, GOT_OBJECTS_PACK_DIR) == -1) {
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

	tmpfd = got_opentempfd();
	if (tmpfd == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fetchfds) == -1) {
		err = got_error_from_errno("socketpair");
		goto done;
	}

	fetchpid = fork();
	if (fetchpid == -1) {
		err = got_error_from_errno("fork");
		goto done;
	} else if (fetchpid == 0){
		got_privsep_exec_child(imsg_fetchfds,
		    GOT_PATH_PROG_FETCH_PACK, tmppackpath);
	}

	if (close(imsg_fetchfds[1]) != 0) {
		err = got_error_from_errno("close");
		goto done;
	}
	imsg_init(&fetchibuf, imsg_fetchfds[0]);
	nfetchfd = dup(fetchfd);
	if (nfetchfd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}
	err = got_privsep_send_fetch_req(&fetchibuf, nfetchfd, &have_refs);
	if (err != NULL)
		goto done;
	nfetchfd = -1;
	err = got_privsep_send_fetch_outfd(&fetchibuf, npackfd);
	if (err != NULL)
		goto done;
	npackfd = dup(packfd);
	if (npackfd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}

	packfile_size = 0;
	while (!done) {
		struct got_object_id *id = NULL;
		char *refname = NULL;
		char *server_progress = NULL;
		off_t packfile_size_cur;

		err = got_privsep_recv_fetch_progress(&done,
		    &id, &refname, symrefs, &server_progress,
		    &packfile_size_cur, &fetchibuf);
		if (err != NULL)
			goto done;
		if (done)
			*pack_hash = id;
		else if (refname && id) {
			err = got_pathlist_append(refs, refname, id);
			if (err)
				goto done;
		} else if (server_progress) {
			char *s, *s0 = server_progress;
			while ((s = strsep(&s0, "\r")) != NULL) {
				if (*s == '\0')
					continue;
				err = progress_cb(progress_arg, s,
				    packfile_size_cur, 0, 0, 0, 0);
				if (err)
					break;
			}
			free(server_progress);
			if (err)
				goto done;
		} else if (packfile_size_cur != packfile_size) {
			err = progress_cb(progress_arg, NULL,
			    packfile_size_cur, 0, 0, 0, 0);
			if (err)
				break;
			packfile_size = packfile_size_cur;
		}
	}
	if (waitpid(fetchpid, &fetchstatus, 0) == -1) {
		err = got_error_from_errno("waitpid");
		goto done;
	}

	if (lseek(packfd, 0, SEEK_SET) == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}
	err = check_pack_hash(packfd, packfile_size, (*pack_hash)->sha1);
	if (err)
		goto done;
 
	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_idxfds) == -1) {
		err = got_error_from_errno("socketpair");
		goto done;
	}
	idxpid = fork();
	if (idxpid == -1) {
		err= got_error_from_errno("fork");
		goto done;
	} else if (idxpid == 0)
		got_privsep_exec_child(imsg_idxfds,
		    GOT_PATH_PROG_INDEX_PACK, tmppackpath);
	if (close(imsg_idxfds[1]) != 0) {
		err = got_error_from_errno("close");
		goto done;
	}
	imsg_init(&idxibuf, imsg_idxfds[0]);

	err = got_privsep_send_index_pack_req(&idxibuf, (*pack_hash)->sha1,
	    npackfd);
	if (err != NULL)
		goto done;
	npackfd = -1;
	err = got_privsep_send_index_pack_outfd(&idxibuf, nidxfd);
	if (err != NULL)
		goto done;
	nidxfd = -1;
	err = got_privsep_send_tmpfd(&idxibuf, tmpfd);
	if (err != NULL)
		goto done;
	tmpfd = -1;
	done = 0;
	while (!done) {
		int nobj_total, nobj_indexed, nobj_loose, nobj_resolved;

		err = got_privsep_recv_index_progress(&done, &nobj_total,
		    &nobj_indexed, &nobj_loose, &nobj_resolved,
		    &idxibuf);
		if (err != NULL)
			goto done;
		if (nobj_indexed != 0) {
			err = progress_cb(progress_arg, NULL,
			    packfile_size, nobj_total,
			    nobj_indexed, nobj_loose, nobj_resolved);
			if (err)
				break;
		}
		imsg_clear(&idxibuf);
	}
	if (close(imsg_idxfds[0]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	if (waitpid(idxpid, &idxstatus, 0) == -1) {
		err = got_error_from_errno("waitpid");
		goto done;
	}

	err = got_object_id_str(&id_str, *pack_hash);
	if (err)
		goto done;
	if (asprintf(&packpath, "%s/%s/pack-%s.pack",
	    repo_path, GOT_OBJECTS_PACK_DIR, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (asprintf(&idxpath, "%s/%s/pack-%s.idx",
	    repo_path, GOT_OBJECTS_PACK_DIR, id_str) == -1) {
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

done:
	if (nfetchfd != -1 && close(nfetchfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (npackfd != -1 && close(npackfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (idxfd != -1 && close(idxfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (tmpfd != -1 && close(tmpfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	free(tmppackpath);
	free(tmpidxpath);
	free(idxpath);
	free(packpath);

	if (err) {
		free(*pack_hash);
		*pack_hash = NULL;
		TAILQ_FOREACH(pe, refs, entry) {
			free((void *)pe->path);
			free(pe->data);
		}
		got_pathlist_free(refs);
		TAILQ_FOREACH(pe, symrefs, entry) {
			free((void *)pe->path);
			free(pe->data);
		}
		got_pathlist_free(symrefs);
	}
	return err;
}
