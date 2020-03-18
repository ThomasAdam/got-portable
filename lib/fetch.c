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
mkpath(char *path)
{
	char *p, namebuf[PATH_MAX];
	struct stat sb;
	int done;

	while (*path == '/')
		path++;
	if (strlcpy(namebuf, path, sizeof(namebuf)) >= sizeof(namebuf)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	p = namebuf;
	for (;;) {
		p += strspn(p, "/");
		p += strcspn(p, "/");
		done = (*p == '\0');
		*p = '\0';

		if (mkdir(namebuf, 0755) != 0) {
			int mkdir_errno = errno;
			if (stat(path, &sb) == -1) {
				/* Not there; use mkdir()s errno */
				errno = mkdir_errno;
				return -1;
			}
			if (!S_ISDIR(sb.st_mode)) {
				/* Is there, but isn't a directory */
				errno = ENOTDIR;
				return -1;
			}
		}

		if (done)
			break;
		*p = '/';
	}

	return 0;
}

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

static int
grab(char *dst, int n, char *p, char *e)
{
	int l;

	l = e - p;
	if (l >= n) {
		errno = ENAMETOOLONG;
		return -1;
	}
	return strlcpy(dst, p, l + 1);
}

static const struct got_error *
dial_ssh(int *fetchfd, char *host, char *port, char *path, char *direction)
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
dial_git(int *fetchfd, char *host, char *port, char *path, char *direction)
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

int
got_parse_uri(char *uri, char *proto, char *host, char *port, char *path, char *repo)
{
	char *s, *p, *q;
	int n, hasport;

	p = strstr(uri, "://");
	if (!p) {
		//werrstr("missing protocol");
		return -1;
	}
	if (grab(proto, GOT_PROTOMAX, uri, p) == -1)
		return -1;
	hasport = (strcmp(proto, "git") == 0 || strstr(proto, "http") == proto);
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
		//werrstr("missing path");
		return -1;
	}

	q = memchr(s, ':', p - s);
	if (q) {
		grab(host, GOT_HOSTMAX, s, q);
		grab(port, GOT_PORTMAX, q + 1, p);
	}else{
		grab(host, GOT_HOSTMAX, s, p);
		snprintf(port, GOT_PORTMAX, "9418");
	}

	snprintf(path, GOT_PATHMAX, "%s", p);
	p = strrchr(p, '/') + 1;
	if (!p || strlen(p) == 0) {
		//werrstr("missing repository in uri");
		return -1;
	}
	n = strlen(p);
	if (hassuffix(p, ".git"))
		n -= 4;
	grab(repo, GOT_REPOMAX, p, p + n);
	return 0;
}

const struct got_error*
got_fetch(char *uri, char *branch_filter, char *destdir)
{
	char proto[GOT_PROTOMAX], host[GOT_HOSTMAX], port[GOT_PORTMAX];
	char repo[GOT_REPOMAX], path[GOT_PATHMAX];
	int imsg_fetchfds[2], imsg_idxfds[2], fetchfd;
	int packfd = -1, npackfd, idxfd = -1, nidxfd, status, done = 0;
	struct got_object_id *packhash = NULL;
	const struct got_error *err;
	struct imsgbuf ibuf;
	pid_t pid;
	char *tmppackpath = NULL, *tmpidxpath = NULL, *default_destdir = NULL;
	char *packpath = NULL, *idxpath = NULL, *id_str = NULL;

	fetchfd = -1;
	if (got_parse_uri(uri, proto, host, port, path, repo) == -1)
		return got_error(GOT_ERR_PARSE_URI);
	if (destdir == NULL) {
		if (asprintf(&default_destdir, "%s.git", repo) == -1)
			return got_error_from_errno("asprintf");
	}
	err = got_repo_init(destdir ? destdir : default_destdir);
	if (err != NULL)
		return err;
	if (chdir(destdir ? destdir : default_destdir))
		return got_error_from_errno("enter new repo");
	if (mkpath("objects/pack") == -1)
		return got_error_from_errno("mkpath");
	err = got_opentemp_named_fd(&tmppackpath, &packfd,
	    "objects/pack/fetching.pack");
	if (err)
		return err;
	npackfd = dup(packfd);
	if (npackfd == -1)
		return got_error_from_errno("dup");
	err = got_opentemp_named_fd(&tmpidxpath, &idxfd,
	    "objects/pack/fetching.idx");
	if (err)
		return err;
	nidxfd = dup(idxfd);
	if (nidxfd == -1)
		return got_error_from_errno("dup");

	if (strcmp(proto, "ssh") == 0 || strcmp(proto, "git+ssh") == 0)
		err = dial_ssh(&fetchfd, host, port, path, "upload");
	else if (strcmp(proto, "git") == 0)
		err = dial_git(&fetchfd, host, port, path, "upload");
	else if (strcmp(proto, "http") == 0 || strcmp(proto, "git+http") == 0)
		err = got_error(GOT_ERR_BAD_PROTO);
	else
		err = got_error(GOT_ERR_BAD_PROTO);
	if (err)
		return err;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fetchfds) == -1)
		return got_error_from_errno("socketpair");

	pid = fork();
	if (pid == -1)
		return got_error_from_errno("fork");
	else if (pid == 0){
		got_privsep_exec_child(imsg_fetchfds, GOT_PATH_PROG_FETCH_PACK, ".");
	}

	if (close(imsg_fetchfds[1]) != 0)
		return got_error_from_errno("close");
	imsg_init(&ibuf, imsg_fetchfds[0]);
	err = got_privsep_send_fetch_req(&ibuf, fetchfd);
	if (err != NULL)
		return err;
	err = got_privsep_send_tmpfd(&ibuf, npackfd);
	if (err != NULL)
		return err;
	npackfd = dup(packfd);
	if (npackfd == -1)
		return got_error_from_errno("dup");
	while (!done) {
		struct got_object_id *id;
		char *refname;
		err = got_privsep_recv_fetch_progress(&done,
		    &id, &refname, &ibuf);
		if (err != NULL)
			return err;
		if (done) {
			packhash = got_object_id_dup(id);
			if (packhash == NULL)
				return got_error_from_errno(
				    "got_object_id_dup");
		} else {
			char *id_str;
			/* TODO Use a progress callback */
			err = got_object_id_str(&id_str, id);
			if (err)
				return err;
			printf( "%.12s %s\n", id_str, refname);
		}
	}
	if (waitpid(pid, &status, 0) == -1)
		return got_error_from_errno("child exit");

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_idxfds) == -1)
		return got_error_from_errno("socketpair");
	pid = fork();
	if (pid == -1)
		return got_error_from_errno("fork");
	else if (pid == 0)
		got_privsep_exec_child(imsg_idxfds, GOT_PATH_PROG_INDEX_PACK, ".");
	if (close(imsg_idxfds[1]) != 0)
		return got_error_from_errno("close");
	imsg_init(&ibuf, imsg_idxfds[0]);

	err = got_privsep_send_index_pack_req(&ibuf, npackfd, packhash);
	if (err != NULL)
		return err;
	err = got_privsep_send_tmpfd(&ibuf, nidxfd);
	if (err != NULL)
		return err;
	err = got_privsep_wait_index_pack_done(&ibuf);
	if (err != NULL)
		return err;
	imsg_clear(&ibuf);
	if (close(imsg_idxfds[0]) == -1)
		return got_error_from_errno("close child");
	if (waitpid(pid, &status, 0) == -1)
		return got_error_from_errno("child exit");

	err = got_object_id_str(&id_str, packhash);
	if (err)
		return err;
	if (asprintf(&packpath, "objects/pack/pack-%s.pack", id_str) == -1)
		return got_error_from_errno("asprintf");

	if (asprintf(&idxpath, "objects/pack/pack-%s.idx", id_str) == -1)
		return got_error_from_errno("asprintf");

	if (rename(tmppackpath, packpath) == -1)
		return got_error_from_errno3("rename", tmppackpath, packpath);
	if (rename(tmpidxpath, idxpath) == -1)
		return got_error_from_errno3("rename", tmpidxpath, idxpath);

	free(tmppackpath);
	free(tmpidxpath);
	free(idxpath);
	free(packpath);
	free(default_destdir);
	free(packhash);

	return NULL;
}
