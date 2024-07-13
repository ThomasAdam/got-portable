/*
 * Copyright (c) 2018, 2019 Ori Bernstein <ori@openbsd.org>
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

#include "got_compat.h"

#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netdb.h>

#include <assert.h>
#include <err.h>
#include <sha1.h>
#include <sha2.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <imsg.h>

#include "got_error.h"
#include "got_path.h"
#include "got_object.h"

#include "got_compat.h"

#include "got_lib_dial.h"
#include "got_lib_delta.h"
#include "got_lib_hash.h"
#include "got_lib_object.h"
#include "got_lib_privsep.h"
#include "got_dial.h"

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

#ifndef ssizeof
#define ssizeof(_x) ((ssize_t)(sizeof(_x)))
#endif

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

#ifndef GOT_DIAL_PATH_SSH
#define GOT_DIAL_PATH_SSH	"/usr/bin/ssh"
#endif

/* IANA assigned */
#define GOT_DEFAULT_GIT_PORT		9418
#define GOT_DEFAULT_GIT_PORT_STR	"9418"

const struct got_error *
got_dial_apply_unveil(const char *proto)
{
	if (strcmp(proto, "git+ssh") == 0 || strcmp(proto, "ssh") == 0) {
		if (unveil(GOT_DIAL_PATH_SSH, "x") != 0) {
			return got_error_from_errno2("unveil",
			    GOT_DIAL_PATH_SSH);
		}
	}

	if (strstr(proto, "http") != NULL) {
		if (unveil(GOT_PATH_PROG_FETCH_HTTP, "x") != 0) {
			return got_error_from_errno2("unveil",
			    GOT_PATH_PROG_FETCH_HTTP);
		}
	}

	return NULL;
}

static int
hassuffix(const char *base, const char *suf)
{
	int nb, ns;

	nb = strlen(base);
	ns = strlen(suf);
	if (ns <= nb && strcmp(base + (nb - ns), suf) == 0)
		return 1;
	return 0;
}

const struct got_error *
got_dial_parse_uri(char **proto, char **host, char **port,
    char **server_path, char **repo_name, const char *uri)
{
	const struct got_error *err = NULL;
	char *s, *p, *q;

	*proto = *host = *port = *server_path = *repo_name = NULL;

	p = strstr(uri, "://");
	if (!p) {
		/* Try parsing Git's "scp" style URL syntax. */
		*proto = strdup("ssh");
		if (*proto == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
		s = (char *)uri;
		q = strchr(s, ':');
		if (q == NULL) {
			err = got_error(GOT_ERR_PARSE_URI);
			goto done;
		}
		/* No slashes allowed before first colon. */
		p = strchr(s, '/');
		if (p && q > p) {
			err = got_error(GOT_ERR_PARSE_URI);
			goto done;
		}
		*host = strndup(s, q - s);
		if (*host == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if ((*host)[0] == '\0') {
			err = got_error(GOT_ERR_PARSE_URI);
			goto done;
		}
		p = q + 1;
	} else {
		*proto = strndup(uri, p - uri);
		if (*proto == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		s = p + 3;

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
			if ((*host)[0] == '\0') {
				err = got_error(GOT_ERR_PARSE_URI);
				goto done;
			}
			*port = strndup(q + 1, p - (q + 1));
			if (*port == NULL) {
				err = got_error_from_errno("strndup");
				goto done;
			}
			if ((*port)[0] == '\0') {
				err = got_error(GOT_ERR_PARSE_URI);
				goto done;
			}
		} else {
			*host = strndup(s, p - s);
			if (*host == NULL) {
				err = got_error_from_errno("strndup");
				goto done;
			}
			if ((*host)[0] == '\0') {
				err = got_error(GOT_ERR_PARSE_URI);
				goto done;
			}
		}
	}

	while (p[0] == '/' && (p[1] == '/' || p[1] == '~'))
		p++;
	*server_path = strdup(p);
	if (*server_path == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}
	got_path_strip_trailing_slashes(*server_path);
	if ((*server_path)[0] == '\0') {
		err = got_error(GOT_ERR_PARSE_URI);
		goto done;
	}

	err = got_path_basename(repo_name, *server_path);
	if (err)
		goto done;
	if (hassuffix(*repo_name, ".git"))
		(*repo_name)[strlen(*repo_name) - 4] = '\0';
	if ((*repo_name)[0] == '\0')
		err = got_error(GOT_ERR_PARSE_URI);
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

/*
 * Escape a given path for the shell which will be started by sshd.
 * In particular, git-shell is known to require single-quote characters
 * around its repository path argument and will refuse to run otherwise.
 */
static const struct got_error *
escape_path(char *buf, size_t bufsize, const char *path)
{
	const char	*p;
	char		*q;

	p = path;
	q = buf;

	if (bufsize > 1)
		*q++ = '\'';

	while (*p != '\0' && (q - buf < bufsize)) {
		/* git escapes ! too */
		if (*p != '\'' && *p != '!') {
			*q++ = *p++;
			continue;
		}

		if (q - buf + 4 >= bufsize)
			break;
		*q++ = '\'';
		*q++ = '\\';
		*q++ = *p++;
		*q++ = '\'';
	}

	if (*p == '\0' && (q - buf + 1 < bufsize)) {
		*q++ = '\'';
		*q = '\0';
		return NULL;
	}

	return got_error_fmt(GOT_ERR_NO_SPACE, "overlong path: %s", path);
}

const struct got_error *
got_dial_ssh(pid_t *newpid, int *newfd, const char *host,
    const char *port, const char *path, const char *command, int verbosity)
{
	const struct got_error *error = NULL;
	int pid, pfd[2];
	char cmd[64];
	char escaped_path[PATH_MAX];
	const char *argv[11];
	int i = 0, j;

	*newpid = -1;
	*newfd = -1;

	error = escape_path(escaped_path, sizeof(escaped_path), path);
	if (error)
		return error;

	argv[i++] = GOT_DIAL_PATH_SSH;
	if (port != NULL) {
		argv[i++] = "-p";
		argv[i++] = (char *)port;
	}
	if (verbosity == -1) {
		argv[i++] = "-q";
	} else {
		/* ssh(1) allows up to 3 "-v" options. */
		for (j = 0; j < MIN(3, verbosity); j++)
			argv[i++] = "-v";
	}
	argv[i++] = "--";
	argv[i++] = (char *)host;
	argv[i++] = (char *)cmd;
	argv[i++] = (char *)escaped_path;
	argv[i++] = NULL;
	assert(i <= nitems(argv));

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pfd) == -1)
		return got_error_from_errno("socketpair");

	pid = fork();
	if (pid == -1) {
		error = got_error_from_errno("fork");
		close(pfd[0]);
		close(pfd[1]);
		return error;
	} else if (pid == 0) {
		if (close(pfd[1]) == -1)
			err(1, "close");
		if (dup2(pfd[0], 0) == -1)
			err(1, "dup2");
		if (dup2(pfd[0], 1) == -1)
			err(1, "dup2");
		if (strlcpy(cmd, command, sizeof(cmd)) >= sizeof(cmd))
			err(1, "snprintf");
		if (execv(GOT_DIAL_PATH_SSH, (char *const *)argv) == -1)
			err(1, "execv %s", GOT_DIAL_PATH_SSH);
		abort(); /* not reached */
	} else {
		if (close(pfd[0]) == -1)
			return got_error_from_errno("close");
		*newpid = pid;
		*newfd = pfd[1];
		return NULL;
	}
}

const struct got_error *
got_dial_git(int *newfd, const char *host, const char *port,
    const char *path, const char *command)
{
	const struct got_error *err = NULL;
	struct addrinfo hints, *servinfo, *p;
	char *cmd = NULL;
	int fd = -1, len, r, eaicode;

	*newfd = -1;

	if (port == NULL)
		port = GOT_DEFAULT_GIT_PORT_STR;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	eaicode = getaddrinfo(host, port, &hints, &servinfo);
	if (eaicode) {
		char msg[512];
		snprintf(msg, sizeof(msg), "%s: %s", host,
		    gai_strerror(eaicode));
		return got_error_msg(GOT_ERR_ADDRINFO, msg);
	}

	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((fd = socket(p->ai_family, p->ai_socktype,
		    p->ai_protocol)) == -1)
			continue;
		if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
			err = NULL;
			break;
		}
		err = got_error_from_errno("connect");
		close(fd);
	}
	freeaddrinfo(servinfo);
	if (p == NULL)
		goto done;

	if (asprintf(&cmd, "%s %s", command, path) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	len = 4 + strlen(cmd) + 1 + strlen("host=") + strlen(host) + 1;
	r = dprintf(fd, "%04x%s%chost=%s%c", len, cmd, '\0', host, '\0');
	if (r < 0)
		err = got_error_from_errno("dprintf");
done:
	free(cmd);
	if (err) {
		if (fd != -1)
			close(fd);
	} else
		*newfd = fd;
	return err;
}

const struct got_error *
got_dial_http(pid_t *newpid, int *newfd, const char *host,
    const char *port, const char *path, int verbosity, int tls)
{
	const struct got_error *error = NULL;
	int pid, pfd[2];
	const char *argv[8];
	int i = 0;

	*newpid = -1;
	*newfd = -1;

	if (!port)
		port = tls ? "443" : "80";

	argv[i++] = GOT_PATH_PROG_FETCH_HTTP;
	if (verbosity == -1)
		argv[i++] = "-q";
	else if (verbosity > 0)
		argv[i++] = "-v";
	argv[i++] = "--";
	argv[i++] = tls ? "https" : "http";
	argv[i++] = host;
	argv[i++] = port;
	argv[i++] = path;
	argv[i++] = NULL;
	assert(i <= nitems(argv));

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pfd) == -1)
		return got_error_from_errno("socketpair");

	pid = fork();
	if (pid == -1) {
		error = got_error_from_errno("fork");
		close(pfd[0]);
		close(pfd[1]);
		return error;
	} else if (pid == 0) {
		if (close(pfd[1]) == -1)
			err(1, "close");
		if (dup2(pfd[0], 0) == -1)
			err(1, "dup2");
		if (dup2(pfd[0], 1) == -1)
			err(1, "dup2");
		if (execv(GOT_PATH_PROG_FETCH_HTTP, (char *const *)argv) == -1)
			err(1, "execv %s", GOT_PATH_PROG_FETCH_HTTP);
		abort(); /* not reached */
	} else {
		if (close(pfd[0]) == -1)
			return got_error_from_errno("close");
		*newpid = pid;
		*newfd = pfd[1];
		return NULL;
	}
}

const struct got_error *
got_dial_parse_command(char **command, char **repo_path, const char *gitcmd)
{
	const struct got_error *err = NULL;
	size_t len, cmdlen, pathlen;
	char *path0 = NULL, *path, *abspath = NULL, *canonpath = NULL;
	const char *relpath;

	*command = NULL;
	*repo_path = NULL;

	len = strlen(gitcmd);

	if (len >= strlen(GOT_DIAL_CMD_SEND) &&
	    strncmp(gitcmd, GOT_DIAL_CMD_SEND,
	    strlen(GOT_DIAL_CMD_SEND)) == 0)
		cmdlen = strlen(GOT_DIAL_CMD_SEND);
	else if (len >= strlen(GOT_DIAL_CMD_FETCH) &&
	    strncmp(gitcmd, GOT_DIAL_CMD_FETCH,
	    strlen(GOT_DIAL_CMD_FETCH)) == 0)
		cmdlen = strlen(GOT_DIAL_CMD_FETCH);
	else
		return got_error(GOT_ERR_BAD_PACKET);

	if (len <= cmdlen + 1 || gitcmd[cmdlen] != ' ')
		return got_error(GOT_ERR_BAD_PACKET);

	if (memchr(&gitcmd[cmdlen + 1], '\0', len - cmdlen) == NULL)
		return got_error(GOT_ERR_BAD_PATH);

	/* Forbid linefeeds in paths, like Git does. */
	if (memchr(&gitcmd[cmdlen + 1], '\n', len - cmdlen) != NULL)
		return got_error(GOT_ERR_BAD_PATH);

	path0 = strdup(&gitcmd[cmdlen + 1]);
	if (path0 == NULL)
		return got_error_from_errno("strdup");
	path = path0;
	pathlen = strlen(path);

	/*
	 * Git clients send a shell command.
	 * Trim spaces and quotes around the path.
	 */
	while (path[0] == '\'' || path[0] == '\"' || path[0] == ' ') {
		path++;
		pathlen--;
	}
	while (pathlen > 0 &&
	    (path[pathlen - 1] == '\'' || path[pathlen - 1] == '\"' ||
	    path[pathlen - 1] == ' ')) {
		path[pathlen - 1] = '\0';
		pathlen--;
	}

	/* Deny an empty repository path. */
	if (path[0] == '\0' || got_path_is_root_dir(path)) {
		err = got_error(GOT_ERR_NOT_GIT_REPO);
		goto done;
	}

	if (asprintf(&abspath, "/%s", path) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	pathlen = strlen(abspath);
	canonpath = malloc(pathlen + 1);
	if (canonpath == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}
	err = got_canonpath(abspath, canonpath, pathlen + 1);
	if (err)
		goto done;

	relpath = canonpath;
	while (relpath[0] == '/')
		relpath++;
	*repo_path = strdup(relpath);
	if (*repo_path == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}
	*command = strndup(gitcmd, cmdlen);
	if (*command == NULL)
		err = got_error_from_errno("strndup");
done:
	free(path0);
	free(abspath);
	free(canonpath);
	if (err) {
		free(*repo_path);
		*repo_path = NULL;
	}
	return err;
}
