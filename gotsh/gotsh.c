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

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "got_error.h"
#include "got_serve.h"

#include "gotd.h"

static int chattygot;

__dead static void
usage()
{
	fprintf(stderr, "usage: %s -c '%s|%s repository-path'\n",
	    getprogname(), GOT_SERVE_CMD_SEND, GOT_SERVE_CMD_FETCH);
	exit(1);
}

static const struct got_error *
apply_unveil(const char *unix_socket_path)
{
#ifdef PROFILE
	if (unveil("gmon.out", "rwc") != 0)
		return got_error_from_errno2("unveil", "gmon.out");
#endif
	if (unveil(unix_socket_path, "w") != 0)
		return got_error_from_errno2("unveil", unix_socket_path);

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");

	return NULL;
}

int
main(int argc, char *argv[])
{
	const struct got_error *error;
	const char *unix_socket_path;
	int gotd_sock = -1;
	struct sockaddr_un	 sun;
	char *gitcmd = NULL, *command = NULL, *repo_path = NULL;

#ifndef PROFILE
	if (pledge("stdio recvfd unix unveil", NULL) == -1)
		err(1, "pledge");
#endif
	if (strcmp(argv[0], GOT_SERVE_CMD_SEND) == 0 ||
	    strcmp(argv[0], GOT_SERVE_CMD_FETCH) == 0) {
		if (argc != 2)
			usage();
		if (asprintf(&gitcmd, "%s %s", argv[0], argv[1]) == -1)
			err(1, "asprintf");
		error = got_serve_parse_command(&command, &repo_path, gitcmd);
	} else {
		if (argc != 3 || strcmp(argv[1], "-c") != 0)
			usage();
		error = got_serve_parse_command(&command, &repo_path, argv[2]);
	}
	if (error && error->code == GOT_ERR_BAD_PACKET)
		usage();
	if (error)
		goto done;

	unix_socket_path = getenv("GOTD_UNIX_SOCKET");
	if (unix_socket_path == NULL)
		unix_socket_path = GOTD_UNIX_SOCKET;

	error = apply_unveil(unix_socket_path);
	if (error)
		goto done;

#ifndef PROFILE
	if (pledge("stdio recvfd unix", NULL) == -1)
		err(1, "pledge");
#endif
	if ((gotd_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		err(1, "socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, unix_socket_path,
	    sizeof(sun.sun_path)) >= sizeof(sun.sun_path))
		errx(1, "gotd socket path too long");
	if (connect(gotd_sock, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "connect: %s", unix_socket_path);

#ifndef PROFILE
	if (pledge("stdio recvfd", NULL) == -1)
		err(1, "pledge");
#endif
	error = got_serve(STDIN_FILENO, STDOUT_FILENO, command, repo_path,
	    gotd_sock, chattygot);
done:
	free(gitcmd);
	free(command);
	free(repo_path);
	if (gotd_sock != -1)
		close(gotd_sock);
	if (error) {
		fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
		return 1;
	}

	return 0;
}
