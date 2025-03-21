/*
 * Copyright (c) 2023 Stefan Sperling <stsp@openbsd.org>
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

/*
 * Resolve path namespace conflicts for git-upload-pack and git-receive-pack.
 */

#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <sha2.h>
#include <syslog.h>
#include <util.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"

#include "got_lib_dial.h"

#include "gotd.h"
#include "log.h"
#include "secrets.h"

#ifndef GITWRAPPER_GIT_LIBEXEC_DIR
#define GITWRAPPER_GIT_LIBEXEC_DIR "/usr/local/libexec/git"
#endif

#ifndef GITWRAPPER_MY_SERVER_PROG
#define GITWRAPPER_MY_SERVER_PROG "gotsh"
#endif

/* only needed to satisfy the linker */
struct gotd_secret *
gotd_secrets_get(struct gotd_secrets *secrets, enum gotd_secret_type t,
    const char *label)
{
	return NULL;
}

__dead static void
usage(void)
{
	fprintf(stderr, "usage: %s -c '%s|%s repository-path'\n",
	    getprogname(), GOT_DIAL_CMD_SEND, GOT_DIAL_CMD_FETCH);
	exit(1);
}

/*
 * Unveil the specific programs we want to start and hide everything else.
 * This is important to limit the impact of our "exec" pledge.
 */
static const struct got_error *
apply_unveil(const char *myserver)
{
	const char *fetchcmd = GITWRAPPER_GIT_LIBEXEC_DIR "/" \
		GOT_DIAL_CMD_FETCH;
	const char *sendcmd = GITWRAPPER_GIT_LIBEXEC_DIR "/" \
		GOT_DIAL_CMD_SEND;

#ifdef PROFILE
	if (unveil("gmon.out", "rwc") != 0)
		return got_error_from_errno2("unveil", "gmon.out");
#endif
	if (unveil(fetchcmd, "x") != 0 && errno != ENOENT)
		return got_error_from_errno2("unveil", fetchcmd);

	if (unveil(sendcmd, "x") != 0 && errno != ENOENT)
		return got_error_from_errno2("unveil", sendcmd);

	if (myserver && unveil(myserver, "x") != 0 && errno != ENOENT)
		return got_error_from_errno2("unveil", myserver);

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");

	return NULL;
}

int
main(int argc, char *argv[])
{
	const struct got_error *error;
	const char *confpath = NULL;
	int conf_fd = -1;
	char *command = NULL, *repo_name = NULL; /* for matching gotd.conf */
	char *myserver = NULL;
	const char *repo_path = NULL; /* as passed on the command line */
	const char *relpath;
	char *gitcommand = NULL;
	struct gotd gotd;
	struct gotd_repo *repo = NULL;

	log_init(1, LOG_USER); /* Log to stderr. */

#ifndef PROFILE
	if (pledge("stdio rpath exec unveil", NULL) == -1)
		err(1, "pledge");
#endif

	/*
	 * Look up our own server program in PATH so we can unveil(2) it.
	 * This call only errors out upon memory allocation failure.
	 * If the program cannot be found then myserver will be set to NULL.
	 */
	error = got_path_find_prog(&myserver, GITWRAPPER_MY_SERVER_PROG);
	if (error)
		goto done;

	/*
	 * Run gotd_parse_config() before unveil(2) because gotd_parse_config()
	 * checks whether repository paths exist on disk.
	 * Parsing errors and warnings will be logged to stderr.
	 * Upon failure we will run Git's native tooling so do not
	 * bother checking for errors here, not even from open(2).
	 */
	confpath = getenv("GOTD_CONF_PATH");
	if (confpath == NULL)
		confpath = GOTD_CONF_PATH;
	conf_fd = open(confpath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	gotd_parse_config(confpath, conf_fd, GOTD_PROC_GITWRAPPER, NULL, &gotd);

	error = apply_unveil(myserver);
	if (error)
		goto done;

#ifndef PROFILE
	if (pledge("stdio exec", NULL) == -1)
		err(1, "pledge");
#endif

	if (strcmp(getprogname(), GOT_DIAL_CMD_SEND) == 0 ||
	    strcmp(getprogname(), GOT_DIAL_CMD_FETCH) == 0) {
		if (argc != 2)
			usage();
		command = strdup(getprogname());
		if (command == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
		repo_path = argv[1];
		relpath = argv[1];
		while (relpath[0] == '/')
			relpath++;
		repo_name = strdup(relpath);
		if (repo_name == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	} else {
		if (argc != 3 || strcmp(argv[1], "-c") != 0)
			usage();
		repo_path = argv[2];
		error = got_dial_parse_command(&command, &repo_name,
		    repo_path);
		if (error && error->code == GOT_ERR_BAD_PACKET)
			usage();
		if (error)
			goto done;
	}

	repo = gotd_find_repo_by_name(repo_name, &gotd.repos);

	/*
	 * Invoke our custom Git server if the repository was found
	 * in gotd.conf. Otherwise invoke native git(1) tooling.
	 */
	if (repo) {
		if (myserver == NULL) {
			error = got_error_fmt(GOT_ERR_NO_PROG,
			    "cannot run '%s'",
			    GITWRAPPER_MY_SERVER_PROG);
			goto done;
		}
		execl(myserver, command, repo_name, (char *)NULL);
		error = got_error_from_errno2("execl", myserver);
	} else {
		if (asprintf(&gitcommand, "%s/%s",
		    GITWRAPPER_GIT_LIBEXEC_DIR, command) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
		execl(gitcommand, gitcommand, repo_path, (char *)NULL);
		error = got_error_from_errno2("execl", gitcommand);
	}

done:
	free(command);
	free(repo_name);
	free(myserver);
	free(gitcommand);
	if (conf_fd != -1 && close(conf_fd) && error == NULL)
		error = got_error_from_errno("close");
	if (error) {
		fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
		return 1;
	}

	return 0;
}
