/*
 * Copyright (c) 2025 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/tree.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <limits.h>
#include <pwd.h>
#include <sha1.h>
#include <sha2.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <util.h>
#include <unistd.h>

#include "got_error.h"
#include "got_path.h"
#include "got_object.h"
#include "got_repository.h"

#include "gotsysd.h"
#include "gotsys.h"

static struct gotsys_conf gotsysconf;
static char repos_path[_POSIX_PATH_MAX];
static int repos_dir_fd = -1;
uid_t gotd_uid;
gid_t gotd_gid;

static void
sighdlr(int sig, short event, void *arg)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGHUP:
		break;
	case SIGUSR1:
		break;
	case SIGTERM:
	case SIGINT:
		event_loopexit(NULL);
		break;
	default:
		break;
	}
}

/* Ensure that repositories are only accessible to the gotd user. */
static const struct got_error *
chmod_700_repo(const char *repo_name)
{
	struct stat sb;

	if (fstatat(repos_dir_fd, repo_name, &sb, AT_SYMLINK_NOFOLLOW) == -1) {
		return got_error_from_errno_fmt("stat %s/%s",
		    repos_path, repo_name);
	}

	if (!S_ISDIR(sb.st_mode) || sb.st_uid != gotd_uid)
		return NULL;

	if (fchmodat(repos_dir_fd, repo_name, S_IRWXU,
	    AT_SYMLINK_NOFOLLOW) == -1) {
		return got_error_from_errno_fmt("chmod %o %s/%s",
		    S_IRWXU, repos_path, repo_name);
	}

	return NULL;
}

static const struct got_error *
create_repo(struct imsg *imsg)
{
	const struct got_error *err = NULL;
	size_t datalen, namelen;
	char *repo_name = NULL;
	char *fullname = NULL;
	char *abspath = NULL;

	if (repos_dir_fd == -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen == 0 || datalen > NAME_MAX)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	repo_name = strndup(imsg->data, datalen);
	if (repo_name == NULL)
		return got_error_from_errno("strndup");

	err = gotsys_conf_validate_repo_name(repo_name);
	if (err)
		goto done;

	namelen = strlen(repo_name);
	if (namelen < 4 || strcmp(&repo_name[namelen - 4], ".git") != 0) {
		if (asprintf(&fullname, "%s.git", repo_name) == -1) {
			err = got_error_from_errno("asprintf");
			fullname = NULL;
			goto done;
		}
	} else {
		fullname = repo_name;
		repo_name = NULL;
	}

	if (asprintf(&abspath, "%s/%s", repos_path, fullname) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (mkdirat(repos_dir_fd, fullname, S_IRWXU) == -1) {
		if (errno == EEXIST)
			err = chmod_700_repo(fullname);
		else
			err = got_error_from_errno2("mkdir", abspath);
	} else
		err = got_repo_init(abspath, NULL, GOT_HASH_SHA1);
done:
	free(repo_name);
	free(fullname);
	free(abspath);
	return err;
	
}

static void
dispatch_event(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	int shut = 0;
	static int flush_and_exit;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1) {
			warn("imsgbuf_read error");
			goto fatal;
		}
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	if (event & EV_WRITE) {
		err = gotsysd_imsg_flush(ibuf);
		if (err) {
			warn("%s", err->msg);
			goto fatal;
		}

		if (flush_and_exit) {
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1) {
			warn("%s: imsg_get", __func__);
			goto fatal;
		}
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_SYSCONF_REPO_CREATE:
			err = create_repo(&imsg);
			break;
		case GOTSYSD_IMSG_SYSCONF_REPO_CREATE_DONE:
			flush_and_exit = 1;
			if (gotsysd_imsg_compose_event(iev,
			    GOTSYSD_IMSG_SYSCONF_REPO_CREATE_DONE, 0,
			    -1, NULL, 0) == -1) {
				err = got_error_from_errno("imsg_compose "
				    "SYSCONF_REPO_CREATE_DONE");
			}
			break;
		default:
			err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
			    "unexpected imsg %d", imsg.hdr.type);
			break;
		}

		if (err) {
			warnx("imsg %d: %s", imsg.hdr.type, err->msg);
			gotsysd_imsg_send_error(&iev->ibuf, 0, 0, err);
			err = NULL;
		}

		imsg_free(&imsg);
	}

	if (!shut) {
		gotsysd_imsg_event_add(iev);
	} else {
fatal:
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

int
main(int argc, char **argv)
{
	const struct got_error *error = NULL;
	struct gotsysd_imsgev iev;
	struct event evsigint, evsigterm, evsighup, evsigusr1;
	struct passwd *pw;
	char *username;
	struct stat sb;
#if 0
	static int attached;

	while (!attached)
		sleep(1);
#endif
	gotsys_conf_init(&gotsysconf);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr chown getpw id unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif
	if (geteuid())
		errx(1, "need root privileges");

	if (argc != 3)
		errx(1, "usage: %s username repos_path", getprogname());

	username = argv[1];
	if (realpath(argv[2], repos_path) == NULL)
		err(1, "realpath %s", argv[2]);

	pw = getpwnam(username);
	if (pw == NULL)
		err(1, "getpwnam %s", username);

	gotd_uid = pw->pw_uid;
	gotd_gid = pw->pw_gid;

	endpwent();
	pw = NULL;

	if (gotd_uid == 0)
		errx(1, "user %s is a root user", username);
	if (gotd_gid == 0)
		errx(1, "user %s has GID 0", username);

	if (setgid(gotd_gid) == -1)
		err(1, "setgid %d failed", gotd_gid);
	if (setuid(gotd_uid) == -1)
		err(1, "setuid %d failed", gotd_uid);

	warn("running as %s", username);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr chown unveil", NULL) == -1) {
		error = got_error_from_errno("pledge");
		goto done;
	}
#endif
	event_init();

	signal_set(&evsigint, SIGINT, sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);
	if (imsgbuf_init(&iev.ibuf, GOTSYSD_FILENO_MSG_PIPE) == -1)
		err(1, "imsgbuf_init");

	iev.handler = dispatch_event;
	iev.events = EV_READ;
	iev.handler_arg = NULL;
	event_set(&iev.ev, iev.ibuf.fd, EV_READ, dispatch_event, &iev);

	if (unveil(repos_path, "rwc") == -1) {
		error = got_error_from_errno_fmt("unveil 'rwc' %s", repos_path);
		goto done;
	}

	if (unveil(NULL, NULL) == -1) {
		error = got_error_from_errno("unveil");
		goto done;
	}

	repos_dir_fd = open(repos_path, O_DIRECTORY);
	if (repos_dir_fd == -1) {
		error = got_error_from_errno2("open", repos_path);
		goto done;
	}

	if (fstat(repos_dir_fd, &sb) == -1) {
		error = got_error_from_errno2("stat", repos_path);
		goto done;
	}

	if (gotd_uid != sb.st_uid) {
		error = got_error_fmt(GOT_ERR_BAD_PATH,
		    "directory is not owned by UID %u: %s",
		    gotd_uid, repos_path);
		goto done;
	}

	if (gotd_gid != sb.st_gid) {
		error = got_error_fmt(GOT_ERR_BAD_PATH,
		    "directory is not owned by GID %u: %s",
		    gotd_gid, repos_path);
		goto done;
	}

	if (sb.st_mode & (S_IRWXG | S_IRWXO)) {
		error = got_error_fmt(GOT_ERR_BAD_PATH,
		    "directory must only be accessible/writable by user %s: %s",
		    username, repos_path);
		goto done;
	}

	if (gotsysd_imsg_compose_event(&iev, GOTSYSD_IMSG_PROG_READY, 0,
	    -1, NULL, 0) == -1) {
		error = got_error_from_errno("gotsysd_imsg_compose_event");
		goto done;
	}

	event_dispatch();
done:
	if (repos_dir_fd != -1 && close(repos_dir_fd) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (close(GOTSYSD_FILENO_MSG_PIPE) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (error) {
		warnx("%s", error->msg);
		gotsysd_imsg_send_error(&iev.ibuf, 0, 0, error);
	}
	imsgbuf_clear(&iev.ibuf);
	return error ? 1 : 0;
}
