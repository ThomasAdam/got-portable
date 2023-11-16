/*
 * Copyright (c) 2016, 2019, 2020-2021 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2015 Reyk Floeter <reyk@openbsd.org>
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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <net/if.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>

#include "got_compat.h"
#include "got_opentemp.h"
#include "got_reference.h"

#include "gotwebd.h"

__dead void usage(void);

int	 main(int, char **);
int	 gotwebd_configure(struct gotwebd *);
void	 gotwebd_configure_done(struct gotwebd *);
void	 gotwebd_sighdlr(int sig, short event, void *arg);
void	 gotwebd_shutdown(void);
void	 gotwebd_dispatch_sockets(int, short, void *);

struct gotwebd	*gotwebd_env;

void
imsg_event_add(struct imsgev *iev)
{
	if (iev->handler == NULL) {
		imsg_flush(&iev->ibuf);
		return;
	}

	iev->events = EV_READ;
	if (iev->ibuf.w.queued)
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler, iev->data);
	event_add(&iev->ev, NULL);
}

int
imsg_compose_event(struct imsgev *iev, uint16_t type, uint32_t peerid,
    pid_t pid, int fd, const void *data, uint16_t datalen)
{
	int ret;

	ret = imsg_compose(&iev->ibuf, type, peerid, pid, fd, data, datalen);
	if (ret == -1)
		return (ret);
	imsg_event_add(iev);
	return (ret);
}

int
main_compose_sockets(struct gotwebd *env, uint32_t type, int fd,
    const void *data, uint16_t len)
{
	size_t	 i;
	int	 ret, d;

	for (i = 0; i < env->nserver; ++i) {
		d = -1;
		if (fd != -1 && (d = dup(fd)) == -1)
			goto err;

		ret = imsg_compose_event(&env->iev_server[i], type, 0, -1,
		    d, data, len);
		if (ret == -1)
			goto err;

		/* prevent fd exhaustion */
		if (d != -1) {
			do {
				ret = imsg_flush(&env->iev_server[i].ibuf);
			} while (ret == -1 && errno == EAGAIN);
			if (ret == -1)
				goto err;
			imsg_event_add(&env->iev_server[i]);
		}
	}

	if (fd != -1)
		close(fd);
	return 0;

err:
	if (fd != -1)
		close(fd);
	return -1;
}

int
sockets_compose_main(struct gotwebd *env, uint32_t type, const void *d,
    uint16_t len)
{
	return (imsg_compose_event(env->iev_parent, type, 0, -1, -1, d, len));
}

void
gotwebd_dispatch_sockets(int fd, short event, void *arg)
{
	struct imsgev		*iev = arg;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	struct gotwebd		*env = gotwebd_env;
	ssize_t			 n;
	int			 shut = 0;

	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0)	/* Connection closed */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)	/* Connection closed */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("imsg_get");
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case IMSG_CFG_DONE:
			gotwebd_configure_done(env);
			break;
		default:
			fatalx("%s: unknown imsg type %d", __func__,
			    imsg.hdr.type);
		}

		imsg_free(&imsg);
	}

	if (!shut)
		imsg_event_add(iev);
	else {
		/* This pipe is dead.  Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
gotwebd_sighdlr(int sig, short event, void *arg)
{
	/* struct privsep	*ps = arg; */

	switch (sig) {
	case SIGHUP:
		log_info("%s: ignoring SIGHUP", __func__);
		break;
	case SIGPIPE:
		log_info("%s: ignoring SIGPIPE", __func__);
		break;
	case SIGUSR1:
		log_info("%s: ignoring SIGUSR1", __func__);
		break;
	case SIGTERM:
	case SIGINT:
		gotwebd_shutdown();
		break;
	default:
		fatalx("unexpected signal");
	}
}

static int
spawn_socket_process(struct gotwebd *env, const char *argv0, int n)
{
	const char	*argv[5];
	int		 argc = 0;
	int		 p[2];
	pid_t		 pid;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, p) == -1)
		fatal("socketpair");

	switch (pid = fork()) {
	case -1:
		fatal("fork");
	case 0:		/* child */
		break;
	default:	/* parent */
		close(p[0]);
		imsg_init(&env->iev_server[n].ibuf, p[1]);
		env->iev_server[n].handler = gotwebd_dispatch_sockets;
		env->iev_server[n].data = &env->iev_server[n];
		event_set(&env->iev_server[n].ev, p[1], EV_READ,
		    gotwebd_dispatch_sockets, &env->iev_server[n]);
		event_add(&env->iev_server[n].ev, NULL);
		return 0;
	}

	close(p[1]);

	argv[argc++] = argv0;
	argv[argc++] = "-S";
	if (env->gotwebd_debug)
		argv[argc++] = "-d";
	if (env->gotwebd_verbose)
		argv[argc++] = "-v";
	argv[argc] = NULL;

	if (p[0] != GOTWEBD_SOCK_FILENO) {
		if (dup2(p[0], GOTWEBD_SOCK_FILENO) == -1)
			fatal("dup2");
	} else if (fcntl(p[0], F_SETFD, 0) == -1)
		fatal("fcntl");

	/* obnoxious cast */
	execvp(argv0, (char * const *)argv);
	fatal("execvp %s", argv0);
}

__dead void
usage(void)
{
	fprintf(stderr, "usage: %s [-dnv] [-D macro=value] [-f file]\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{
	struct event		 sigint, sigterm, sighup, sigpipe, sigusr1;
	struct gotwebd		*env;
	struct passwd		*pw;
	int			 ch, i;
	int			 no_action = 0;
	int			 server_proc = 0;
	const char		*conffile = GOTWEBD_CONF;
	const char		*argv0;

	if ((argv0 = argv[0]) == NULL)
		argv0 = "gotwebd";

	/* log to stderr until daemonized */
	log_init(1, LOG_DAEMON);

	env = calloc(1, sizeof(*env));
	if (env == NULL)
		fatal("%s: calloc", __func__);
	config_init(env);

	while ((ch = getopt(argc, argv, "D:df:nSv")) != -1) {
		switch (ch) {
		case 'D':
			if (cmdline_symset(optarg) < 0)
				log_warnx("could not parse macro definition %s",
				    optarg);
			break;
		case 'd':
			env->gotwebd_debug = 1;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'n':
			no_action = 1;
			break;
		case 'S':
			server_proc = 1;
			break;
		case 'v':
			env->gotwebd_verbose++;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	if (argc > 0)
		usage();

	gotwebd_env = env;
	env->gotwebd_conffile = conffile;

	if (parse_config(env->gotwebd_conffile, env) == -1)
		exit(1);

	if (no_action) {
		fprintf(stderr, "configuration OK\n");
		exit(0);
	}

	/* check for root privileges */
	if (geteuid())
		fatalx("need root privileges");

	pw = getpwnam(GOTWEBD_USER);
	if (pw == NULL)
		fatalx("unknown user %s", GOTWEBD_USER);
	env->pw = pw;

	log_init(env->gotwebd_debug, LOG_DAEMON);
	log_setverbose(env->gotwebd_verbose);

	if (server_proc) {
		setproctitle("sockets");
		log_procinit("sockets");

		if (chroot(pw->pw_dir) == -1)
			fatal("chroot %s", pw->pw_dir);
		if (chdir("/") == -1)
			fatal("chdir /");
		if (setgroups(1, &pw->pw_gid) == -1 ||
		    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1 ||
		    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
			fatal("failed to drop privileges");

		sockets(env, GOTWEBD_SOCK_FILENO);
		return 1;
	}

	if (!env->gotwebd_debug && daemon(1, 0) == -1)
		fatal("daemon");

	event_init();

	env->nserver = env->prefork_gotwebd;
	env->iev_server = calloc(env->nserver, sizeof(*env->iev_server));
	if (env->iev_server == NULL)
		fatal("calloc");

	for (i = 0; i < env->nserver; ++i) {
		if (spawn_socket_process(env, argv0, i) == -1)
			fatal("spawn_socket_process");
	}

	if (chdir("/") == -1)
		fatal("chdir /");

	log_procinit("gotwebd");

	log_info("%s startup", getprogname());

	signal_set(&sigint, SIGINT, gotwebd_sighdlr, env);
	signal_set(&sigterm, SIGTERM, gotwebd_sighdlr, env);
	signal_set(&sighup, SIGHUP, gotwebd_sighdlr, env);
	signal_set(&sigpipe, SIGPIPE, gotwebd_sighdlr, env);
	signal_set(&sigusr1, SIGUSR1, gotwebd_sighdlr, env);

	signal_add(&sigint, NULL);
	signal_add(&sigterm, NULL);
	signal_add(&sighup, NULL);
	signal_add(&sigpipe, NULL);
	signal_add(&sigusr1, NULL);

	if (gotwebd_configure(env) == -1)
		fatalx("configuration failed");

#ifdef PROFILE
	if (unveil("gmon.out", "rwc") != 0)
		err(1, "gmon.out");
#endif

	if (unveil(env->httpd_chroot, "r") == -1)
		err(1, "unveil");

	if (unveil(GOTWEBD_CONF, "r") == -1)
		err(1, "unveil");

	if (unveil(NULL, NULL) != 0)
		err(1, "unveil");

#ifndef PROFILE
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");
#endif

	event_dispatch();

	log_debug("%s gotwebd exiting", getprogname());

	return (0);
}

int
gotwebd_configure(struct gotwebd *env)
{
	struct server *srv;
	struct socket *sock;

	/* gotweb need to reload its config. */
	env->gotwebd_reload = env->prefork_gotwebd;

	/* send our gotweb servers */
	TAILQ_FOREACH(srv, &env->servers, entry) {
		if (config_setserver(env, srv) == -1)
			fatalx("%s: send server error", __func__);
	}

	/* send our sockets */
	TAILQ_FOREACH(sock, &env->sockets, entry) {
		if (config_setsock(env, sock) == -1)
			fatalx("%s: send socket error", __func__);
		if (config_setfd(env, sock) == -1)
			fatalx("%s: send priv_fd error", __func__);
	}

	if (main_compose_sockets(env, IMSG_CFG_DONE, -1, NULL, 0) == -1)
		fatal("main_compose_sockets IMSG_CFG_DONE");

	return (0);
}

void
gotwebd_configure_done(struct gotwebd *env)
{
	if (env->gotwebd_reload == 0) {
		log_warnx("%s: configuration already finished", __func__);
		return;
	}

	env->gotwebd_reload--;
	if (env->gotwebd_reload == 0 &&
	    main_compose_sockets(env, IMSG_CTL_START, -1, NULL, 0) == -1)
		fatal("main_compose_sockets IMSG_CTL_START");
}

void
gotwebd_shutdown(void)
{
	struct gotwebd	*env = gotwebd_env;
	pid_t		 pid;
	int		 i, status;

	for (i = 0; i < env->nserver; ++i) {
		event_del(&env->iev_server[i].ev);
		imsg_clear(&env->iev_server[i].ibuf);
		close(env->iev_server[i].ibuf.fd);
		env->iev_server[i].ibuf.fd = -1;
	}

	do {
		pid = waitpid(WAIT_ANY, &status, 0);
		if (pid <= 0)
			continue;

		if (WIFSIGNALED(status))
			log_warnx("lost child: pid %u terminated; signal %d",
			    pid, WTERMSIG(status));
		else if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
			log_warnx("lost child: pid %u exited abnormally",
			    pid);
	} while (pid != -1 || (pid == -1 && errno == EINTR));

	free(gotwebd_env);

	log_warnx("gotwebd terminating");
	exit(0);
}
