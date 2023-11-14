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

#include "proc.h"
#include "gotwebd.h"

__dead void usage(void);

int	 main(int, char **);
int	 gotwebd_configure(struct gotwebd *);
void	 gotwebd_configure_done(struct gotwebd *);
void	 gotwebd_sighdlr(int sig, short event, void *arg);
void	 gotwebd_shutdown(void);
int	 gotwebd_dispatch_sockets(int, struct privsep_proc *, struct imsg *);

struct gotwebd	*gotwebd_env;

static struct privsep_proc procs[] = {
	{ "sockets",	PROC_SOCKS,	gotwebd_dispatch_sockets, sockets,
	    sockets_shutdown },
};

int
gotwebd_dispatch_sockets(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep		*ps = p->p_ps;
	struct gotwebd		*env = ps->ps_env;

	switch (imsg->hdr.type) {
	case IMSG_CFG_DONE:
		gotwebd_configure_done(env);
		break;
	default:
		return (-1);
	}

	return (0);
}

void
gotwebd_sighdlr(int sig, short event, void *arg)
{
	/* struct privsep	*ps = arg; */

	if (privsep_process != PROC_GOTWEBD)
		return;

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
	struct gotwebd *env;
	struct privsep *ps;
	unsigned int proc;
	int ch;
	const char *conffile = GOTWEBD_CONF;
	enum privsep_procid proc_id = PROC_GOTWEBD;
	int proc_instance = 0;
	const char *errp, *title = NULL;
	int argc0 = argc;

	env = calloc(1, sizeof(*env));
	if (env == NULL)
		fatal("%s: calloc", __func__);

	/* XXX: add s and S for both sockets */
	while ((ch = getopt(argc, argv, "D:df:I:nP:v")) != -1) {
		switch (ch) {
		case 'D':
			if (cmdline_symset(optarg) < 0)
				log_warnx("could not parse macro definition %s",
				    optarg);
			break;
		case 'd':
			env->gotwebd_debug = 2;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'I':
			proc_instance = strtonum(optarg, 0,
			    PROC_MAX_INSTANCES, &errp);
			if (errp)
				fatalx("invalid process instance");
			break;
		case 'n':
			env->gotwebd_debug = 2;
			env->gotwebd_noaction = 1;
			break;
		case 'P':
			title = optarg;
			proc_id = proc_getid(procs, nitems(procs), title);
			if (proc_id == PROC_MAX)
				fatalx("invalid process name");
			break;
		case 'v':
			env->gotwebd_verbose++;
			break;
		default:
			usage();
		}
	}

	/* log to stderr until daemonized */
	log_init(env->gotwebd_debug ? env->gotwebd_debug : 1, LOG_DAEMON);

	argc -= optind;
	if (argc > 0)
		usage();

	ps = calloc(1, sizeof(*ps));
	if (ps == NULL)
		fatal("%s: calloc:", __func__);

	gotwebd_env = env;
	env->gotwebd_ps = ps;
	ps->ps_env = env;
	env->gotwebd_conffile = conffile;

	if (parse_config(env->gotwebd_conffile, env) == -1)
		exit(1);

	if (env->gotwebd_noaction && !env->gotwebd_debug)
		env->gotwebd_debug = 1;

	/* check for root privileges */
	if (env->gotwebd_noaction == 0) {
		if (geteuid())
			fatalx("need root privileges");
	}

	ps->ps_pw = getpwnam(GOTWEBD_USER);
	if (ps->ps_pw == NULL)
		fatalx("unknown user %s", GOTWEBD_USER);

	log_init(env->gotwebd_debug, LOG_DAEMON);
	log_setverbose(env->gotwebd_verbose);

	if (env->gotwebd_noaction)
		ps->ps_noaction = 1;

	ps->ps_instances[PROC_SOCKS] = env->prefork_gotwebd;
	ps->ps_instance = proc_instance;
	if (title != NULL)
		ps->ps_title[proc_id] = title;

	for (proc = 0; proc < nitems(procs); proc++)
		procs[proc].p_chroot = env->httpd_chroot;

	/* only the gotwebd returns */
	proc_init(ps, procs, nitems(procs), argc0, argv, proc_id);

	log_procinit("gotwebd");
	if (!env->gotwebd_debug && daemon(0, 0) == -1)
		fatal("can't daemonize");

	if (ps->ps_noaction == 0)
		log_info("%s startup", getprogname());

	event_init();

	signal_set(&ps->ps_evsigint, SIGINT, gotwebd_sighdlr, ps);
	signal_set(&ps->ps_evsigterm, SIGTERM, gotwebd_sighdlr, ps);
	signal_set(&ps->ps_evsighup, SIGHUP, gotwebd_sighdlr, ps);
	signal_set(&ps->ps_evsigpipe, SIGPIPE, gotwebd_sighdlr, ps);
	signal_set(&ps->ps_evsigusr1, SIGUSR1, gotwebd_sighdlr, ps);

	signal_add(&ps->ps_evsigint, NULL);
	signal_add(&ps->ps_evsigterm, NULL);
	signal_add(&ps->ps_evsighup, NULL);
	signal_add(&ps->ps_evsigpipe, NULL);
	signal_add(&ps->ps_evsigusr1, NULL);

	if (!env->gotwebd_noaction)
		proc_connect(ps);

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
	int id;

	if (env->gotwebd_noaction) {
		fprintf(stderr, "configuration OK\n");
		proc_kill(env->gotwebd_ps);
		exit(0);
	}

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

	for (id = 0; id < PROC_MAX; id++) {
		if (id == privsep_process)
			continue;
		proc_compose(env->gotwebd_ps, id, IMSG_CFG_DONE, NULL, 0);
	}

	return (0);
}

void
gotwebd_configure_done(struct gotwebd *env)
{
	int id;

	if (env->gotwebd_reload == 0) {
		log_warnx("%s: configuration already finished", __func__);
		return;
	}

	env->gotwebd_reload--;
	if (env->gotwebd_reload == 0) {
		for (id = 0; id < PROC_MAX; id++) {
			if (id == privsep_process)
				continue;
			proc_compose(env->gotwebd_ps, id, IMSG_CTL_START,
			    NULL, 0);
		}
	}
}

void
gotwebd_shutdown(void)
{
	proc_kill(gotwebd_env->gotwebd_ps);

	/* unlink(gotwebd_env->gotweb->gotweb_conf.gotweb_unix_socket_name); */
	/* free(gotwebd_env->gotweb); */
	free(gotwebd_env);

	log_warnx("gotwebd terminating");
	exit(0);
}
