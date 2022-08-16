/*
 * Copyright (c) 2016, 2019, 2020-2021 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2015 Mike Larkin <mlarkin@openbsd.org>
 * Copyright (c) 2013 David Gwynne <dlg@openbsd.org>
 * Copyright (c) 2013 Florian Obser <florian@openbsd.org>
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
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/un.h>

#include <net/if.h>
#include <netinet/in.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "got_error.h"
#include "got_opentemp.h"

#include "proc.h"
#include "gotwebd.h"

#include "got_compat.h"

#define SOCKS_BACKLOG 5
#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))


volatile int client_cnt;

struct timeval	timeout = { TIMEOUT_DEFAULT, 0 };

void	 sockets_sighdlr(int, short, void *);
void	 sockets_run(struct privsep *, struct privsep_proc *, void *);
void	 sockets_launch(void);
void	 sockets_purge(struct gotwebd *);
void	 sockets_accept_paused(int, short, void *);
void	 sockets_dup_new_socket(struct socket *, struct socket *);
void	 sockets_rlimit(int);


int	 sockets_dispatch_gotwebd(int, struct privsep_proc *, struct imsg *);
int	 sockets_unix_socket_listen(struct privsep *, struct socket *);
int	 sockets_create_socket(struct addresslist *, in_port_t);
int	 sockets_accept_reserve(int, struct sockaddr *, socklen_t *, int,
	    volatile int *);

struct socket
	*sockets_conf_new_socket(struct gotwebd *, struct server *, int, int,
	    int);

int cgi_inflight = 0;

static struct privsep_proc procs[] = {
	{ "gotwebd",	PROC_GOTWEBD,	sockets_dispatch_gotwebd  },
};

void
sockets(struct privsep *ps, struct privsep_proc *p)
{
	proc_run(ps, p, procs, nitems(procs), sockets_run, NULL);
}

void
sockets_run(struct privsep *ps, struct privsep_proc *p, void *arg)
{
	if (config_init(ps->ps_env) == -1)
		fatal("failed to initialize configuration");

	p->p_shutdown = sockets_shutdown;

	sockets_rlimit(-1);

	signal_del(&ps->ps_evsigchld);
	signal_set(&ps->ps_evsigchld, SIGCHLD, sockets_sighdlr, ps);
	signal_add(&ps->ps_evsigchld, NULL);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath inet recvfd proc exec sendfd",
	    NULL) == -1)
		fatal("pledge");
#endif
}

void
sockets_parse_sockets(struct gotwebd *env)
{
	struct server *srv;
	struct socket *sock, *new_sock = NULL;
	struct address *a;
	int sock_id = 0, ipv4 = 0, ipv6 = 0;

	TAILQ_FOREACH(srv, &env->servers, entry) {
		if (srv->unix_socket) {
			sock_id++;
			new_sock = sockets_conf_new_socket(env, srv,
			    sock_id, UNIX, 0);
			TAILQ_INSERT_TAIL(&env->sockets, new_sock, entry);
		}

		if (srv->fcgi_socket) {
			sock_id++;
			new_sock = sockets_conf_new_socket(env, srv,
			    sock_id, FCGI, 0);
			TAILQ_INSERT_TAIL(&env->sockets, new_sock, entry);

			/* add ipv6 children */
			TAILQ_FOREACH(sock, &env->sockets, entry) {
				ipv4 = ipv6 = 0;

				TAILQ_FOREACH(a, &sock->conf.al, entry) {
					if (a->ss.ss_family == AF_INET)
						ipv4 = 1;
					if (a->ss.ss_family == AF_INET6)
						ipv6 = 1;
				}

				/* create ipv6 sock */
				if (ipv4 == 1 && ipv6 == 1) {
					sock_id++;
					sock->conf.child_id = sock_id;
					new_sock = sockets_conf_new_socket(env,
					    srv, sock_id, FCGI, 1);
					sockets_dup_new_socket(sock, new_sock);
					TAILQ_INSERT_TAIL(&env->sockets,
					    new_sock, entry);
					continue;
				}
			}
		}
	}
}

void
sockets_dup_new_socket(struct socket *p_sock, struct socket *sock)
{
	struct address *a, *acp;
	int n;

	sock->conf.parent_id = p_sock->conf.id;
	sock->conf.ipv4 = 0;
	sock->conf.ipv6 = 1;

	memcpy(&sock->conf.srv_name, p_sock->conf.srv_name,
	    sizeof(sock->conf.srv_name));

	n = snprintf(sock->conf.name, GOTWEBD_MAXTEXT, "%s_child",
	    p_sock->conf.srv_name);
	if (n < 0 || (size_t)n >= GOTWEBD_MAXTEXT) {
		free(p_sock);
		free(sock);
		fatalx("%s: snprintf", __func__);
	}

	TAILQ_FOREACH(a, &p_sock->conf.al, entry) {
		if (a->ss.ss_family == AF_INET)
			continue;

		if ((acp = calloc(1, sizeof(*acp))) == NULL)
			fatal("%s: calloc", __func__);
		memcpy(&acp->ss, &a->ss, sizeof(acp->ss));
		acp->ipproto = a->ipproto;
		acp->prefixlen = a->prefixlen;
		acp->port = a->port;
		if (strlen(a->ifname) != 0) {
			if (strlcpy(acp->ifname, a->ifname,
			    sizeof(acp->ifname)) >= sizeof(acp->ifname)) {
				fatalx("%s: interface name truncated",
				    __func__);
			}
		}

		TAILQ_INSERT_TAIL(&sock->conf.al, acp, entry);
	}
}

struct socket *
sockets_conf_new_socket(struct gotwebd *env, struct server *srv, int id,
    int type, int is_dup)
{
	struct socket *sock;
	struct address *a, *acp;
	int n;

	if ((sock = calloc(1, sizeof(*sock))) == NULL)
		fatalx("%s: calloc", __func__);

	TAILQ_INIT(&sock->conf.al);

	sock->conf.parent_id = 0;
	sock->conf.id = id;

	sock->fd = -1;

	sock->conf.type = type;

	if (type == UNIX) {
		if (strlcpy(sock->conf.unix_socket_name,
		    srv->unix_socket_name,
		    sizeof(sock->conf.unix_socket_name)) >=
		    sizeof(sock->conf.unix_socket_name)) {
			free(sock);
			fatalx("%s: strlcpy", __func__);
		}
	} else
		sock->conf.ipv4 = 1;

	sock->conf.fcgi_socket_port = srv->fcgi_socket_port;

	if (is_dup)
		goto done;

	n = snprintf(sock->conf.name, GOTWEBD_MAXTEXT, "%s_parent",
	    srv->name);
	if (n < 0 || (size_t)n >= GOTWEBD_MAXTEXT) {
		free(sock);
		fatalx("%s: snprintf", __func__);
	}

	if (strlcpy(sock->conf.srv_name, srv->name,
	    sizeof(sock->conf.srv_name)) >= sizeof(sock->conf.srv_name)) {
		free(sock);
		fatalx("%s: strlcpy", __func__);
	}

	TAILQ_FOREACH(a, &srv->al, entry) {
		if ((acp = calloc(1, sizeof(*acp))) == NULL) {
			free(sock);
			fatal("%s: calloc", __func__);
		}
		memcpy(&acp->ss, &a->ss, sizeof(acp->ss));
		acp->ipproto = a->ipproto;
		acp->prefixlen = a->prefixlen;
		acp->port = a->port;
		if (strlen(a->ifname) != 0) {
			if (strlcpy(acp->ifname, a->ifname,
			    sizeof(acp->ifname)) >= sizeof(acp->ifname)) {
				fatalx("%s: interface name truncated",
				    __func__);
			}
		}

		TAILQ_INSERT_TAIL(&sock->conf.al, acp, entry);
	}
done:
	return (sock);
}

void
sockets_launch(void)
{
	struct socket *sock;

	TAILQ_FOREACH(sock, &gotwebd_env->sockets, entry) {
		log_debug("%s: configuring socket %d (%d)", __func__,
		    sock->conf.id, sock->fd);

		event_set(&sock->ev, sock->fd, EV_READ | EV_PERSIST,
		    sockets_socket_accept, sock);

		if (event_add(&sock->ev, NULL))
			fatalx("event add sock");

		evtimer_set(&sock->pause, sockets_accept_paused, sock);

		log_debug("%s: running socket listener %d", __func__,
		    sock->conf.id);
	}
}

void
sockets_purge(struct gotwebd *env)
{
	struct socket *sock, *tsock;

	/* shutdown and remove sockets */
	TAILQ_FOREACH_SAFE(sock, &env->sockets, entry, tsock) {
		if (event_initialized(&sock->ev))
			event_del(&sock->ev);
		if (evtimer_initialized(&sock->evt))
			evtimer_del(&sock->evt);
		if (evtimer_initialized(&sock->pause))
			evtimer_del(&sock->pause);
		if (sock->fd != -1)
			close(sock->fd);
		TAILQ_REMOVE(&env->sockets, sock, entry);
	}
}

int
sockets_dispatch_gotwebd(int fd, struct privsep_proc *p, struct imsg *imsg)
{
	struct privsep *ps = p->p_ps;
	int res = 0, cmd = 0, verbose;

	switch (imsg->hdr.type) {
	case IMSG_CFG_SRV:
		config_getserver(gotwebd_env, imsg);
		break;
	case IMSG_CFG_SOCK:
		config_getsock(gotwebd_env, imsg);
		break;
	case IMSG_CFG_FD:
		config_getfd(gotwebd_env, imsg);
		break;
	case IMSG_CFG_DONE:
		config_getcfg(gotwebd_env, imsg);
		break;
	case IMSG_CTL_START:
		sockets_launch();
		break;
	case IMSG_CTL_VERBOSE:
		IMSG_SIZE_CHECK(imsg, &verbose);
		memcpy(&verbose, imsg->data, sizeof(verbose));
		log_setverbose(verbose);
		break;
	default:
		return -1;
	}

	switch (cmd) {
	case 0:
		break;
	default:
		if (proc_compose_imsg(ps, PROC_GOTWEBD, -1, cmd,
		    imsg->hdr.peerid, -1, &res, sizeof(res)) == -1)
			return -1;
		break;
	}

	return 0;
}

void
sockets_sighdlr(int sig, short event, void *arg)
{
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
	case SIGCHLD:
		break;
	default:
		log_info("SIGNAL: %d", sig);
		fatalx("unexpected signal");
	}
}

void
sockets_shutdown(void)
{
	struct server *srv, *tsrv;
	struct socket *sock, *tsock;

	sockets_purge(gotwebd_env);

	/* clean sockets */
	TAILQ_FOREACH_SAFE(sock, &gotwebd_env->sockets, entry, tsock) {
		TAILQ_REMOVE(&gotwebd_env->sockets, sock, entry);
		close(sock->fd);
		free(sock);
	}

	/* clean servers */
	TAILQ_FOREACH_SAFE(srv, &gotwebd_env->servers, entry, tsrv)
		free(srv);

	free(gotwebd_env);
}

int
sockets_privinit(struct gotwebd *env, struct socket *sock)
{
	struct privsep *ps = env->gotwebd_ps;

	if (sock->conf.type == UNIX) {
		log_debug("%s: initializing unix socket %s", __func__,
		    sock->conf.unix_socket_name);
		sock->fd = sockets_unix_socket_listen(ps, sock);
		if (sock->fd == -1) {
			log_warnx("%s: create unix socket failed", __func__);
			return -1;
		}
	}

	if (sock->conf.type == FCGI) {
		log_debug("%s: initializing fcgi socket for %s", __func__,
		    sock->conf.name);
		sock->fd = sockets_create_socket(&sock->conf.al,
		    sock->conf.fcgi_socket_port);
		if (sock->fd == -1) {
			log_warnx("%s: create unix socket failed", __func__);
			return -1;
		}
	}

	return 0;
}

int
sockets_unix_socket_listen(struct privsep *ps, struct socket *sock)
{
	struct gotwebd *env = ps->ps_env;
	struct sockaddr_un sun;
	struct socket *tsock;
	int u_fd = -1;
	mode_t old_umask, mode;

	TAILQ_FOREACH(tsock, &env->sockets, entry) {
		if (strcmp(tsock->conf.unix_socket_name,
		    sock->conf.unix_socket_name) == 0 &&
		    tsock->fd != -1)
			return (tsock->fd);
	}

	/* TA: FIXME:  this needs upstreaming. */
	int socket_flags = SOCK_STREAM | SOCK_NONBLOCK;
#ifdef SOCK_CLOEXEC
	socket_flags |= SOCK_CLOEXEC;
#endif
	u_fd = socket(AF_UNIX, socket_flags, 0);
	if (u_fd == -1) {
		log_warn("%s: socket", __func__);
		return -1;
	}

	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, sock->conf.unix_socket_name,
	    sizeof(sun.sun_path)) >= sizeof(sun.sun_path)) {
		log_warn("%s: %s name too long", __func__,
		    sock->conf.unix_socket_name);
		close(u_fd);
		return -1;
	}

	if (unlink(sock->conf.unix_socket_name) == -1) {
		if (errno != ENOENT) {
			log_warn("%s: unlink %s", __func__,
			    sock->conf.unix_socket_name);
			close(u_fd);
			return -1;
		}
	}

	old_umask = umask(S_IXUSR|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH);
	mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP;

	if (bind(u_fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		log_warn("%s: bind: %s", __func__, sock->conf.unix_socket_name);
		close(u_fd);
		(void)umask(old_umask);
		return -1;
	}

	(void)umask(old_umask);

	if (chmod(sock->conf.unix_socket_name, mode) == -1) {
		log_warn("%s: chmod", __func__);
		close(u_fd);
		(void)unlink(sock->conf.unix_socket_name);
		return -1;
	}

	if (chown(sock->conf.unix_socket_name, ps->ps_pw->pw_uid,
	    ps->ps_pw->pw_gid) == -1) {
		log_warn("%s: chown", __func__);
		close(u_fd);
		(void)unlink(sock->conf.unix_socket_name);
		return -1;
	}

	if (listen(u_fd, SOCKS_BACKLOG) == -1) {
		log_warn("%s: listen", __func__);
		return -1;
	}

	return u_fd;
}

int
sockets_create_socket(struct addresslist *al, in_port_t port)
{
	struct addrinfo hints;
	struct address *a;
	int fd = -1, o_val = 1, flags;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_PASSIVE;

	TAILQ_FOREACH(a, al, entry) {
		switch (a->ss.ss_family) {
		case AF_INET:
			((struct sockaddr_in *)(&a->ss))->sin_port = port;
			break;
		case AF_INET6:
			((struct sockaddr_in6 *)(&a->ss))->sin6_port = port;
			break;
		default:
			log_warnx("%s: unknown address family", __func__);
			goto fail;
		}

		fd = socket(a->ss.ss_family, hints.ai_socktype,
		    a->ipproto);
			log_debug("%s: opening socket (%d) for %s", __func__,
			    fd, a->ifname);

		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &o_val,
		    sizeof(int)) == -1) {
			log_warn("%s: setsockopt error", __func__);
			return -1;
		}

		/* non-blocking */
		flags = fcntl(fd, F_GETFL);
		flags |= O_NONBLOCK;
		fcntl(fd, F_SETFL, flags);

		/* TA: 'sizeof a' vs a->ss.len */ 
		if (bind(fd, (struct sockaddr *)&a->ss, sizeof a) == -1) {
			close(fd);
			log_info("%s: can't bind to port %d", __func__,
			    ntohs(port));
			goto fail;
		}

		if (listen(fd, SOMAXCONN) == -1) {
			log_warn("%s, unable to listen on socket", __func__);
			goto fail;
		}
	}

	free(a);
	return (fd);
fail:
	free(a);
	return -1;
}

int
sockets_accept_reserve(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
    int reserve, volatile int *counter)
{
	int ret;

	if (getdtablecount() + reserve +
	    ((*counter + 1) * FD_NEEDED) >= getdtablesize()) {
		log_debug("inflight fds exceeded");
		errno = EMFILE;
		return -1;
	}
/* TA:  This needs fixing upstream. */
#ifdef __APPLE__
	ret = accept(sockfd, addr, addrlen);
#else
	ret = accept4(sockfd, addr, addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
#endif

	if (ret > -1) {
		(*counter)++;
		log_debug("inflight incremented, now %d", *counter);
	}

	return ret;
}

void
sockets_accept_paused(int fd, short events, void *arg)
{
	struct socket *sock = (struct socket *)arg;

	event_add(&sock->ev, NULL);
}

void
sockets_socket_accept(int fd, short event, void *arg)
{
	struct socket *sock = (struct socket *)arg;
	struct sockaddr_storage ss;
	struct timeval backoff;
	struct request *c = NULL;
	socklen_t len;
	int s;

	backoff.tv_sec = 1;
	backoff.tv_usec = 0;

	event_add(&sock->ev, NULL);
	if (event & EV_TIMEOUT)
		return;

	len = sizeof(ss);

	s = sockets_accept_reserve(fd, (struct sockaddr *)&ss, &len,
	    FD_RESERVE, &cgi_inflight);

	if (s == -1) {
		switch (errno) {
		case EINTR:
		case EWOULDBLOCK:
		case ECONNABORTED:
			return;
		case EMFILE:
		case ENFILE:
			event_del(&sock->ev);
			evtimer_add(&sock->pause, &backoff);
			return;
		default:
			log_warn("%s: accept", __func__);
		}
	}

	if (client_cnt > GOTWEBD_MAXCLIENTS)
		goto err;

	c = calloc(1, sizeof(struct request));
	if (c == NULL) {
		log_warn("%s", __func__);
		close(s);
		cgi_inflight--;
		return;
	}

	c->fd = s;
	c->sock = sock;
	memcpy(c->priv_fd, sock->priv_fd, sizeof(c->priv_fd));
	c->buf_pos = 0;
	c->buf_len = 0;
	c->request_started = 0;
	c->sock->client_status = CLIENT_CONNECT;

	event_set(&c->ev, s, EV_READ, fcgi_request, c);
	event_add(&c->ev, NULL);

	evtimer_set(&c->tmo, fcgi_timeout, c);
	evtimer_add(&c->tmo, &timeout);

	client_cnt++;

	return;
err:
	cgi_inflight--;
	close(s);
	if (c != NULL)
		free(c);
}

void
sockets_rlimit(int maxfd)
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_NOFILE, &rl) == -1)
		fatal("%s: failed to get resource limit", __func__);
	log_debug("%s: max open files %llu", __func__,
	    (unsigned long long)rl.rlim_max);

	/*
	 * Allow the maximum number of open file descriptors for this
	 * login class (which should be the class "daemon" by default).
	 */
	if (maxfd == -1)
		rl.rlim_cur = rl.rlim_max;
	else
		rl.rlim_cur = MAXIMUM(rl.rlim_max, (rlim_t)maxfd);
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
		fatal("%s: failed to set resource limit", __func__);
}
