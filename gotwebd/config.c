/*
 * Copyright (c) 2020-2021 Tracey Emery <tracey@traceyemery.net>
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <event.h>
#include <fcntl.h>
#include <errno.h>

#include "got_opentemp.h"
#include "got_reference.h"

#include "got_compat.h"

#include "proc.h"
#include "gotwebd.h"

int
config_init(struct gotwebd *env)
{
	struct privsep *ps = env->gotwebd_ps;
	unsigned int what;

	/* Global configuration. */
	if (privsep_process == PROC_GOTWEBD)
		env->prefork_gotwebd = GOTWEBD_NUMPROC;

	ps->ps_what[PROC_GOTWEBD] = CONFIG_ALL;
	ps->ps_what[PROC_SOCKS] = CONFIG_SOCKS;

	/* Other configuration. */
	what = ps->ps_what[privsep_process];
	if (what & CONFIG_SOCKS) {
		env->server_cnt = 0;
		TAILQ_INIT(&env->servers);
		TAILQ_INIT(&env->sockets);
	}
	return 0;
}

int
config_getcfg(struct gotwebd *env, struct imsg *imsg)
{
	/* nothing to do but tell gotwebd configuration is done */
	if (privsep_process != PROC_GOTWEBD)
		proc_compose(env->gotwebd_ps, PROC_GOTWEBD,
		    IMSG_CFG_DONE, NULL, 0);

	return 0;
}

int
config_setserver(struct gotwebd *env, struct server *srv)
{
	struct server ssrv;
	struct privsep *ps = env->gotwebd_ps;

	memcpy(&ssrv, srv, sizeof(ssrv));
	if (proc_compose(ps, PROC_SOCKS, IMSG_CFG_SRV, &ssrv, sizeof(ssrv))
	    == -1)
		fatal("proc_compose");
	return 0;
}

int
config_getserver(struct gotwebd *env, struct imsg *imsg)
{
	struct server *srv;
	uint8_t *p = imsg->data;

	IMSG_SIZE_CHECK(imsg, &srv);

	srv = calloc(1, sizeof(*srv));
	if (srv == NULL)
		fatalx("%s: calloc", __func__);

	if (IMSG_DATA_SIZE(imsg) != sizeof(*srv)) {
		log_debug("%s: imsg size error", __func__);
		free(srv);
		return 1;
	}

	memcpy(srv, p, sizeof(*srv));
	srv->cached_repos = calloc(GOTWEBD_REPO_CACHESIZE,
	    sizeof(*srv->cached_repos));
	if (srv->cached_repos == NULL)
		fatal("%s: calloc", __func__);
	srv->ncached_repos = 0;

	/* log server info */
	log_debug("%s: server=%s fcgi_socket=%s unix_socket=%s", __func__,
	    srv->name, srv->fcgi_socket ? "yes" : "no", srv->unix_socket ?
	    "yes" : "no");

	TAILQ_INSERT_TAIL(&env->servers, srv, entry);

	return 0;
}

int
config_setsock(struct gotwebd *env, struct socket *sock)
{
	struct privsep *ps = env->gotwebd_ps;
	struct socket_conf s;
	int id;
	int fd = -1, n, m;
	struct iovec iov[6];
	size_t c;
	unsigned int what;

	/* open listening sockets */
	if (sockets_privinit(env, sock) == -1)
		return -1;

	for (id = 0; id < PROC_MAX; id++) {
		what = ps->ps_what[id];

		if ((what & CONFIG_SOCKS) == 0 || id == privsep_process)
			continue;

		memcpy(&s, &sock->conf, sizeof(s));

		c = 0;
		iov[c].iov_base = &s;
		iov[c++].iov_len = sizeof(s);

		if (id == PROC_SOCKS) {
			/* XXX imsg code will close the fd after 1st call */
			n = -1;
			proc_range(ps, id, &n, &m);
			for (n = 0; n < m; n++) {
				if (sock->fd == -1)
					fd = -1;
				else if ((fd = dup(sock->fd)) == -1)
					return 1;
				if (proc_composev_imsg(ps, id, n, IMSG_CFG_SOCK,
				    -1, fd, iov, c) != 0) {
					log_warn("%s: failed to compose "
					    "IMSG_CFG_SOCK imsg",
					    __func__);
					return 1;
				}
				if (proc_flush_imsg(ps, id, n) == -1) {
					log_warn("%s: failed to flush "
					    "IMSG_CFG_SOCK imsg",
					    __func__);
					return 1;
				}
			}
		}
	}

	/* Close socket early to prevent fd exhaustion in gotwebd. */
	if (sock->fd != -1) {
		close(sock->fd);
		sock->fd = -1;
	}

	return 0;
}

int
config_getsock(struct gotwebd *env, struct imsg *imsg)
{
	struct socket *sock = NULL;
	struct socket_conf sock_conf;
	uint8_t *p = imsg->data;
	int i;

	IMSG_SIZE_CHECK(imsg, &sock_conf);
	memcpy(&sock_conf, p, sizeof(sock_conf));

	if (IMSG_DATA_SIZE(imsg) != sizeof(sock_conf)) {
		log_debug("%s: imsg size error", __func__);
		return 1;
	}

	/* create a new socket */
	if ((sock = calloc(1, sizeof(*sock))) == NULL) {
		if (imsg->fd != -1)
			close(imsg->fd);
		return 1;
	}

	memcpy(&sock->conf, &sock_conf, sizeof(sock->conf));
	sock->fd = imsg->fd;

	TAILQ_INSERT_TAIL(&env->sockets, sock, entry);

	for (i = 0; i < PRIV_FDS__MAX; i++)
		sock->priv_fd[i] = -1;

	for (i = 0; i < GOTWEB_PACK_NUM_TEMPFILES; i++)
		sock->pack_fds[i] = -1;

	/* log new socket info */
	log_debug("%s: name=%s id=%d server=%s af_type=%s socket_path=%s",
	    __func__, sock->conf.name, sock->conf.id, sock->conf.srv_name,
	    sock->conf.af_type == AF_UNIX ? "unix" :
	    (sock->conf.af_type == AF_INET ? "inet" :
	    (sock->conf.af_type == AF_INET6 ? "inet6" : "unknown")),
	    strlen(sock->conf.unix_socket_name) ?
	    sock->conf.unix_socket_name : "none");

	return 0;
}

int
config_setfd(struct gotwebd *env, struct socket *sock)
{
	struct privsep *ps = env->gotwebd_ps;
	int id, s;
	int fd = -1, n, m, j;
	struct iovec iov[6];
	size_t c;
	unsigned int what;

	log_debug("%s: Allocating %d file descriptors",
	    __func__, PRIV_FDS__MAX + GOTWEB_PACK_NUM_TEMPFILES);

	for (j = 0; j < PRIV_FDS__MAX + GOTWEB_PACK_NUM_TEMPFILES; j++) {
		for (id = 0; id < PROC_MAX; id++) {
			what = ps->ps_what[id];

			if ((what & CONFIG_SOCKS) == 0 || id == privsep_process)
				continue;

			s = sock->conf.id;
			c = 0;
			iov[c].iov_base = &s;
			iov[c++].iov_len = sizeof(s);

			if (id == PROC_SOCKS) {
				/*
				 * XXX imsg code will close the fd
				 * after 1st call
				 */
				n = -1;
				proc_range(ps, id, &n, &m);
				for (n = 0; n < m; n++) {
					fd = got_opentempfd();
					if (fd == -1)
						return 1;
					if (proc_composev_imsg(ps, id, n,
					    IMSG_CFG_FD, -1, fd, iov, c) != 0) {
						log_warn("%s: failed to compose "
						    "IMSG_CFG_FD imsg",
						    __func__);
						return 1;
					}
					if (proc_flush_imsg(ps, id, n) == -1) {
						log_warn("%s: failed to flush "
						    "IMSG_CFG_FD imsg",
						    __func__);
						return 1;
					}
				}
			}
		}

		/* Close fd early to prevent fd exhaustion in gotwebd. */
		if (fd != -1)
			close(fd);
	}
	return 0;
}

int
config_getfd(struct gotwebd *env, struct imsg *imsg)
{
	struct socket *sock;
	uint8_t *p = imsg->data;
	int sock_id, match = 0, i;

	IMSG_SIZE_CHECK(imsg, &sock_id);
	memcpy(&sock_id, p, sizeof(sock_id));

	TAILQ_FOREACH(sock, &env->sockets, entry) {
		const int nfds = (GOTWEB_PACK_NUM_TEMPFILES + PRIV_FDS__MAX);
		for (i = 0; i < nfds; i++) {
			if (i < PRIV_FDS__MAX && sock->priv_fd[i] == -1) {
				log_debug("%s: assigning socket %d priv_fd %d",
				    __func__, sock_id, imsg->fd);
				sock->priv_fd[i] = imsg->fd;
				match = 1;
				break;
			}
			if (sock->pack_fds[i - PRIV_FDS__MAX] == -1) {
				log_debug("%s: assigning socket %d pack_fd %d",
				    __func__, sock_id, imsg->fd);
				sock->pack_fds[i - PRIV_FDS__MAX] = imsg->fd;
				match = 1;
				break;
			}
		}
	}

	if (match)
		return 0;
	else
		return 1;
}
