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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <errno.h>
#include <event.h>
#include <siphash.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <imsg.h>
#include <limits.h>
#include <sha1.h>
#include <sha2.h>
#include <signal.h>
#include <unistd.h>

#include "got_error.h"
#include "got_path.h"

#include "gotd.h"
#include "log.h"
#include "listen.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct gotd_listen_client {
	STAILQ_ENTRY(gotd_listen_client)	 entry;
	uint32_t			 id;
	int				 fd;
	uid_t				 euid;
};
STAILQ_HEAD(gotd_listen_clients, gotd_listen_client);

static struct gotd_listen_clients gotd_listen_clients[GOTD_CLIENT_TABLE_SIZE];
static SIPHASH_KEY clients_hash_key;
static volatile int listen_client_cnt;
static int inflight;

struct gotd_uid_connection_counter {
	STAILQ_ENTRY(gotd_uid_connection_counter) entry;
	uid_t euid;
	int nconnections;
};
STAILQ_HEAD(gotd_client_uids, gotd_uid_connection_counter);
static struct gotd_client_uids gotd_client_uids[GOTD_CLIENT_TABLE_SIZE];
static SIPHASH_KEY uid_hash_key;

static struct {
	pid_t pid;
	const char *title;
	int fd;
	struct gotd_imsgev iev;
	struct gotd_imsgev pause;
	struct gotd_uid_connection_limit *connection_limits;
	size_t nconnection_limits;
} gotd_listen;

static int inflight;

static void listen_shutdown(void);

static void
listen_sighdlr(int sig, short event, void *arg)
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
		listen_shutdown();
		/* NOTREACHED */
		break;
	default:
		fatalx("unexpected signal");
	}
}

static uint64_t
client_hash(uint32_t client_id)
{
	return SipHash24(&clients_hash_key, &client_id, sizeof(client_id));
}

static void
add_client(struct gotd_listen_client *client)
{
	uint64_t slot = client_hash(client->id) % nitems(gotd_listen_clients);
	STAILQ_INSERT_HEAD(&gotd_listen_clients[slot], client, entry);
	listen_client_cnt++;
}

static struct gotd_listen_client *
find_client(uint32_t client_id)
{
	uint64_t slot;
	struct gotd_listen_client *c;

	slot = client_hash(client_id) % nitems(gotd_listen_clients);
	STAILQ_FOREACH(c, &gotd_listen_clients[slot], entry) {
		if (c->id == client_id)
			return c;
	}

	return NULL;
}

static uint32_t
get_client_id(void)
{
	int duplicate = 0;
	uint32_t id;

	do {
		id = arc4random();
		duplicate = (find_client(id) != NULL);
	} while (duplicate || id == 0);

	return id;
}

static uint64_t
uid_hash(uid_t euid)
{
	return SipHash24(&uid_hash_key, &euid, sizeof(euid));
}

static void
add_uid_connection_counter(struct gotd_uid_connection_counter *counter)
{
	uint64_t slot = uid_hash(counter->euid) % nitems(gotd_client_uids);
	STAILQ_INSERT_HEAD(&gotd_client_uids[slot], counter, entry);
}

static void
remove_uid_connection_counter(struct gotd_uid_connection_counter *counter)
{
	uint64_t slot = uid_hash(counter->euid) % nitems(gotd_client_uids);
	STAILQ_REMOVE(&gotd_client_uids[slot], counter,
	    gotd_uid_connection_counter, entry);
}

static struct gotd_uid_connection_counter *
find_uid_connection_counter(uid_t euid)
{
	uint64_t slot;
	struct gotd_uid_connection_counter *c;

	slot = uid_hash(euid) % nitems(gotd_client_uids);
	STAILQ_FOREACH(c, &gotd_client_uids[slot], entry) {
		if (c->euid == euid)
			return c;
	}

	return NULL;
}

static const struct got_error *
disconnect(struct gotd_listen_client *client)
{
	struct gotd_uid_connection_counter *counter;
	uint64_t slot;
	int client_fd;

	log_debug("client on fd %d disconnecting", client->fd);

	slot = client_hash(client->id) % nitems(gotd_listen_clients);
	STAILQ_REMOVE(&gotd_listen_clients[slot], client,
	    gotd_listen_client, entry);

	counter = find_uid_connection_counter(client->euid);
	if (counter) {
		if (counter->nconnections > 0)
			counter->nconnections--;
		if (counter->nconnections == 0) {
			remove_uid_connection_counter(counter);
			free(counter);
		}
	}

	client_fd = client->fd;
	free(client);
	inflight--;
	listen_client_cnt--;
	if (close(client_fd) == -1)
		return got_error_from_errno("close");

	return NULL;
}

static int
accept_reserve(int fd, struct sockaddr *addr, socklen_t *addrlen,
    int reserve, volatile int *counter)
{
	int ret;

	if (getdtablecount() + reserve +
	    ((*counter + 1) * GOTD_FD_NEEDED) >= getdtablesize()) {
		log_debug("inflight fds exceeded");
		errno = EMFILE;
		return -1;
	}

	if ((ret = accept4(fd, addr, addrlen,
	    SOCK_NONBLOCK | SOCK_CLOEXEC)) > -1) {
		(*counter)++;
	}

	return ret;
}

static void
gotd_accept_paused(int fd, short event, void *arg)
{
	event_add(&gotd_listen.iev.ev, NULL);
}

static void
gotd_accept(int fd, short event, void *arg)
{
	struct gotd_imsgev *iev = arg;
	struct sockaddr_storage ss;
	struct timeval backoff;
	socklen_t len;
	int s = -1;
	struct gotd_listen_client *client = NULL;
	struct gotd_uid_connection_counter *counter = NULL;
	struct gotd_imsg_connect iconn;
	uid_t euid;
	gid_t egid;

	backoff.tv_sec = 1;
	backoff.tv_usec = 0;

	if (event_add(&gotd_listen.iev.ev, NULL) == -1) {
		log_warn("event_add");
		return;
	}
	if (event & EV_TIMEOUT)
		return;

	len = sizeof(ss);

	/* Other backoff conditions apart from EMFILE/ENFILE? */
	s = accept_reserve(fd, (struct sockaddr *)&ss, &len, GOTD_FD_RESERVE,
	    &inflight);
	if (s == -1) {
		switch (errno) {
		case EINTR:
		case EWOULDBLOCK:
		case ECONNABORTED:
			return;
		case EMFILE:
		case ENFILE:
			event_del(&gotd_listen.iev.ev);
			evtimer_add(&gotd_listen.pause.ev, &backoff);
			return;
		default:
			log_warn("accept");
			return;
		}
	}

	if (listen_client_cnt >= GOTD_MAXCLIENTS)
		goto err;

	if (getpeereid(s, &euid, &egid) == -1) {
		log_warn("getpeerid");
		goto err;
	}

	counter = find_uid_connection_counter(euid);
	if (counter == NULL) {
		counter = calloc(1, sizeof(*counter));
		if (counter == NULL) {
			log_warn("%s: calloc", __func__);
			goto err;
		}
		counter->euid = euid;
		counter->nconnections = 1;
		add_uid_connection_counter(counter);
	} else {
		int max_connections = GOTD_MAX_CONN_PER_UID;
		struct gotd_uid_connection_limit *limit;

		limit = gotd_find_uid_connection_limit(
		    gotd_listen.connection_limits,
		    gotd_listen.nconnection_limits, euid);
		if (limit)
			max_connections = limit->max_connections;

		if (counter->nconnections >= max_connections) {
			log_warnx("maximum connections exceeded for uid %d",
			    euid);
			goto err;
		}
		counter->nconnections++;
	}

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		log_warn("%s: calloc", __func__);
		goto err;
	}
	client->id = get_client_id();
	client->fd = s;
	client->euid = euid;
	s = -1;
	add_client(client);
	log_debug("%s: new client connected on fd %d uid %d gid %d", __func__,
	    client->fd, euid, egid);

	memset(&iconn, 0, sizeof(iconn));
	iconn.client_id = client->id;
	iconn.euid = euid;
	iconn.egid = egid;
	s = dup(client->fd);
	if (s == -1) {
		log_warn("%s: dup", __func__);
		goto err;
	}
	if (gotd_imsg_compose_event(iev, GOTD_IMSG_CONNECT, PROC_LISTEN, s,
	    &iconn, sizeof(iconn)) == -1) {
		log_warn("imsg compose CONNECT");
		goto err;
	}

	return;
err:
	inflight--;
	if (client)
		disconnect(client);
	if (s != -1)
		close(s);
}

static const struct got_error *
recv_disconnect(struct imsg *imsg)
{
	struct gotd_imsg_disconnect idisconnect;
	size_t datalen;
	struct gotd_listen_client *client = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(idisconnect))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&idisconnect, imsg->data, sizeof(idisconnect));

	log_debug("client disconnecting");

	client = find_client(idisconnect.client_id);
	if (client == NULL)
		return got_error(GOT_ERR_CLIENT_ID);

	return disconnect(client);
}

static void
listen_dispatch(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	int shut = 0;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	if (event & EV_WRITE) {
		n = msgbuf_write(&ibuf->w);
		if (n == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_DISCONNECT:
			err = recv_disconnect(&imsg);
			if (err)
				log_warnx("disconnect: %s", err->msg);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);
	}

	if (!shut) {
		gotd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
listen_main(const char *title, int gotd_socket,
    struct gotd_uid_connection_limit *connection_limits,
    size_t nconnection_limits)
{
	struct gotd_imsgev iev;
	struct event evsigint, evsigterm, evsighup, evsigusr1;

	arc4random_buf(&clients_hash_key, sizeof(clients_hash_key));
	arc4random_buf(&uid_hash_key, sizeof(uid_hash_key));

	gotd_listen.title = title;
	gotd_listen.pid = getpid();
	gotd_listen.fd = gotd_socket;
	gotd_listen.connection_limits = connection_limits;
	gotd_listen.nconnection_limits = nconnection_limits;

	signal_set(&evsigint, SIGINT, listen_sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, listen_sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, listen_sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, listen_sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);

	imsg_init(&iev.ibuf, GOTD_FILENO_MSG_PIPE);
	iev.handler = listen_dispatch;
	iev.events = EV_READ;
	iev.handler_arg = NULL;
	event_set(&iev.ev, iev.ibuf.fd, EV_READ, listen_dispatch, &iev);
	if (event_add(&iev.ev, NULL) == -1)
		fatalx("event add");

	event_set(&gotd_listen.iev.ev, gotd_listen.fd, EV_READ | EV_PERSIST,
	    gotd_accept, &iev);
	if (event_add(&gotd_listen.iev.ev, NULL))
		fatalx("event add");
	evtimer_set(&gotd_listen.pause.ev, gotd_accept_paused, NULL);

	event_dispatch();

	listen_shutdown();
}

static void
listen_shutdown(void)
{
	log_debug("%s: shutting down", gotd_listen.title);

	free(gotd_listen.connection_limits);
	if (gotd_listen.fd != -1)
		close(gotd_listen.fd);

	exit(0);
}
