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

#include "got_compat.h"

#include <sys/queue.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/resource.h>

#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <limits.h>
#include <pwd.h>
#include <imsg.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "got_error.h"
#include "got_opentemp.h"
#include "got_path.h"
#include "got_repository.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_diff.h"

#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_object_cache.h"
#include "got_lib_hash.h"
#include "got_lib_gitproto.h"
#include "got_lib_pack.h"
#include "got_lib_repository.h"

#include "gotd.h"
#include "log.h"
#include "listen.h"
#include "auth.h"
#include "session_read.h"
#include "session_write.h"
#include "repo_read.h"
#include "repo_write.h"
#include "notify.h"
#include "secrets.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

enum gotd_client_state {
	GOTD_CLIENT_STATE_NEW,
	GOTD_CLIENT_STATE_ACCESS_GRANTED,
};

struct gotd_child_proc {
	pid_t				 pid;
	enum gotd_procid		 type;
	char				 repo_name[NAME_MAX];
	char				 repo_path[PATH_MAX];
	int				 pipe[2];
	struct gotd_imsgev		 iev;
	struct event			 tmo;

	TAILQ_ENTRY(gotd_child_proc)	 entry;
};
TAILQ_HEAD(gotd_procs, gotd_child_proc) procs;

struct gotd_client {
	STAILQ_ENTRY(gotd_client)	 entry;
	enum gotd_client_state		 state;
	uint32_t			 id;
	int				 fd;
	struct gotd_imsgev		 iev;
	struct event			 tmo;
	uid_t				 euid;
	gid_t				 egid;
	char				*username;
	struct gotd_child_proc		*repo;
	struct gotd_child_proc		*auth;
	struct gotd_child_proc		*session;
	int				 required_auth;
};
STAILQ_HEAD(gotd_clients, gotd_client);

static struct gotd_clients gotd_clients[GOTD_CLIENT_TABLE_SIZE];
static SIPHASH_KEY clients_hash_key;
volatile int client_cnt;
static struct timeval auth_timeout = { 5, 0 };
static struct gotd gotd;

void gotd_sighdlr(int sig, short event, void *arg);
static void gotd_shutdown(void);
static const struct got_error *start_session_child(struct gotd_client *,
    struct gotd_repo *, char *, const char *, int, int);
static const struct got_error *start_repo_child(struct gotd_client *,
    enum gotd_procid, struct gotd_repo *, char *, const char *, int, int);
static const struct got_error *start_auth_child(struct gotd_client *, int,
    struct gotd_repo *, char *, const char *, int, int);
static void kill_proc(struct gotd_child_proc *, int);
static void disconnect(struct gotd_client *);
static void drop_privs(struct passwd *);

__dead static void
usage(void)
{
	fprintf(stderr, "usage: %s [-dnv] [-f config-file] [-s secrets]\n",
	    getprogname());
	exit(1);
}

static void
drop_privs(struct passwd *pw)
{
	/* Drop root privileges. */
	if (setgid(pw->pw_gid) == -1)
		fatal("setgid %d failed", pw->pw_gid);
	if (setuid(pw->pw_uid) == -1)
		fatal("setuid %d failed", pw->pw_uid);
}

static int
unix_socket_listen(const char *unix_socket_path, uid_t uid, gid_t gid)
{
	struct sockaddr_un sun;
	int fd = -1;
	mode_t old_umask, mode;
	int sock_flags = SOCK_STREAM | SOCK_NONBLOCK;

#ifdef SOCK_CLOEXEC
	sock_flags |= SOCK_CLOEXEC;
#endif

	fd = socket(AF_UNIX, sock_flags, 0);
	if (fd == -1) {
		log_warn("socket");
		return -1;
	}

	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, unix_socket_path,
	    sizeof(sun.sun_path)) >= sizeof(sun.sun_path)) {
		log_warnx("%s: name too long", unix_socket_path);
		close(fd);
		return -1;
	}

	if (unlink(unix_socket_path) == -1) {
		if (errno != ENOENT) {
			log_warn("unlink %s", unix_socket_path);
			close(fd);
			return -1;
		}
	}

	old_umask = umask(S_IXUSR|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH);
	mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;

	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		log_warn("bind: %s", unix_socket_path);
		close(fd);
		umask(old_umask);
		return -1;
	}

	umask(old_umask);

	if (chmod(unix_socket_path, mode) == -1) {
		log_warn("chmod %o %s", mode, unix_socket_path);
		close(fd);
		unlink(unix_socket_path);
		return -1;
	}

	if (chown(unix_socket_path, uid, gid) == -1) {
		log_warn("chown %s uid=%d gid=%d", unix_socket_path, uid, gid);
		close(fd);
		unlink(unix_socket_path);
		return -1;
	}

	if (listen(fd, GOTD_UNIX_SOCKET_BACKLOG) == -1) {
		log_warn("listen");
		close(fd);
		unlink(unix_socket_path);
		return -1;
	}

	return fd;
}

static uint64_t
client_hash(uint32_t client_id)
{
	return SipHash24(&clients_hash_key, &client_id, sizeof(client_id));
}

static void
add_client(struct gotd_client *client)
{
	uint64_t slot = client_hash(client->id) % nitems(gotd_clients);
	STAILQ_INSERT_HEAD(&gotd_clients[slot], client, entry);
	client_cnt++;
}

static struct gotd_client *
find_client(uint32_t client_id)
{
	uint64_t slot;
	struct gotd_client *c;

	slot = client_hash(client_id) % nitems(gotd_clients);
	STAILQ_FOREACH(c, &gotd_clients[slot], entry) {
		if (c->id == client_id)
			return c;
	}

	return NULL;
}

static struct gotd_client *
find_client_by_proc_fd(int fd)
{
	uint64_t slot;

	for (slot = 0; slot < nitems(gotd_clients); slot++) {
		struct gotd_client *c;

		STAILQ_FOREACH(c, &gotd_clients[slot], entry) {
			if (c->repo && c->repo->iev.ibuf.fd == fd)
				return c;
			if (c->auth && c->auth->iev.ibuf.fd == fd)
				return c;
			if (c->session && c->session->iev.ibuf.fd == fd)
				return c;
		}
	}

	return NULL;
}

static int
client_is_reading(struct gotd_client *client)
{
	return (client->required_auth &
	    (GOTD_AUTH_READ | GOTD_AUTH_WRITE)) == GOTD_AUTH_READ;
}

static int
client_is_writing(struct gotd_client *client)
{
	return (client->required_auth &
	    (GOTD_AUTH_READ | GOTD_AUTH_WRITE)) ==
	    (GOTD_AUTH_READ | GOTD_AUTH_WRITE);
}

static const struct got_error *
ensure_client_is_not_writing(struct gotd_client *client)
{
	if (client_is_writing(client)) {
		return got_error_fmt(GOT_ERR_BAD_PACKET,
		    "uid %d made a read-request but is writing to "
		    "a repository", client->euid);
	}

	return NULL;
}

static const struct got_error *
ensure_client_is_not_reading(struct gotd_client *client)
{
	if (client_is_reading(client)) {
		return got_error_fmt(GOT_ERR_BAD_PACKET,
		    "uid %d made a write-request but is reading from "
		    "a repository", client->euid);
	}

	return NULL;
}

static void
proc_done(struct gotd_child_proc *proc)
{
	struct gotd_client *client;

	TAILQ_REMOVE(&procs, proc, entry);

	client = find_client_by_proc_fd(proc->iev.ibuf.fd);
	if (client != NULL) {
		if (proc == client->repo)
			client->repo = NULL;
		if (proc == client->auth)
			client->auth = NULL;
		if (proc == client->session)
			client->session = NULL;
		disconnect(client);
	}

	if (proc == gotd.notify_proc)
		gotd.notify_proc = NULL;

	evtimer_del(&proc->tmo);

	if (proc->iev.ibuf.fd != -1) {
		event_del(&proc->iev.ev);
		msgbuf_clear(&proc->iev.ibuf.w);
		close(proc->iev.ibuf.fd);
	}

	free(proc);
}

static void
kill_repo_proc(struct gotd_client *client)
{
	if (client->repo == NULL)
		return;

	kill_proc(client->repo, 0);
	client->repo = NULL;
}

static void
kill_auth_proc(struct gotd_client *client)
{
	if (client->auth == NULL)
		return;

	kill_proc(client->auth, 0);
	client->auth = NULL;
}

static void
kill_session_proc(struct gotd_client *client)
{
	if (client->session == NULL)
		return;

	kill_proc(client->session, 0);
	client->session = NULL;
}

static void
disconnect(struct gotd_client *client)
{
	struct gotd_imsg_disconnect idisconnect;
	struct gotd_child_proc *listen_proc = gotd.listen_proc;
	uint64_t slot;

	log_debug("uid %d: disconnecting", client->euid);

	kill_auth_proc(client);
	kill_session_proc(client);
	kill_repo_proc(client);

	idisconnect.client_id = client->id;
	if (gotd_imsg_compose_event(&listen_proc->iev,
	    GOTD_IMSG_DISCONNECT, PROC_GOTD, -1,
	    &idisconnect, sizeof(idisconnect)) == -1)
		log_warn("imsg compose DISCONNECT");

	slot = client_hash(client->id) % nitems(gotd_clients);
	STAILQ_REMOVE(&gotd_clients[slot], client, gotd_client, entry);
	imsg_clear(&client->iev.ibuf);
	event_del(&client->iev.ev);
	evtimer_del(&client->tmo);
	if (client->fd != -1)
		close(client->fd);
	else if (client->iev.ibuf.fd != -1)
		close(client->iev.ibuf.fd);
	free(client->username);
	free(client);
	client_cnt--;
}

static void
disconnect_on_error(struct gotd_client *client, const struct got_error *err)
{
	struct imsgbuf ibuf;

	if (err->code != GOT_ERR_EOF) {
		log_warnx("uid %d: %s", client->euid, err->msg);
		if (client->fd != -1) {
			imsg_init(&ibuf, client->fd);
			gotd_imsg_send_error(&ibuf, 0, PROC_GOTD, err);
			imsg_clear(&ibuf);
		}
	}
	disconnect(client);
}

static const struct got_error *
send_repo_info(struct gotd_imsgev *iev, struct gotd_repo *repo)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_info_repo irepo;

	memset(&irepo, 0, sizeof(irepo));

	if (strlcpy(irepo.repo_name, repo->name, sizeof(irepo.repo_name))
	    >= sizeof(irepo.repo_name))
		return got_error_msg(GOT_ERR_NO_SPACE, "repo name too long");
	if (strlcpy(irepo.repo_path, repo->path, sizeof(irepo.repo_path))
	    >= sizeof(irepo.repo_path))
		return got_error_msg(GOT_ERR_NO_SPACE, "repo path too long");

	if (gotd_imsg_compose_event(iev, GOTD_IMSG_INFO_REPO, PROC_GOTD, -1,
	    &irepo, sizeof(irepo)) == -1) {
		err = got_error_from_errno("imsg compose INFO_REPO");
		if (err)
			return err;
	}

	return NULL;
}

static const struct got_error *
send_client_info(struct gotd_imsgev *iev, struct gotd_client *client)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_info_client iclient;
	struct gotd_child_proc *proc;

	memset(&iclient, 0, sizeof(iclient));
	iclient.euid = client->euid;
	iclient.egid = client->egid;

	proc = client->repo;
	if (proc) {
		if (strlcpy(iclient.repo_name, proc->repo_path,
		    sizeof(iclient.repo_name)) >= sizeof(iclient.repo_name)) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "repo name too long");
		}
		if (client_is_writing(client))
			iclient.is_writing = 1;

		iclient.repo_child_pid = proc->pid;
	}

	if (client->session)
		iclient.session_child_pid = client->session->pid;

	if (gotd_imsg_compose_event(iev, GOTD_IMSG_INFO_CLIENT, PROC_GOTD, -1,
	    &iclient, sizeof(iclient)) == -1) {
		err = got_error_from_errno("imsg compose INFO_CLIENT");
		if (err)
			return err;
	}

	return NULL;
}

static const struct got_error *
send_info(struct gotd_client *client)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_info info;
	uint64_t slot;
	struct gotd_repo *repo;

	if (client->euid != 0)
		return got_error_set_errno(EPERM, "info");

	info.pid = gotd.pid;
	info.verbosity = gotd.verbosity;
	info.nrepos = gotd.nrepos;
	info.nclients = client_cnt - 1;

	if (gotd_imsg_compose_event(&client->iev, GOTD_IMSG_INFO, PROC_GOTD, -1,
	    &info, sizeof(info)) == -1) {
		err = got_error_from_errno("imsg compose INFO");
		if (err)
			return err;
	}

	TAILQ_FOREACH(repo, &gotd.repos, entry) {
		err = send_repo_info(&client->iev, repo);
		if (err)
			return err;
	}

	for (slot = 0; slot < nitems(gotd_clients); slot++) {
		struct gotd_client *c;
		STAILQ_FOREACH(c, &gotd_clients[slot], entry) {
			if (c->id == client->id)
				continue;
			err = send_client_info(&client->iev, c);
			if (err)
				return err;
		}
	}

	return NULL;
}

static const struct got_error *
stop_gotd(struct gotd_client *client)
{

	if (client->euid != 0)
		return got_error_set_errno(EPERM, "stop");

	gotd_shutdown();
	/* NOTREACHED */
	return NULL;
}

static const struct got_error *
start_client_authentication(struct gotd_client *client, struct imsg *imsg)
{
	const struct got_error *err;
	struct gotd_imsg_list_refs ireq;
	struct gotd_repo *repo = NULL;
	size_t datalen;

	log_debug("list-refs request from uid %d", client->euid);

	if (client->state != GOTD_CLIENT_STATE_NEW)
		return got_error_msg(GOT_ERR_BAD_REQUEST,
		    "unexpected list-refs request received");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&ireq, imsg->data, datalen);

	if (ireq.client_is_reading) {
		err = ensure_client_is_not_writing(client);
		if (err)
			return err;
		repo = gotd_find_repo_by_name(ireq.repo_name, &gotd.repos);
		if (repo == NULL)
			return got_error(GOT_ERR_NOT_GIT_REPO);
		err = start_auth_child(client, GOTD_AUTH_READ, repo,
		    gotd.argv0, gotd.confpath, gotd.daemonize,
		    gotd.verbosity);
		if (err)
			return err;
	} else {
		err = ensure_client_is_not_reading(client);
		if (err)
			return err;
		repo = gotd_find_repo_by_name(ireq.repo_name, &gotd.repos);
		if (repo == NULL)
			return got_error(GOT_ERR_NOT_GIT_REPO);
		err = start_auth_child(client,
		    GOTD_AUTH_READ | GOTD_AUTH_WRITE,
		    repo, gotd.argv0, gotd.confpath, gotd.daemonize,
		    gotd.verbosity);
		if (err)
			return err;
	}

	evtimer_add(&client->tmo, &auth_timeout);

	/* Flow continues upon authentication success/failure or timeout. */
	return NULL;
}

static void
gotd_request(int fd, short events, void *arg)
{
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_client *client = iev->handler_arg;
	const struct got_error *err = NULL;
	struct imsg imsg;
	ssize_t n;

	if (events & EV_WRITE) {
		while (ibuf->w.queued) {
			n = msgbuf_write(&ibuf->w);
			if (n == -1 && errno == EPIPE) {
				/*
				 * The client has closed its socket.
				 * This can happen when Git clients are
				 * done sending pack file data.
				 */
				msgbuf_clear(&ibuf->w);
				continue;
			} else if (n == -1 && errno != EAGAIN) {
				err = got_error_from_errno("msgbuf_write");
				disconnect_on_error(client, err);
				return;
			}
			if (n == 0) {
				/* Connection closed. */
				err = got_error(GOT_ERR_EOF);
				disconnect_on_error(client, err);
				return;
			}
		}

		/* Disconnect gotctl(8) now that messages have been sent. */
		if (!client_is_reading(client) && !client_is_writing(client)) {
			disconnect(client);
			return;
		}
	}

	if ((events & EV_READ) == 0)
		return;

	memset(&imsg, 0, sizeof(imsg));

	while (err == NULL) {
		err = gotd_imsg_recv(&imsg, ibuf, 0);
		if (err) {
			if (err->code == GOT_ERR_PRIVSEP_READ)
				err = NULL;
			break;
		}

		evtimer_del(&client->tmo);

		switch (imsg.hdr.type) {
		case GOTD_IMSG_INFO:
			err = send_info(client);
			break;
		case GOTD_IMSG_STOP:
			err = stop_gotd(client);
			break;
		case GOTD_IMSG_LIST_REFS:
			err = start_client_authentication(client, &imsg);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}

	if (err) {
		disconnect_on_error(client, err);
	} else {
		gotd_imsg_event_add(&client->iev);
	}
}

static void
gotd_auth_timeout(int fd, short events, void *arg)
{
	struct gotd_client *client = arg;

	log_debug("disconnecting uid %d due to authentication timeout",
	    client->euid);
	disconnect(client);
}

static const struct got_error *
recv_connect(uint32_t *client_id, struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_connect iconnect;
	size_t datalen;
	int s = -1;
	struct gotd_client *client = NULL;

	*client_id = 0;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(iconnect))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iconnect, imsg->data, sizeof(iconnect));

	s = imsg_get_fd(imsg);
	if (s == -1) {
		err = got_error(GOT_ERR_PRIVSEP_NO_FD);
		goto done;
	}

	if (find_client(iconnect.client_id)) {
		err = got_error_msg(GOT_ERR_CLIENT_ID, "duplicate client ID");
		goto done;
	}

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	*client_id = iconnect.client_id;

	client->state = GOTD_CLIENT_STATE_NEW;
	client->id = iconnect.client_id;
	client->fd = s;
	s = -1;
	/* The auth process will verify UID/GID for us. */
	client->euid = iconnect.euid;
	client->egid = iconnect.egid;

	imsg_init(&client->iev.ibuf, client->fd);
	client->iev.handler = gotd_request;
	client->iev.events = EV_READ;
	client->iev.handler_arg = client;

	event_set(&client->iev.ev, client->fd, EV_READ, gotd_request,
	    &client->iev);
	gotd_imsg_event_add(&client->iev);

	evtimer_set(&client->tmo, gotd_auth_timeout, client);

	add_client(client);
	log_debug("%s: new client uid %d connected on fd %d", __func__,
	    client->euid, client->fd);
done:
	if (err) {
		struct gotd_child_proc *listen_proc = gotd.listen_proc;
		struct gotd_imsg_disconnect idisconnect;

		idisconnect.client_id = client->id;
		if (gotd_imsg_compose_event(&listen_proc->iev,
		    GOTD_IMSG_DISCONNECT, PROC_GOTD, -1,
		    &idisconnect, sizeof(idisconnect)) == -1)
			log_warn("imsg compose DISCONNECT");

		if (s != -1)
			close(s);
	}

	return err;
}

static const char *gotd_proc_names[PROC_MAX] = {
	"parent",
	"listen",
	"auth",
	"session_read",
	"session_write",
	"repo_read",
	"repo_write",
	"gitwrapper",
	"notify"
};

static void
kill_proc(struct gotd_child_proc *proc, int fatal)
{
	struct timeval tv = { 5, 0 };

	log_debug("kill -%d %d", fatal ? SIGKILL : SIGTERM, proc->pid);

	if (proc->iev.ibuf.fd != -1) {
		event_del(&proc->iev.ev);
		msgbuf_clear(&proc->iev.ibuf.w);
		close(proc->iev.ibuf.fd);
		proc->iev.ibuf.fd = -1;
	}

	if (!evtimer_pending(&proc->tmo, NULL) && !fatal)
		evtimer_add(&proc->tmo, &tv);

	if (fatal) {
		log_warnx("sending SIGKILL to PID %d", proc->pid);
		kill(proc->pid, SIGKILL);
	} else
		kill(proc->pid, SIGTERM);
}

static void
kill_proc_timeout(int fd, short ev, void *d)
{
	struct gotd_child_proc *proc = d;

	log_warnx("timeout waiting for PID %d to terminate;"
	    " retrying with force", proc->pid);
	kill_proc(proc, 1);
}

static void
gotd_shutdown(void)
{
	uint64_t slot;

	log_debug("shutting down");
	for (slot = 0; slot < nitems(gotd_clients); slot++) {
		struct gotd_client *c, *tmp;

		STAILQ_FOREACH_SAFE(c, &gotd_clients[slot], entry, tmp)
			disconnect(c);
	}

	kill_proc(gotd.listen_proc, 0);

	log_info("terminating");
	exit(0);
}

static struct gotd_child_proc *
find_proc_by_pid(pid_t pid)
{
	struct gotd_child_proc *proc = NULL;

	TAILQ_FOREACH(proc, &procs, entry)
		if (proc->pid == pid)
			break;

	return proc;
}

void
gotd_sighdlr(int sig, short event, void *arg)
{
	struct gotd_child_proc *proc;
	pid_t pid;
	int status;

	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGHUP:
		log_info("%s: ignoring SIGHUP", __func__);
		break;
	case SIGUSR1:
		log_info("%s: ignoring SIGUSR1", __func__);
		break;
	case SIGTERM:
	case SIGINT:
		gotd_shutdown();
		break;
	case SIGCHLD:
		for (;;) {
			pid = waitpid(WAIT_ANY, &status, WNOHANG);
			if (pid == -1) {
				if (errno == EINTR)
					continue;
				if (errno == ECHILD)
					break;
				fatal("waitpid");
			}
			if (pid == 0)
				break;

			log_debug("reaped pid %d", pid);
			proc = find_proc_by_pid(pid);
			if (proc == NULL) {
				log_info("caught exit of unknown child %d",
				    pid);
				continue;
			}

			if (WIFSIGNALED(status)) {
				log_warnx("child PID %d terminated with"
				    " signal %d", pid, WTERMSIG(status));
			}

			proc_done(proc);
		}
		break;
	default:
		fatalx("unexpected signal");
	}
}

static const struct got_error *
ensure_proc_is_reading(struct gotd_client *client,
    struct gotd_child_proc *proc)
{
	if (!client_is_reading(client)) {
		kill_proc(proc, 1);
		return got_error_fmt(GOT_ERR_BAD_PACKET,
		    "PID %d handled a read-request for uid %d but this "
		    "user is not reading from a repository", proc->pid,
		    client->euid);
	}

	return NULL;
}

static const struct got_error *
ensure_proc_is_writing(struct gotd_client *client,
    struct gotd_child_proc *proc)
{
	if (!client_is_writing(client)) {
		kill_proc(proc, 1);
		return got_error_fmt(GOT_ERR_BAD_PACKET,
		    "PID %d handled a write-request for uid %d but this "
		    "user is not writing to a repository", proc->pid,
		    client->euid);
	}

	return NULL;
}

static int
verify_imsg_src(struct gotd_client *client, struct gotd_child_proc *proc,
    struct imsg *imsg)
{
	const struct got_error *err;
	int ret = 0;

	if (proc->type == PROC_REPO_READ || proc->type == PROC_REPO_WRITE) {
		if (client->repo == NULL)
			fatalx("no process found for uid %d", client->euid);
		if (proc->pid != client->repo->pid) {
			kill_proc(proc, 1);
			log_warnx("received message from PID %d for uid %d, "
			    "while PID %d is the process serving this user",
			    proc->pid, client->euid, client->repo->pid);
			return 0;
		}
	}
	if (proc->type == PROC_SESSION_READ ||
	    proc->type == PROC_SESSION_WRITE) {
		if (client->session == NULL) {
			log_warnx("no session found for uid %d", client->euid);
			return 0;
		}
		if (proc->pid != client->session->pid) {
			kill_proc(proc, 1);
			log_warnx("received message from PID %d for uid %d, "
			    "while PID %d is the process serving this user",
			    proc->pid, client->euid, client->session->pid);
			return 0;
		}
	}

	switch (imsg->hdr.type) {
	case GOTD_IMSG_ERROR:
		ret = 1;
		break;
	case GOTD_IMSG_CONNECT:
		if (proc->type != PROC_LISTEN) {
			err = got_error_fmt(GOT_ERR_BAD_PACKET,
			    "new connection for uid %d from PID %d "
			    "which is not the listen process",
			    client->euid, proc->pid);
		} else
			ret = 1;
		break;
	case GOTD_IMSG_ACCESS_GRANTED:
		if (proc->type != PROC_AUTH) {
			err = got_error_fmt(GOT_ERR_BAD_PACKET,
			    "authentication of uid %d from PID %d "
			    "which is not the auth process",
			    client->euid, proc->pid);
		} else
			ret = 1;
		break;
	case GOTD_IMSG_CLIENT_SESSION_READY:
		if (proc->type != PROC_SESSION_READ &&
		    proc->type != PROC_SESSION_WRITE) {
			err = got_error_fmt(GOT_ERR_BAD_PACKET,
			    "unexpected \"ready\" signal from PID %d",
			    proc->pid);
		} else
			ret = 1;
		break;
	case GOTD_IMSG_REPO_CHILD_READY:
		if (proc->type != PROC_REPO_READ &&
		    proc->type != PROC_REPO_WRITE) {
			err = got_error_fmt(GOT_ERR_BAD_PACKET,
			    "unexpected \"ready\" signal from PID %d",
			    proc->pid);
		} else
			ret = 1;
		break;
	case GOTD_IMSG_PACKFILE_DONE:
		err = ensure_proc_is_reading(client, proc);
		if (err)
			log_warnx("uid %d: %s", client->euid, err->msg);
		else
			ret = 1;
		break;
	case GOTD_IMSG_PACKFILE_INSTALL:
	case GOTD_IMSG_REF_UPDATES_START:
	case GOTD_IMSG_REF_UPDATE:
		err = ensure_proc_is_writing(client, proc);
		if (err)
			log_warnx("uid %d: %s", client->euid, err->msg);
		else
			ret = 1;
		break;
	default:
		log_debug("%s: unexpected imsg %d", __func__, imsg->hdr.type);
		break;
	}

	return ret;
}

static const struct got_error *
connect_repo_child(struct gotd_client *client,
    struct gotd_child_proc *repo_proc)
{
	static const struct got_error *err;
	struct gotd_imsgev *session_iev = &client->session->iev;
	struct gotd_imsg_connect_repo_child ireq;
	int pipe[2];
	int sock_flags = SOCK_STREAM | SOCK_NONBLOCK;

#ifdef SOCK_CLOEXEC
	sock_flags |= SOCK_CLOEXEC;
#endif

	if (client->state != GOTD_CLIENT_STATE_ACCESS_GRANTED)
		return got_error_msg(GOT_ERR_BAD_REQUEST,
		    "unexpected repo child ready signal received");

	if (socketpair(AF_UNIX, sock_flags, PF_UNSPEC, pipe) == -1)
		fatal("socketpair");

	memset(&ireq, 0, sizeof(ireq));
	ireq.proc_id = repo_proc->type;

	/* Pass repo child pipe to session child process. */
	if (gotd_imsg_compose_event(session_iev, GOTD_IMSG_CONNECT_REPO_CHILD,
	    PROC_GOTD, pipe[0], &ireq, sizeof(ireq)) == -1) {
		err = got_error_from_errno("imsg compose CONNECT_REPO_CHILD");
		close(pipe[0]);
		close(pipe[1]);
		return err;
	}

	/* Pass session child pipe to repo child process. */
	if (gotd_imsg_compose_event(&repo_proc->iev,
	    GOTD_IMSG_CONNECT_REPO_CHILD, PROC_GOTD, pipe[1], NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose CONNECT_REPO_CHILD");
		close(pipe[1]);
		return err;
	}

	return NULL;
}

static void
gotd_dispatch_listener(int fd, short event, void *arg)
{
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_child_proc *proc = gotd.listen_proc;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;

	if (proc->iev.ibuf.fd != fd)
		fatalx("%s: unexpected fd %d", __func__, fd);

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		n = msgbuf_write(&ibuf->w);
		if (n == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	for (;;) {
		const struct got_error *err = NULL;
		struct gotd_client *client = NULL;
		uint32_t client_id = 0;
		int do_disconnect = 0;

		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			do_disconnect = 1;
			err = gotd_imsg_recv_error(&client_id, &imsg);
			break;
		case GOTD_IMSG_CONNECT:
			err = recv_connect(&client_id, &imsg);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		client = find_client(client_id);
		if (client == NULL) {
			log_warnx("%s: client not found", __func__);
			imsg_free(&imsg);
			continue;
		}

		if (err)
			log_warnx("uid %d: %s", client->euid, err->msg);

		if (do_disconnect) {
			if (err)
				disconnect_on_error(client, err);
			else
				disconnect(client);
		}

		imsg_free(&imsg);
	}
done:
	if (!shut) {
		gotd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

static void
gotd_dispatch_notifier(int fd, short event, void *arg)
{
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_child_proc *proc = gotd.notify_proc;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;

	if (proc->iev.ibuf.fd != fd)
		fatalx("%s: unexpected fd %d", __func__, fd);

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		n = msgbuf_write(&ibuf->w);
		if (n == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);
	}
done:
	if (!shut) {
		gotd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);

		/*
		 * Do not exit all of gotd if the notification handler dies.
		 * We can continue operating without notifications until an
		 * operator intervenes.
		 */
		log_warnx("notify child process (pid %d) closed its imsg pipe "
		    "unexpectedly", proc->pid);
		proc_done(proc);
	}
}

static void
gotd_dispatch_auth_child(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_client *client;
	struct gotd_repo *repo = NULL;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;
	uint32_t client_id = 0;
	int do_disconnect = 0;
	size_t datalen;

	client = find_client_by_proc_fd(fd);
	if (client == NULL) {
		/* Can happen during process teardown. */
		warnx("cannot find client for fd %d", fd);
		shut = 1;
		goto done;
	}

	if (client->auth == NULL)
		fatalx("cannot find auth child process for fd %d", fd);

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		n = msgbuf_write(&ibuf->w);
		if (n == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
		}
		goto done;
	}

	if (client->auth->iev.ibuf.fd != fd)
		fatalx("%s: unexpected fd %d", __func__, fd);

	if ((n = imsg_get(ibuf, &imsg)) == -1)
		fatal("%s: imsg_get error", __func__);
	if (n == 0)	/* No more messages. */
		return;

	evtimer_del(&client->tmo);

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case GOTD_IMSG_ERROR:
		do_disconnect = 1;
		err = gotd_imsg_recv_error(&client_id, &imsg);
		break;
	case GOTD_IMSG_ACCESS_GRANTED:
		if (client->state != GOTD_CLIENT_STATE_NEW) {
			do_disconnect = 1;
			err = got_error(GOT_ERR_PRIVSEP_MSG);
		}
		break;
	default:
		do_disconnect = 1;
		log_debug("unexpected imsg %d", imsg.hdr.type);
		break;
	}

	if (!verify_imsg_src(client, client->auth, &imsg)) {
		do_disconnect = 1;
		log_debug("dropping imsg type %d from PID %d",
		    imsg.hdr.type, client->auth->pid);
	}

	if (do_disconnect) {
		if (err)
			disconnect_on_error(client, err);
		else
			disconnect(client);
		imsg_free(&imsg);
		return;
	}

	client->state = GOTD_CLIENT_STATE_ACCESS_GRANTED;
	if (datalen > 0)
		client->username = strndup(imsg.data, datalen);
	imsg_free(&imsg);
	if (client->username == NULL &&
	    asprintf(&client->username, "uid %d", client->euid) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	repo = gotd_find_repo_by_name(client->auth->repo_name, &gotd.repos);
	if (repo == NULL) {
		err = got_error(GOT_ERR_NOT_GIT_REPO);
		goto done;
	}
	kill_auth_proc(client);

	log_info("authenticated %s for repository %s",
	    client->username, repo->name);

	err = start_session_child(client, repo, gotd.argv0,
	    gotd.confpath, gotd.daemonize, gotd.verbosity);
	if (err)
		goto done;
done:
	if (err)
		log_warnx("uid %d: %s", client->euid, err->msg);

	/* We might have killed the auth process by now. */
	if (client->auth != NULL) {
		if (!shut) {
			gotd_imsg_event_add(iev);
		} else {
			/* This pipe is dead. Remove its event handler */
			event_del(&iev->ev);
		}
	}
}

static const struct got_error *
connect_session(struct gotd_client *client)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_connect iconnect;
	int s;
	struct ibuf *wbuf;

	memset(&iconnect, 0, sizeof(iconnect));

	s = dup(client->fd);
	if (s == -1)
		return got_error_from_errno("dup");

	iconnect.client_id = client->id;
	iconnect.euid = client->euid;
	iconnect.egid = client->egid;
	iconnect.username_len = strlen(client->username);

	wbuf = imsg_create(&client->session->iev.ibuf, GOTD_IMSG_CONNECT,
	    PROC_GOTD, gotd.pid, sizeof(iconnect) + iconnect.username_len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg compose CONNECT");
		close(s);
		return err;
	}
	if (imsg_add(wbuf, &iconnect, sizeof(iconnect)) == -1) {
		close(s);
		return got_error_from_errno("imsg_add CONNECT");
	}
	if (imsg_add(wbuf, client->username, iconnect.username_len) == -1) {
		close(s);
		return got_error_from_errno("imsg_add CONNECT");
	}

	ibuf_fd_set(wbuf, s);
	imsg_close(&client->session->iev.ibuf, wbuf);
	gotd_imsg_event_add(&client->session->iev);

	/*
	 * We are no longer interested in messages from this client.
	 * Further client requests will be handled by the session process.
	 */
	msgbuf_clear(&client->iev.ibuf.w);
	imsg_clear(&client->iev.ibuf);
	event_del(&client->iev.ev);
	client->fd = -1; /* will be closed via copy in client->iev.ibuf.fd */

	return NULL;
}

static void
gotd_dispatch_client_session(int fd, short event, void *arg)
{
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_child_proc *proc = NULL;
	struct gotd_client *client = NULL;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;

	client = find_client_by_proc_fd(fd);
	if (client == NULL) {
		/* Can happen during process teardown. */
		warnx("cannot find client for fd %d", fd);
		shut = 1;
		goto done;
	}

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		n = msgbuf_write(&ibuf->w);
		if (n == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	proc = client->session;
	if (proc == NULL)
		fatalx("cannot find session child process for fd %d", fd);

	for (;;) {
		const struct got_error *err = NULL;
		uint32_t client_id = 0;
		int do_disconnect = 0, do_start_repo_child = 0;

		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			do_disconnect = 1;
			err = gotd_imsg_recv_error(&client_id, &imsg);
			break;
		case GOTD_IMSG_CLIENT_SESSION_READY:
			if (client->state != GOTD_CLIENT_STATE_ACCESS_GRANTED) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			do_start_repo_child = 1;
			break;
		case GOTD_IMSG_DISCONNECT:
			do_disconnect = 1;
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		if (!verify_imsg_src(client, proc, &imsg)) {
			log_debug("dropping imsg type %d from PID %d",
			    imsg.hdr.type, proc->pid);
			imsg_free(&imsg);
			continue;
		}
		if (err)
			log_warnx("uid %d: %s", client->euid, err->msg);

		if (do_start_repo_child) {
			struct gotd_repo *repo;
			const char *name = client->session->repo_name;

			repo = gotd_find_repo_by_name(name, &gotd.repos);
			if (repo != NULL) {
				enum gotd_procid proc_type;

				if (client->required_auth & GOTD_AUTH_WRITE)
					proc_type = PROC_REPO_WRITE;
				else
					proc_type = PROC_REPO_READ;

				err = start_repo_child(client, proc_type, repo,
				    gotd.argv0, gotd.confpath, gotd.daemonize,
				    gotd.verbosity);
			} else
				err = got_error(GOT_ERR_NOT_GIT_REPO);

			if (err) {
				log_warnx("uid %d: %s", client->euid, err->msg);
				do_disconnect = 1;
			}
		}

		if (do_disconnect) {
			if (err)
				disconnect_on_error(client, err);
			else
				disconnect(client);
		}

		imsg_free(&imsg);
	}
done:
	if (!shut) {
		gotd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		disconnect(client);
	}
}

static const struct got_error *
connect_notifier_and_session(struct gotd_client *client)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *session_iev = &client->session->iev;
	int pipe[2];
	int sock_flags = SOCK_STREAM|SOCK_NONBLOCK;

	if (gotd.notify_proc == NULL)
		return NULL;

#ifdef SOCK_CLOEXEC
	sock_flags |= SOCK_CLOEXEC;
#endif
	if (socketpair(AF_UNIX, sock_flags,
	    PF_UNSPEC, pipe) == -1)
		return got_error_from_errno("socketpair");

	/* Pass notifier pipe to session . */
	if (gotd_imsg_compose_event(session_iev, GOTD_IMSG_CONNECT_NOTIFIER,
	    PROC_GOTD, pipe[0], NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose CONNECT_NOTIFIER");
		close(pipe[0]);
		close(pipe[1]);
		return err;
	}

	/* Pass session pipe to notifier. */
	if (gotd_imsg_compose_event(&gotd.notify_proc->iev,
	    GOTD_IMSG_CONNECT_SESSION, PROC_GOTD, pipe[1], NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose CONNECT_SESSION");
		close(pipe[1]);
		return err;
	}

	return NULL;
}

static void
gotd_dispatch_repo_child(int fd, short event, void *arg)
{
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_child_proc *proc = NULL;
	struct gotd_client *client;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;

	client = find_client_by_proc_fd(fd);
	if (client == NULL) {
		/* Can happen during process teardown. */
		warnx("cannot find client for fd %d", fd);
		shut = 1;
		goto done;
	}

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	if (event & EV_WRITE) {
		n = msgbuf_write(&ibuf->w);
		if (n == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0) {
			/* Connection closed. */
			shut = 1;
			goto done;
		}
	}

	proc = client->repo;
	if (proc == NULL)
		fatalx("cannot find child process for fd %d", fd);

	for (;;) {
		const struct got_error *err = NULL;
		uint32_t client_id = 0;
		int do_disconnect = 0;

		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			do_disconnect = 1;
			err = gotd_imsg_recv_error(&client_id, &imsg);
			break;
		case GOTD_IMSG_REPO_CHILD_READY:
			err = connect_session(client);
			if (err)
				break;
			err = connect_notifier_and_session(client);
			if (err)
				break;
			err = connect_repo_child(client, proc);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}

		if (!verify_imsg_src(client, proc, &imsg)) {
			log_debug("dropping imsg type %d from PID %d",
			    imsg.hdr.type, proc->pid);
			imsg_free(&imsg);
			continue;
		}
		if (err)
			log_warnx("uid %d: %s", client->euid, err->msg);

		if (do_disconnect) {
			if (err)
				disconnect_on_error(client, err);
			else
				disconnect(client);
		}

		imsg_free(&imsg);
	}
done:
	if (!shut) {
		gotd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		disconnect(client);
	}
}

static pid_t
start_child(enum gotd_procid proc_id, const char *repo_path,
    char *argv0, const char *confpath, int fd, int daemonize, int verbosity)
{
	const char	*argv[11];
	int		 argc = 0;
	pid_t		 pid;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		close(fd);
		return pid;
	}

	if (fd != GOTD_FILENO_MSG_PIPE) {
		if (dup2(fd, GOTD_FILENO_MSG_PIPE) == -1)
			fatal("cannot setup imsg fd");
	} else if (fcntl(fd, F_SETFD, 0) == -1)
		fatal("cannot setup imsg fd");

	argv[argc++] = argv0;
	switch (proc_id) {
	case PROC_LISTEN:
		argv[argc++] = "-TL";
		break;
	case PROC_AUTH:
		argv[argc++] = "-TA";
		break;
	case PROC_SESSION_READ:
		argv[argc++] = "-Ts";
		break;
	case PROC_SESSION_WRITE:
		argv[argc++] = "-TS";
		break;
	case PROC_REPO_READ:
		argv[argc++] = "-TR";
		break;
	case PROC_REPO_WRITE:
		argv[argc++] = "-TW";
		break;
	case PROC_NOTIFY:
		argv[argc++] = "-TN";
		break;
	default:
		fatalx("invalid process id %d", proc_id);
	}

	argv[argc++] = "-f";
	argv[argc++] = confpath;

	if (repo_path) {
		argv[argc++] = "-P";
		argv[argc++] = repo_path;
	}

	if (!daemonize)
		argv[argc++] = "-d";
	if (verbosity > 0)
		argv[argc++] = "-v";
	if (verbosity > 1)
		argv[argc++] = "-v";
	argv[argc++] = NULL;

	execvp(argv0, (char * const *)argv);
	fatal("execvp");
}

static void
start_listener(char *argv0, const char *confpath, int daemonize, int verbosity)
{
	struct gotd_child_proc *proc;
	int sock_flags = SOCK_STREAM|SOCK_NONBLOCK;

#ifdef SOCK_CLOEXEC
	sock_flags |= SOCK_CLOEXEC;
#endif

	proc = calloc(1, sizeof(*proc));
	if (proc == NULL)
		fatal("calloc");

	TAILQ_INSERT_HEAD(&procs, proc, entry);

	/* proc->tmo is initialized in main() after event_init() */

	proc->type = PROC_LISTEN;

	if (socketpair(AF_UNIX, sock_flags,
	    PF_UNSPEC, proc->pipe) == -1)
		fatal("socketpair");

	proc->pid = start_child(proc->type, NULL, argv0, confpath,
	    proc->pipe[1], daemonize, verbosity);
	imsg_init(&proc->iev.ibuf, proc->pipe[0]);
	proc->iev.handler = gotd_dispatch_listener;
	proc->iev.events = EV_READ;
	proc->iev.handler_arg = NULL;

	gotd.listen_proc = proc;
}

static void
start_notifier(char *argv0, const char *confpath, int daemonize, int verbosity)
{
	struct gotd_child_proc *proc;
	int sock_flags = SOCK_STREAM | SOCK_NONBLOCK;


	proc = calloc(1, sizeof(*proc));
	if (proc == NULL)
		fatal("calloc");

	TAILQ_INSERT_HEAD(&procs, proc, entry);

	/* proc->tmo is initialized in main() after event_init() */

	proc->type = PROC_NOTIFY;

#ifdef SOCK_CLOEXEC
	sock_flags |= SOCK_CLOEXEC;
#endif
	if (socketpair(AF_UNIX, sock_flags,
	    PF_UNSPEC, proc->pipe) == -1)
		fatal("socketpair");

	proc->pid = start_child(proc->type, NULL, argv0, confpath,
	    proc->pipe[1], daemonize, verbosity);
	imsg_init(&proc->iev.ibuf, proc->pipe[0]);
	proc->iev.handler = gotd_dispatch_notifier;
	proc->iev.events = EV_READ;
	proc->iev.handler_arg = NULL;
	event_set(&proc->iev.ev, proc->iev.ibuf.fd, EV_READ,
	    gotd_dispatch_notifier, &proc->iev);

	gotd.notify_proc = proc;
}

static const struct got_error *
start_session_child(struct gotd_client *client, struct gotd_repo *repo,
    char *argv0, const char *confpath, int daemonize, int verbosity)
{
	struct gotd_child_proc *proc;
	int sock_flags = SOCK_STREAM | SOCK_NONBLOCK;

#ifdef SOCK_CLOEXEC
	sock_flags |= SOCK_CLOEXEC;
#endif

	proc = calloc(1, sizeof(*proc));
	if (proc == NULL)
		return got_error_from_errno("calloc");

	TAILQ_INSERT_HEAD(&procs, proc, entry);
	evtimer_set(&proc->tmo, kill_proc_timeout, proc);

	if (client_is_reading(client))
		proc->type = PROC_SESSION_READ;
	else
		proc->type = PROC_SESSION_WRITE;
	if (strlcpy(proc->repo_name, repo->name,
	    sizeof(proc->repo_name)) >= sizeof(proc->repo_name))
		fatalx("repository name too long: %s", repo->name);
	log_debug("starting client uid %d session for repository %s",
	    client->euid, repo->name);
	if (strlcpy(proc->repo_path, repo->path, sizeof(proc->repo_path)) >=
	    sizeof(proc->repo_path))
		fatalx("repository path too long: %s", repo->path);
	if (socketpair(AF_UNIX, sock_flags, PF_UNSPEC, proc->pipe) == -1)
		fatal("socketpair");
	proc->pid = start_child(proc->type, proc->repo_path, argv0,
	    confpath, proc->pipe[1], daemonize, verbosity);
	imsg_init(&proc->iev.ibuf, proc->pipe[0]);
	log_debug("proc %s %s is on fd %d",
	    gotd_proc_names[proc->type], proc->repo_path,
	    proc->pipe[0]);
	proc->iev.handler = gotd_dispatch_client_session;
	proc->iev.events = EV_READ;
	proc->iev.handler_arg = NULL;
	event_set(&proc->iev.ev, proc->iev.ibuf.fd, EV_READ,
	    gotd_dispatch_client_session, &proc->iev);
	gotd_imsg_event_add(&proc->iev);

	client->session = proc;
	return NULL;
}

static const struct got_error *
start_repo_child(struct gotd_client *client, enum gotd_procid proc_type,
    struct gotd_repo *repo, char *argv0, const char *confpath,
    int daemonize, int verbosity)
{
	struct gotd_child_proc *proc;
	int sock_flags = SOCK_STREAM|SOCK_NONBLOCK;

#ifdef SOCK_CLOEXEC
	sock_flags |= SOCK_CLOEXEC;
#endif

	if (proc_type != PROC_REPO_READ && proc_type != PROC_REPO_WRITE)
		return got_error_msg(GOT_ERR_NOT_IMPL, "bad process type");

	proc = calloc(1, sizeof(*proc));
	if (proc == NULL)
		return got_error_from_errno("calloc");

	TAILQ_INSERT_HEAD(&procs, proc, entry);
	evtimer_set(&proc->tmo, kill_proc_timeout, proc);

	proc->type = proc_type;
	if (strlcpy(proc->repo_name, repo->name,
	    sizeof(proc->repo_name)) >= sizeof(proc->repo_name))
		fatalx("repository name too long: %s", repo->name);
	log_debug("starting %s for repository %s",
	    proc->type == PROC_REPO_READ ? "reader" : "writer", repo->name);

	if (strlcpy(proc->repo_path, repo->path, sizeof(proc->repo_path)) >=
	    sizeof(proc->repo_path))
		fatalx("repository path too long: %s", repo->path);
	if (realpath(repo->path, proc->repo_path) == NULL)
		fatal("%s", repo->path);
	if (socketpair(AF_UNIX, sock_flags,
	    PF_UNSPEC, proc->pipe) == -1)
		fatal("socketpair");
	proc->pid = start_child(proc->type, proc->repo_path, argv0,
	    confpath, proc->pipe[1], daemonize, verbosity);
	imsg_init(&proc->iev.ibuf, proc->pipe[0]);
	log_debug("proc %s %s is on fd %d",
	    gotd_proc_names[proc->type], proc->repo_path,
	    proc->pipe[0]);
	proc->iev.handler = gotd_dispatch_repo_child;
	proc->iev.events = EV_READ;
	proc->iev.handler_arg = NULL;
	event_set(&proc->iev.ev, proc->iev.ibuf.fd, EV_READ,
	    gotd_dispatch_repo_child, &proc->iev);
	gotd_imsg_event_add(&proc->iev);

	client->repo = proc;
	return NULL;
}

static const struct got_error *
start_auth_child(struct gotd_client *client, int required_auth,
    struct gotd_repo *repo, char *argv0, const char *confpath,
    int daemonize, int verbosity)
{
	const struct got_error *err = NULL;
	struct gotd_child_proc *proc;
	struct gotd_imsg_auth iauth;
	int fd;
	int sock_flags = SOCK_STREAM|SOCK_NONBLOCK;

#ifdef SOCK_CLOEXEC
	sock_flags |= SOCK_CLOEXEC;
#endif

	memset(&iauth, 0, sizeof(iauth));

	fd = dup(client->fd);
	if (fd == -1)
		return got_error_from_errno("dup");

	proc = calloc(1, sizeof(*proc));
	if (proc == NULL) {
		err = got_error_from_errno("calloc");
		close(fd);
		return err;
	}

	TAILQ_INSERT_HEAD(&procs, proc, entry);
	evtimer_set(&proc->tmo, kill_proc_timeout, proc);

	proc->type = PROC_AUTH;
	if (strlcpy(proc->repo_name, repo->name,
	    sizeof(proc->repo_name)) >= sizeof(proc->repo_name))
		fatalx("repository name too long: %s", repo->name);
	log_debug("starting auth for uid %d repository %s",
	    client->euid, repo->name);
	if (strlcpy(proc->repo_path, repo->path, sizeof(proc->repo_path)) >=
	    sizeof(proc->repo_path))
		fatalx("repository path too long: %s", repo->path);
	if (realpath(repo->path, proc->repo_path) == NULL)
		fatal("%s", repo->path);
	if (socketpair(AF_UNIX, sock_flags,
	    PF_UNSPEC, proc->pipe) == -1)
		fatal("socketpair");
	proc->pid = start_child(proc->type, proc->repo_path, argv0,
	    confpath, proc->pipe[1], daemonize, verbosity);
	imsg_init(&proc->iev.ibuf, proc->pipe[0]);
	log_debug("proc %s %s is on fd %d",
	    gotd_proc_names[proc->type], proc->repo_path,
	    proc->pipe[0]);
	proc->iev.handler = gotd_dispatch_auth_child;
	proc->iev.events = EV_READ;
	proc->iev.handler_arg = NULL;
	event_set(&proc->iev.ev, proc->iev.ibuf.fd, EV_READ,
	    gotd_dispatch_auth_child, &proc->iev);
	gotd_imsg_event_add(&proc->iev);

	iauth.euid = client->euid;
	iauth.egid = client->egid;
	iauth.required_auth = required_auth;
	iauth.client_id = client->id;
	if (gotd_imsg_compose_event(&proc->iev, GOTD_IMSG_AUTHENTICATE,
	    PROC_GOTD, fd, &iauth, sizeof(iauth)) == -1) {
		log_warn("imsg compose AUTHENTICATE");
		close(fd);
		/* Let the auth_timeout handler tidy up. */
	}

	client->auth = proc;
	client->required_auth = required_auth;
	return NULL;
}

static void
apply_unveil_repo_readonly(const char *repo_path, int need_tmpdir)
{
	if (need_tmpdir) {
		if (unveil(GOT_TMPDIR_STR, "rwc") == -1)
			fatal("unveil %s", GOT_TMPDIR_STR);
	}

	if (unveil(repo_path, "r") == -1)
		fatal("unveil %s", repo_path);

	if (unveil(NULL, NULL) == -1)
		fatal("unveil");
}

static void
apply_unveil_repo_readwrite(const char *repo_path)
{
	if (unveil(repo_path, "rwc") == -1)
		fatal("unveil %s", repo_path);

	if (unveil(GOT_TMPDIR_STR, "rwc") == -1)
		fatal("unveil %s", GOT_TMPDIR_STR);

	if (unveil(NULL, NULL) == -1)
		fatal("unveil");
}

static void
apply_unveil_none(void)
{
	if (unveil("/", "") == -1)
		fatal("unveil");

	if (unveil(NULL, NULL) == -1)
		fatal("unveil");
}

static void
apply_unveil_selfexec(void)
{
	if (unveil(gotd.argv0, "x") == -1)
		fatal("unveil %s", gotd.argv0);

	if (unveil(NULL, NULL) == -1)
		fatal("unveil");
}

static void
set_max_datasize(void)
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_DATA, &rl) != 0)
		return;

	rl.rlim_cur = rl.rlim_max;
	setrlimit(RLIMIT_DATA, &rl);
}

static void
unveil_notification_helpers(void)
{
	const char *helpers[] = {
	    GOTD_PATH_PROG_NOTIFY_EMAIL,
	    GOTD_PATH_PROG_NOTIFY_HTTP,
	};
	size_t i;

	for (i = 0; i < nitems(helpers); i++) {
		if (unveil(helpers[i], "x") == 0)
			continue;
		fatal("unveil %s", helpers[i]);
	}

	if (unveil(NULL, NULL) == -1)
		fatal("unveil");
}

static void
check_file_secrecy(int fd, const char *fname)
{
	struct stat st;

	if (fstat(fd, &st))
		fatal("cannot stat %s", fname);

	if (st.st_uid != 0)
		fatalx("secrets file %s must be owned by root", fname);

	if (st.st_gid != 0)
		fatalx("secrets file %s must be owned by group wheel/root",
		    fname);

	if (st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO))
		fatalx("secrets file %s must not be group writable or world "
		    "readable/writable", fname);
}

int
main(int argc, char **argv)
{
	const struct got_error *error = NULL;
	struct gotd_secrets *secrets = NULL;
	int ch, fd = -1, daemonize = 1, verbosity = 0, noaction = 0;
	const char *confpath = GOTD_CONF_PATH;
	char *secretspath = NULL;
	char *argv0 = argv[0];
	char title[2048];
	struct passwd *pw = NULL;
	uid_t uid;
	char *repo_path = NULL;
	enum gotd_procid proc_id = PROC_GOTD;
	struct event evsigint, evsigterm, evsighup, evsigusr1, evsigchld;
	int *pack_fds = NULL, *temp_fds = NULL;
	struct gotd_repo *repo = NULL;
	char *default_sender = NULL;
	char hostname[HOST_NAME_MAX + 1];
	FILE *fp;
	FILE *diff_f1 = NULL, *diff_f2 = NULL;
	int diff_fd1 = -1, diff_fd2 = -1;
	const char *errstr;

	TAILQ_INIT(&procs);

	log_init(1, LOG_DAEMON); /* Log to stderr until daemonized. */

	while ((ch = getopt(argc, argv, "df:nP:s:T:v")) != -1) {
		switch (ch) {
		case 'd':
			daemonize = 0;
			break;
		case 'f':
			confpath = optarg;
			break;
		case 'n':
			noaction = 1;
			break;
		case 'P':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				fatal("realpath '%s'", optarg);
			break;
		case 's':
			secretspath = realpath(optarg, NULL);
			if (secretspath == NULL)
				fatal("realpath '%s'", optarg);
			break;
		case 'T':
			switch (*optarg) {
			case 'A':
				proc_id = PROC_AUTH;
				break;
			case 'L':
				proc_id = PROC_LISTEN;
				break;
			case 'N':
				proc_id = PROC_NOTIFY;
				break;
			case 'R':
				proc_id = PROC_REPO_READ;
				break;
			case 's':
				proc_id = PROC_SESSION_READ;
				break;
			case 'S':
				proc_id = PROC_SESSION_WRITE;
				break;
			case 'W':
				proc_id = PROC_REPO_WRITE;
				break;
			default:
				errx(1, "unknown proc type %s", optarg);
			}
			break;
		case 'v':
			if (verbosity < 3)
				verbosity++;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	if (geteuid() && (proc_id == PROC_GOTD || proc_id == PROC_LISTEN))
		fatalx("need root privileges");

	if (proc_id == PROC_GOTD) {
		const char *p = secretspath ? secretspath : GOTD_SECRETS_PATH;

		fp = fopen(p, "r");
		if (fp == NULL && (secretspath != NULL || errno != ENOENT))
			fatal("can't open secrets file %s", p);

		if (fp != NULL) {
			check_file_secrecy(fileno(fp), p);
			error = gotd_secrets_parse(p, fp, &secrets);
			fclose(fp);
			if (error)
				fatalx("failed to parse secrets file %s: %s",
				    p, error->msg);
		}
	}

	if (parse_config(confpath, proc_id, secrets, &gotd) != 0)
		return 1;

	pw = getpwnam(gotd.user_name);
	if (pw == NULL) {
		uid = strtonum(gotd.user_name, 0, UID_MAX - 1, &errstr);
		if (errstr == NULL)
			pw = getpwuid(uid);
	}
	if (pw == NULL)
		fatalx("user %s not found", gotd.user_name);

	if (pw->pw_uid == 0)
		fatalx("cannot run %s as the superuser", getprogname());

	/*
	 * SHA2 repositories cannot be used with gotd until Git protocol v2
	 * support is added. Reject them at startup for now.
	 */
	TAILQ_FOREACH(repo, &gotd.repos, entry) {
		struct got_repository *r;

		error = got_repo_open(&r, repo->path, NULL, NULL);
		if (error) {
			if (error->code == GOT_ERR_ERRNO && errno == ENOENT)
				continue;
			fatalx("%s: %s", repo->path, error->msg);
		}

		if (got_repo_get_object_format(r) != GOT_HASH_SHA1) {
			error = got_error_msg(GOT_ERR_NOT_IMPL,
			    "sha256 object IDs unsupported in network "
			    "protocol");
			fatalx("%s: %s", repo->path, error->msg);
		}

		got_repo_close(r);
	}

	if (noaction) {
		fprintf(stderr, "configuration OK\n");
		return 0;
	}

	gotd.argv0 = argv0;
	gotd.daemonize = daemonize;
	gotd.verbosity = verbosity;
	gotd.confpath = confpath;

	/* Require an absolute path in argv[0] for reliable re-exec. */
	if (!got_path_is_absolute(argv0))
		fatalx("bad path \"%s\": must be an absolute path", argv0);

	log_init(daemonize ? 0 : 1, LOG_DAEMON);
	log_setverbose(verbosity);

	if (proc_id == PROC_GOTD) {
		snprintf(title, sizeof(title), "%s", gotd_proc_names[proc_id]);
		arc4random_buf(&clients_hash_key, sizeof(clients_hash_key));
		if (daemonize && daemon(1, 0) == -1)
			fatal("daemon");
		gotd.pid = getpid();
		start_listener(argv0, confpath, daemonize, verbosity);
		start_notifier(argv0, confpath, daemonize, verbosity);
	} else if (proc_id == PROC_LISTEN) {
		snprintf(title, sizeof(title), "%s", gotd_proc_names[proc_id]);
		if (verbosity) {
			log_info("socket: %s", gotd.unix_socket_path);
			log_info("user: %s", pw->pw_name);
		}

		fd = unix_socket_listen(gotd.unix_socket_path, pw->pw_uid,
		    pw->pw_gid);
		if (fd == -1) {
			fatal("cannot listen on unix socket %s",
			    gotd.unix_socket_path);
		}
	} else if (proc_id == PROC_AUTH) {
		snprintf(title, sizeof(title), "%s %s",
		    gotd_proc_names[proc_id], repo_path);
	} else if (proc_id == PROC_REPO_READ || proc_id == PROC_REPO_WRITE ||
	    proc_id == PROC_SESSION_READ || proc_id == PROC_SESSION_WRITE) {
		error = got_repo_pack_fds_open(&pack_fds);
		if (error != NULL)
			fatalx("cannot open pack tempfiles: %s", error->msg);
		error = got_repo_temp_fds_open(&temp_fds);
		if (error != NULL)
			fatalx("cannot open pack tempfiles: %s", error->msg);
		if (repo_path == NULL)
			fatalx("repository path not specified");
		snprintf(title, sizeof(title), "%s %s",
		    gotd_proc_names[proc_id], repo_path);
	} else if (proc_id == PROC_NOTIFY) {
		snprintf(title, sizeof(title), "%s", gotd_proc_names[proc_id]);
		if (gethostname(hostname, sizeof(hostname)) == -1)
			fatal("gethostname");
		if (asprintf(&default_sender, "%s@%s",
		    pw->pw_name, hostname) == -1)
			fatal("asprintf");
	} else
		fatal("invalid process id %d", proc_id);

	setproctitle("%s", title);
	log_procinit(title);

	if (proc_id != PROC_GOTD && proc_id != PROC_LISTEN &&
	    proc_id != PROC_REPO_READ && proc_id != PROC_REPO_WRITE) {
		/* Drop root privileges. */
		if (setgid(pw->pw_gid) == -1)
			fatal("setgid %d failed", pw->pw_gid);
		if (setuid(pw->pw_uid) == -1)
			fatal("setuid %d failed", pw->pw_uid);
	}

	event_init();

	switch (proc_id) {
	case PROC_GOTD:
#ifndef PROFILE
		/* "exec" promise will be limited to argv[0] via unveil(2). */
		if (pledge("stdio proc exec sendfd recvfd unveil", NULL) == -1)
			err(1, "pledge");
#endif
		break;
	case PROC_LISTEN:
#ifndef PROFILE
		if (pledge("stdio sendfd unix unveil", NULL) == -1)
			err(1, "pledge");
#endif
		/*
		 * Ensure that AF_UNIX bind(2) cannot be used with any other
		 * sockets by revoking all filesystem access via unveil(2).
		 */
		apply_unveil_none();

		enter_chroot(GOTD_EMPTY_PATH);
		drop_privs(pw);

		listen_main(title, fd, gotd.connection_limits,
		    gotd.nconnection_limits);
		/* NOTREACHED */
		break;
	case PROC_AUTH:
#ifndef PROFILE
		if (pledge("stdio getpw recvfd unix unveil", NULL) == -1)
			err(1, "pledge");
#endif
		/*
		 * We need the "unix" pledge promise for getpeername(2) only.
		 * Ensure that AF_UNIX bind(2) cannot be used by revoking all
		 * filesystem access via unveil(2). Access to password database
		 * files will still work since "getpw" bypasses unveil(2).
		 */
		apply_unveil_none();

		drop_privs(pw);

		auth_main(title, &gotd.repos, repo_path);
		/* NOTREACHED */
		break;
	case PROC_SESSION_READ:
	case PROC_SESSION_WRITE:
#ifndef PROFILE
		/*
		 * The "recvfd" promise is only needed during setup and
		 * will be removed in a later pledge(2) call.
		 */
		if (pledge("stdio rpath wpath cpath recvfd sendfd fattr flock "
		    "unveil", NULL) == -1)
			err(1, "pledge");
#endif
		if (proc_id == PROC_SESSION_READ)
			apply_unveil_repo_readonly(repo_path, 1);
		else {
			apply_unveil_repo_readwrite(repo_path);
			repo = gotd_find_repo_by_path(repo_path, &gotd);
			if (repo == NULL)
				fatalx("no repository for path %s", repo_path);
		}

		drop_privs(pw);

		if (proc_id == PROC_SESSION_READ)
			session_read_main(title, repo_path, pack_fds, temp_fds,
			    &gotd.request_timeout, repo);
		else
			session_write_main(title, repo_path, pack_fds, temp_fds,
			    &gotd.request_timeout, repo);
		/* NOTREACHED */
		break;
	case PROC_REPO_READ:
		set_max_datasize();
#ifndef PROFILE
		if (pledge("stdio rpath recvfd unveil", NULL) == -1)
			err(1, "pledge");
#endif
		apply_unveil_repo_readonly(repo_path, 0);

		if (enter_chroot(repo_path)) {
			log_info("change repo path %s", repo_path);
			free(repo_path);
			repo_path = strdup("/");
			if (repo_path == NULL)
				fatal("strdup");
			log_info("repo path is now %s", repo_path);
		}
		drop_privs(pw);

		repo_read_main(title, repo_path, pack_fds, temp_fds);
		/* NOTREACHED */
		exit(0);
	case PROC_REPO_WRITE:
		set_max_datasize();

		diff_f1 = got_opentemp();
		if (diff_f1 == NULL)
			fatal("got_opentemp");
		diff_f2 = got_opentemp();
		if (diff_f2 == NULL)
			fatal("got_opentemp");
		diff_fd1 = got_opentempfd();
		if (diff_fd1 == -1)
			fatal("got_opentempfd");
		diff_fd2 = got_opentempfd();
		if (diff_fd2 == -1)
			fatal("got_opentempfd");
#ifndef PROFILE
		if (pledge("stdio rpath recvfd unveil", NULL) == -1)
			err(1, "pledge");
#endif
		apply_unveil_repo_readonly(repo_path, 0);
		repo = gotd_find_repo_by_path(repo_path, &gotd);
		if (repo == NULL)
			fatalx("no repository for path %s", repo_path);

		if (enter_chroot(repo_path)) {
			free(repo_path);
			repo_path = strdup("/");
			if (repo_path == NULL)
				fatal("strdup");
		}
		drop_privs(pw);

		repo_write_main(title, repo_path, pack_fds, temp_fds,
		    diff_f1, diff_f2, diff_fd1, diff_fd2,
		    &repo->protected_tag_namespaces,
		    &repo->protected_branch_namespaces,
		    &repo->protected_branches);
		/* NOTREACHED */
		exit(0);
	case PROC_NOTIFY:
#ifndef PROFILE
		if (pledge("stdio proc exec recvfd unveil", NULL) == -1)
			err(1, "pledge");
#endif
		/*
		 * Limit "exec" promise to notification helpers via unveil(2).
		 */
		unveil_notification_helpers();

		drop_privs(pw);

		notify_main(title, &gotd.repos, default_sender);
		/* NOTREACHED */
		exit(0);
	default:
		fatal("invalid process id %d", proc_id);
	}

	if (proc_id != PROC_GOTD)
		fatal("invalid process id %d", proc_id);

	evtimer_set(&gotd.listen_proc->tmo, kill_proc_timeout,
	    gotd.listen_proc);
	if (gotd.notify_proc) {
		evtimer_set(&gotd.notify_proc->tmo, kill_proc_timeout,
		    gotd.notify_proc);
	}

	apply_unveil_selfexec();

	signal_set(&evsigint, SIGINT, gotd_sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, gotd_sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, gotd_sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, gotd_sighdlr, NULL);
	signal_set(&evsigchld, SIGCHLD, gotd_sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);
	signal_add(&evsigchld, NULL);

	gotd_imsg_event_add(&gotd.listen_proc->iev);
	if (gotd.notify_proc) {
		struct imsgbuf *imsgbuf = &gotd.notify_proc->iev.ibuf;
		struct gotd_secret *s;
		size_t i, n = 0;

		gotd_imsg_event_add(&gotd.notify_proc->iev);

		if (gotd.secrets)
			n = gotd.secrets->len;

		if (imsg_compose(imsgbuf, GOTD_IMSG_SECRETS, 0, 0, -1,
		    &n, sizeof(n)) == -1)
			fatal("imsg_compose GOTD_IMSG_SECRETS");
		if (imsg_flush(imsgbuf))
			fatal("imsg_flush");

		for (i = 0; i < n; ++i) {
			struct iovec iov[5];
			int keylen, vallen;

			s = &gotd.secrets->secrets[i];

			keylen = strlen(s->key) + 1;
			vallen = strlen(s->val) + 1;

			iov[0].iov_base = &s->type;
			iov[0].iov_len = sizeof(s->type);

			iov[1].iov_base = &keylen;
			iov[1].iov_len = sizeof(keylen);

			iov[2].iov_base = &vallen;
			iov[2].iov_len = sizeof(vallen);

			iov[3].iov_base = s->key;
			iov[3].iov_len = keylen;

			iov[4].iov_base = s->val;
			iov[4].iov_len = vallen;

			if (imsg_composev(imsgbuf, GOTD_IMSG_SECRET,
			    0, 0, -1, iov, 5) == -1)
				fatal("imsg_composev GOTD_IMSG_SECRET");
			if (imsg_flush(imsgbuf))
				fatal("imsg_flush");
		}

		gotd_secrets_free(gotd.secrets);
		gotd.secrets = NULL;
	}

	event_dispatch();

	free(repo_path);
	free(secretspath);
	free(default_sender);
	gotd_shutdown();

	return 0;
}
