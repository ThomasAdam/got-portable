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
#include <sys/tree.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <limits.h>
#include <pwd.h>
#include <imsg.h>
#include <sha1.h>
#include <signal.h>
#include <siphash.h>
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

#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_object_cache.h"
#include "got_lib_sha1.h"
#include "got_lib_gitproto.h"
#include "got_lib_pack.h"
#include "got_lib_repository.h"

#include "gotd.h"
#include "log.h"
#include "listen.h"
#include "auth.h"
#include "repo_read.h"
#include "repo_write.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct gotd_client {
	STAILQ_ENTRY(gotd_client)	 entry;
	enum gotd_client_state		 state;
	struct gotd_client_capability	*capabilities;
	size_t				 ncapa_alloc;
	size_t				 ncapabilities;
	uint32_t			 id;
	int				 fd;
	int				 delta_cache_fd;
	struct gotd_imsgev		 iev;
	struct event			 tmo;
	uid_t				 euid;
	gid_t				 egid;
	struct gotd_child_proc		*repo_read;
	struct gotd_child_proc		*repo_write;
	struct gotd_child_proc		*auth;
	int				 required_auth;
	char				*packfile_path;
	char				*packidx_path;
	int				 nref_updates;
};
STAILQ_HEAD(gotd_clients, gotd_client);

static struct gotd_clients gotd_clients[GOTD_CLIENT_TABLE_SIZE];
static SIPHASH_KEY clients_hash_key;
volatile int client_cnt;
static struct timeval auth_timeout = { 5, 0 };
static struct gotd gotd;

void gotd_sighdlr(int sig, short event, void *arg);
static void gotd_shutdown(void);
static const struct got_error *start_repo_child(struct gotd_client *,
    enum gotd_procid, struct gotd_repo *, char *, const char *, int, int);
static const struct got_error *start_auth_child(struct gotd_client *, int,
    struct gotd_repo *, char *, const char *, int, int);
static void kill_proc(struct gotd_child_proc *, int);

__dead static void
usage()
{
	fprintf(stderr, "usage: %s [-dv] [-f config-file]\n", getprogname());
	exit(1);
}

static int
unix_socket_listen(const char *unix_socket_path, uid_t uid, gid_t gid)
{
	struct sockaddr_un sun;
	int fd = -1;
	mode_t old_umask, mode;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK| SOCK_CLOEXEC, 0);
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

static struct gotd_child_proc *
get_client_proc(struct gotd_client *client)
{
	if (client->repo_read && client->repo_write) {
		fatalx("uid %d is reading and writing in the same session",
		    client->euid);
		/* NOTREACHED */
	}

	if (client->repo_read)
		return client->repo_read;
	else if (client->repo_write)
		return client->repo_write;

	return NULL;
}

static struct gotd_client *
find_client_by_proc_fd(int fd)
{
	uint64_t slot;

	for (slot = 0; slot < nitems(gotd_clients); slot++) {
		struct gotd_client *c;

		STAILQ_FOREACH(c, &gotd_clients[slot], entry) {
			struct gotd_child_proc *proc = get_client_proc(c);
			if (proc && proc->iev.ibuf.fd == fd)
				return c;
			if (c->auth && c->auth->iev.ibuf.fd == fd)
				return c;
		}
	}

	return NULL;
}

static int
client_is_reading(struct gotd_client *client)
{
	return client->repo_read != NULL;
}

static int
client_is_writing(struct gotd_client *client)
{
	return client->repo_write != NULL;
}

static const struct got_error *
ensure_client_is_reading(struct gotd_client *client)
{
	if (!client_is_reading(client)) {
		return got_error_fmt(GOT_ERR_BAD_PACKET,
		    "uid %d made a read-request but is not reading from "
		    "a repository", client->euid);
	}

	return NULL;
}

static const struct got_error *
ensure_client_is_writing(struct gotd_client *client)
{
	if (!client_is_writing(client)) {
		return got_error_fmt(GOT_ERR_BAD_PACKET,
		    "uid %d made a write-request but is not writing to "
		    "a repository", client->euid);
	}

	return NULL;
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
wait_for_child(pid_t child_pid)
{
	pid_t pid;
	int status;

	log_debug("waiting for child PID %ld to terminate",
	    (long)child_pid);

	do {
		pid = waitpid(child_pid, &status, WNOHANG);
		if (pid == -1) {
			if (errno != EINTR && errno != ECHILD)
				fatal("wait");
		} else if (WIFSIGNALED(status)) {
			log_warnx("child PID %ld terminated; signal %d",
			    (long)pid, WTERMSIG(status));
		}
	} while (pid != -1 || (pid == -1 && errno == EINTR));
}

static void
kill_auth_proc(struct gotd_client *client)
{
	struct gotd_child_proc *proc;

	if (client->auth == NULL)
		return;

	proc = client->auth;
	client->auth = NULL;

	event_del(&proc->iev.ev);
	msgbuf_clear(&proc->iev.ibuf.w);
	close(proc->iev.ibuf.fd);
	kill_proc(proc, 0);
	wait_for_child(proc->pid);
	free(proc);
}

static void
disconnect(struct gotd_client *client)
{
	struct gotd_imsg_disconnect idisconnect;
	struct gotd_child_proc *proc = get_client_proc(client);
	struct gotd_child_proc *listen_proc = &gotd.listen_proc;
	uint64_t slot;

	log_debug("uid %d: disconnecting", client->euid);

	kill_auth_proc(client);

	idisconnect.client_id = client->id;
	if (proc) {
		if (gotd_imsg_compose_event(&proc->iev,
		    GOTD_IMSG_DISCONNECT, PROC_GOTD, -1,
		    &idisconnect, sizeof(idisconnect)) == -1)
			log_warn("imsg compose DISCONNECT");

		msgbuf_clear(&proc->iev.ibuf.w);
		close(proc->iev.ibuf.fd);
		kill_proc(proc, 0);
		wait_for_child(proc->pid);
		free(proc);
		proc = NULL;
	}

	if (gotd_imsg_compose_event(&listen_proc->iev,
	    GOTD_IMSG_DISCONNECT, PROC_GOTD, -1,
	    &idisconnect, sizeof(idisconnect)) == -1)
		log_warn("imsg compose DISCONNECT");

	slot = client_hash(client->id) % nitems(gotd_clients);
	STAILQ_REMOVE(&gotd_clients[slot], client, gotd_client, entry);
	imsg_clear(&client->iev.ibuf);
	event_del(&client->iev.ev);
	evtimer_del(&client->tmo);
	close(client->fd);
	if (client->delta_cache_fd != -1)
		close(client->delta_cache_fd);
	if (client->packfile_path) {
		if (unlink(client->packfile_path) == -1 && errno != ENOENT)
			log_warn("unlink %s: ", client->packfile_path);
		free(client->packfile_path);
	}
	if (client->packidx_path) {
		if (unlink(client->packidx_path) == -1 && errno != ENOENT)
			log_warn("unlink %s: ", client->packidx_path);
		free(client->packidx_path);
	}
	free(client->capabilities);
	free(client);
	client_cnt--;
}

static void
disconnect_on_error(struct gotd_client *client, const struct got_error *err)
{
	struct imsgbuf ibuf;

	log_warnx("uid %d: %s", client->euid, err->msg);
	if (err->code != GOT_ERR_EOF) {
		imsg_init(&ibuf, client->fd);
		gotd_imsg_send_error(&ibuf, 0, PROC_GOTD, err);
		imsg_clear(&ibuf);
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
send_capability(struct gotd_client_capability *capa, struct gotd_imsgev* iev)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_capability icapa;
	size_t len;
	struct ibuf *wbuf;

	memset(&icapa, 0, sizeof(icapa));

	icapa.key_len = strlen(capa->key);
	len = sizeof(icapa) + icapa.key_len;
	if (capa->value) {
		icapa.value_len = strlen(capa->value);
		len += icapa.value_len;
	}

	wbuf = imsg_create(&iev->ibuf, GOTD_IMSG_CAPABILITY, 0, 0, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create CAPABILITY");
		return err;
	}

	if (imsg_add(wbuf, &icapa, sizeof(icapa)) == -1)
		return got_error_from_errno("imsg_add CAPABILITY");
	if (imsg_add(wbuf, capa->key, icapa.key_len) == -1)
		return got_error_from_errno("imsg_add CAPABILITY");
	if (capa->value) {
		if (imsg_add(wbuf, capa->value, icapa.value_len) == -1)
			return got_error_from_errno("imsg_add CAPABILITY");
	}

	wbuf->fd = -1;
	imsg_close(&iev->ibuf, wbuf);

	gotd_imsg_event_add(iev);

	return NULL;
}

static const struct got_error *
send_client_info(struct gotd_imsgev *iev, struct gotd_client *client)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_info_client iclient;
	struct gotd_child_proc *proc;
	size_t i;

	memset(&iclient, 0, sizeof(iclient));
	iclient.euid = client->euid;
	iclient.egid = client->egid;

	proc = get_client_proc(client);
	if (proc) {
		if (strlcpy(iclient.repo_name, proc->repo_path,
		    sizeof(iclient.repo_name)) >= sizeof(iclient.repo_name)) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "repo name too long");
		}
		if (client_is_writing(client))
			iclient.is_writing = 1;
	}

	iclient.state = client->state;
	iclient.ncapabilities = client->ncapabilities;

	if (gotd_imsg_compose_event(iev, GOTD_IMSG_INFO_CLIENT, PROC_GOTD, -1,
	    &iclient, sizeof(iclient)) == -1) {
		err = got_error_from_errno("imsg compose INFO_CLIENT");
		if (err)
			return err;
	}

	for (i = 0; i < client->ncapabilities; i++) {
		struct gotd_client_capability *capa;
		capa = &client->capabilities[i];
		err = send_capability(capa, iev);
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

static struct gotd_repo *
find_repo_by_name(const char *repo_name)
{
	struct gotd_repo *repo;
	size_t namelen;

	TAILQ_FOREACH(repo, &gotd.repos, entry) {
		namelen = strlen(repo->name);
		if (strncmp(repo->name, repo_name, namelen) != 0)
			continue;
		if (repo_name[namelen] == '\0' ||
		    strcmp(&repo_name[namelen], ".git") == 0)
			return repo;
	}

	return NULL;
}

static const struct got_error *
start_client_session(struct gotd_client *client, struct imsg *imsg)
{
	const struct got_error *err;
	struct gotd_imsg_list_refs ireq;
	struct gotd_repo *repo = NULL;
	size_t datalen;

	log_debug("list-refs request from uid %d", client->euid);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&ireq, imsg->data, datalen);

	if (ireq.client_is_reading) {
		err = ensure_client_is_not_writing(client);
		if (err)
			return err;
		repo = find_repo_by_name(ireq.repo_name);
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
		repo = find_repo_by_name(ireq.repo_name);
		if (repo == NULL)
			return got_error(GOT_ERR_NOT_GIT_REPO);
		err = start_auth_child(client,
		    GOTD_AUTH_READ | GOTD_AUTH_WRITE,
		    repo, gotd.argv0, gotd.confpath, gotd.daemonize,
		    gotd.verbosity);
		if (err)
			return err;
	}

	/* Flow continues upon authentication successs/failure or timeout. */
	return NULL;
}

static const struct got_error *
forward_want(struct gotd_client *client, struct imsg *imsg)
{
	struct gotd_imsg_want ireq;
	struct gotd_imsg_want iwant;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&ireq, imsg->data, datalen);

	memset(&iwant, 0, sizeof(iwant));
	memcpy(iwant.object_id, ireq.object_id, SHA1_DIGEST_LENGTH);
	iwant.client_id = client->id;

	if (gotd_imsg_compose_event(&client->repo_read->iev, GOTD_IMSG_WANT,
	    PROC_GOTD, -1, &iwant, sizeof(iwant)) == -1)
		return got_error_from_errno("imsg compose WANT");

	return NULL;
}

static const struct got_error *
forward_ref_update(struct gotd_client *client, struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_ref_update ireq;
	struct gotd_imsg_ref_update *iref = NULL;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ireq, imsg->data, sizeof(ireq));
	if (datalen != sizeof(ireq) + ireq.name_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	iref = malloc(datalen);
	if (iref == NULL)
		return got_error_from_errno("malloc");
	memcpy(iref, imsg->data, datalen);

	iref->client_id = client->id;
	if (gotd_imsg_compose_event(&client->repo_write->iev,
	    GOTD_IMSG_REF_UPDATE, PROC_GOTD, -1, iref, datalen) == -1)
		err = got_error_from_errno("imsg compose REF_UPDATE");
	free(iref);
	return err;
}

static const struct got_error *
forward_have(struct gotd_client *client, struct imsg *imsg)
{
	struct gotd_imsg_have ireq;
	struct gotd_imsg_have ihave;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&ireq, imsg->data, datalen);

	memset(&ihave, 0, sizeof(ihave));
	memcpy(ihave.object_id, ireq.object_id, SHA1_DIGEST_LENGTH);
	ihave.client_id = client->id;

	if (gotd_imsg_compose_event(&client->repo_read->iev, GOTD_IMSG_HAVE,
	    PROC_GOTD, -1, &ihave, sizeof(ihave)) == -1)
		return got_error_from_errno("imsg compose HAVE");

	return NULL;
}

static int
client_has_capability(struct gotd_client *client, const char *capastr)
{
	struct gotd_client_capability *capa;
	size_t i;

	if (client->ncapabilities == 0)
		return 0;

	for (i = 0; i < client->ncapabilities; i++) {
		capa = &client->capabilities[i];
		if (strcmp(capa->key, capastr) == 0)
			return 1;
	}

	return 0;
}

static const struct got_error *
recv_capabilities(struct gotd_client *client, struct imsg *imsg)
{
	struct gotd_imsg_capabilities icapas;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(icapas))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&icapas, imsg->data, sizeof(icapas));

	client->ncapa_alloc = icapas.ncapabilities;
	client->capabilities = calloc(client->ncapa_alloc,
	    sizeof(*client->capabilities));
	if (client->capabilities == NULL) {
		client->ncapa_alloc = 0;
		return got_error_from_errno("calloc");
	}

	log_debug("expecting %zu capabilities from uid %d",
	    client->ncapa_alloc, client->euid);
	return NULL;
}

static const struct got_error *
recv_capability(struct gotd_client *client, struct imsg *imsg)
{
	struct gotd_imsg_capability icapa;
	struct gotd_client_capability *capa;
	size_t datalen;
	char *key, *value = NULL;

	if (client->capabilities == NULL ||
	    client->ncapabilities >= client->ncapa_alloc) {
		return got_error_msg(GOT_ERR_BAD_REQUEST,
		    "unexpected capability received");
	}

	memset(&icapa, 0, sizeof(icapa));

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(icapa))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&icapa, imsg->data, sizeof(icapa));

	if (datalen != sizeof(icapa) + icapa.key_len + icapa.value_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	key = malloc(icapa.key_len + 1);
	if (key == NULL)
		return got_error_from_errno("malloc");
	if (icapa.value_len > 0) {
		value = malloc(icapa.value_len + 1);
		if (value == NULL) {
			free(key);
			return got_error_from_errno("malloc");
		}
	}

	memcpy(key, imsg->data + sizeof(icapa), icapa.key_len);
	key[icapa.key_len] = '\0';
	if (value) {
		memcpy(value, imsg->data + sizeof(icapa) + icapa.key_len,
		    icapa.value_len);
		value[icapa.value_len] = '\0';
	}

	capa = &client->capabilities[client->ncapabilities++];
	capa->key = key;
	capa->value = value;

	if (value)
		log_debug("uid %d: capability %s=%s", client->euid, key, value);
	else
		log_debug("uid %d: capability %s", client->euid, key);

	return NULL;
}

static const struct got_error *
send_packfile(struct gotd_client *client)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_send_packfile ipack;
	struct gotd_imsg_packfile_pipe ipipe;
	int pipe[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pipe) == -1)
		return got_error_from_errno("socketpair");

	memset(&ipack, 0, sizeof(ipack));
	memset(&ipipe, 0, sizeof(ipipe));

	ipack.client_id = client->id;
	if (client_has_capability(client, GOT_CAPA_SIDE_BAND_64K))
		ipack.report_progress = 1;

	client->delta_cache_fd = got_opentempfd();
	if (client->delta_cache_fd == -1)
		return got_error_from_errno("got_opentempfd");

	if (gotd_imsg_compose_event(&client->repo_read->iev,
	    GOTD_IMSG_SEND_PACKFILE, PROC_GOTD, client->delta_cache_fd,
	    &ipack, sizeof(ipack)) == -1) {
		err = got_error_from_errno("imsg compose SEND_PACKFILE");
		close(pipe[0]);
		close(pipe[1]);
		return err;
	}

	ipipe.client_id = client->id;

	/* Send pack pipe end 0 to repo_read. */
	if (gotd_imsg_compose_event(&client->repo_read->iev,
	    GOTD_IMSG_PACKFILE_PIPE, PROC_GOTD, pipe[0],
	        &ipipe, sizeof(ipipe)) == -1) {
		err = got_error_from_errno("imsg compose PACKFILE_PIPE");
		close(pipe[1]);
		return err;
	}

	/* Send pack pipe end 1 to gotsh(1) (expects just an fd, no data). */
	if (gotd_imsg_compose_event(&client->iev,
	    GOTD_IMSG_PACKFILE_PIPE, PROC_GOTD, pipe[1], NULL, 0) == -1)
		err = got_error_from_errno("imsg compose PACKFILE_PIPE");

	return err;
}

static const struct got_error *
recv_packfile(struct gotd_client *client)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_recv_packfile ipack;
	struct gotd_imsg_packfile_pipe ipipe;
	struct gotd_imsg_packidx_file ifile;
	char *basepath = NULL, *pack_path = NULL, *idx_path = NULL;
	int packfd = -1, idxfd = -1;
	int pipe[2] = { -1, -1 };

	if (client->packfile_path) {
		return got_error_fmt(GOT_ERR_PRIVSEP_MSG,
		    "uid %d already has a pack file", client->euid);
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pipe) == -1)
		return got_error_from_errno("socketpair");

	memset(&ipipe, 0, sizeof(ipipe));
	ipipe.client_id = client->id;

	/* Send pack pipe end 0 to repo_write. */
	if (gotd_imsg_compose_event(&client->repo_write->iev,
	    GOTD_IMSG_PACKFILE_PIPE, PROC_GOTD, pipe[0],
	        &ipipe, sizeof(ipipe)) == -1) {
		err = got_error_from_errno("imsg compose PACKFILE_PIPE");
		pipe[0] = -1;
		goto done;
	}
	pipe[0] = -1;

	/* Send pack pipe end 1 to gotsh(1) (expects just an fd, no data). */
	if (gotd_imsg_compose_event(&client->iev,
	    GOTD_IMSG_PACKFILE_PIPE, PROC_GOTD, pipe[1], NULL, 0) == -1)
		err = got_error_from_errno("imsg compose PACKFILE_PIPE");
	pipe[1] = -1;

	if (asprintf(&basepath, "%s/%s/receiving-from-uid-%d.pack",
	    client->repo_write->repo_path, GOT_OBJECTS_PACK_DIR,
	    client->euid) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_opentemp_named_fd(&pack_path, &packfd, basepath, "");
	if (err)
		goto done;

	free(basepath);
	if (asprintf(&basepath, "%s/%s/receiving-from-uid-%d.idx",
	    client->repo_write->repo_path, GOT_OBJECTS_PACK_DIR,
	    client->euid) == -1) {
		err = got_error_from_errno("asprintf");
		basepath = NULL;
		goto done;
	}
	err = got_opentemp_named_fd(&idx_path, &idxfd, basepath, "");
	if (err)
		goto done;

	memset(&ifile, 0, sizeof(ifile));
	ifile.client_id = client->id;
	if (gotd_imsg_compose_event(&client->repo_write->iev,
	    GOTD_IMSG_PACKIDX_FILE, PROC_GOTD, idxfd,
	    &ifile, sizeof(ifile)) == -1) {
		err = got_error_from_errno("imsg compose PACKIDX_FILE");
		idxfd = -1;
		goto done;
	}
	idxfd = -1;

	memset(&ipack, 0, sizeof(ipack));
	ipack.client_id = client->id;
	if (client_has_capability(client, GOT_CAPA_REPORT_STATUS))
		ipack.report_status = 1;

	if (gotd_imsg_compose_event(&client->repo_write->iev,
	    GOTD_IMSG_RECV_PACKFILE, PROC_GOTD, packfd,
	    &ipack, sizeof(ipack)) == -1) {
		err = got_error_from_errno("imsg compose RECV_PACKFILE");
		packfd = -1;
		goto done;
	}
	packfd = -1;

done:
	free(basepath);
	if (pipe[0] != -1 && close(pipe[0]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (pipe[1] != -1 && close(pipe[1]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (idxfd != -1 && close(idxfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (err) {
		free(pack_path);
		free(idx_path);
	} else {
		client->packfile_path = pack_path;
		client->packidx_path = idx_path;
	}
	return err;
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
				err = got_error_from_errno("imsg_flush");
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
			if (client->state != GOTD_STATE_EXPECT_LIST_REFS) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected list-refs request received");
				break;
			}
			err = start_client_session(client, &imsg);
			if (err)
				break;
			break;
		case GOTD_IMSG_CAPABILITIES:
			if (client->state != GOTD_STATE_EXPECT_CAPABILITIES) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected capabilities received");
				break;
			}
			log_debug("receiving capabilities from uid %d",
			    client->euid);
			err = recv_capabilities(client, &imsg);
			break;
		case GOTD_IMSG_CAPABILITY:
			if (client->state != GOTD_STATE_EXPECT_CAPABILITIES) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected capability received");
				break;
			}
			err = recv_capability(client, &imsg);
			if (err || client->ncapabilities < client->ncapa_alloc)
				break;
			if (client_is_reading(client)) {
				client->state = GOTD_STATE_EXPECT_WANT;
				log_debug("uid %d: expecting want-lines",
				    client->euid);
			} else if (client_is_writing(client)) {
				client->state = GOTD_STATE_EXPECT_REF_UPDATE;
				log_debug("uid %d: expecting ref-update-lines",
				    client->euid);
			} else
				fatalx("client %d is both reading and writing",
				    client->euid);
			break;
		case GOTD_IMSG_WANT:
			if (client->state != GOTD_STATE_EXPECT_WANT) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected want-line received");
				break;
			}
			log_debug("received want-line from uid %d",
			    client->euid);
			err = ensure_client_is_reading(client);
			if (err)
				break;
			err = forward_want(client, &imsg);
			break;
		case GOTD_IMSG_REF_UPDATE:
			if (client->state != GOTD_STATE_EXPECT_REF_UPDATE) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected ref-update-line received");
				break;
			}
			log_debug("received ref-update-line from uid %d",
			    client->euid);
			err = ensure_client_is_writing(client);
			if (err)
				break;
			err = forward_ref_update(client, &imsg);
			if (err)
				break;
			client->state = GOTD_STATE_EXPECT_MORE_REF_UPDATES;
			break;
		case GOTD_IMSG_HAVE:
			if (client->state != GOTD_STATE_EXPECT_HAVE) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected have-line received");
				break;
			}
			log_debug("received have-line from uid %d",
			    client->euid);
			err = ensure_client_is_reading(client);
			if (err)
				break;
			err = forward_have(client, &imsg);
			if (err)
				break;
			break;
		case GOTD_IMSG_FLUSH:
			if (client->state == GOTD_STATE_EXPECT_WANT ||
			    client->state == GOTD_STATE_EXPECT_HAVE) {
				err = ensure_client_is_reading(client);
				if (err)
					break;
			} else if (client->state ==
			    GOTD_STATE_EXPECT_MORE_REF_UPDATES) {
				err = ensure_client_is_writing(client);
				if (err)
					break;
			} else {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected flush-pkt received");
				break;
			}
			log_debug("received flush-pkt from uid %d",
			    client->euid);
			if (client->state == GOTD_STATE_EXPECT_WANT) {
				client->state = GOTD_STATE_EXPECT_HAVE;
				log_debug("uid %d: expecting have-lines",
				    client->euid);
			} else if (client->state == GOTD_STATE_EXPECT_HAVE) {
				client->state = GOTD_STATE_EXPECT_DONE;
				log_debug("uid %d: expecting 'done'",
				    client->euid);
			} else if (client->state ==
			    GOTD_STATE_EXPECT_MORE_REF_UPDATES) {
				client->state = GOTD_STATE_EXPECT_PACKFILE;
				log_debug("uid %d: expecting packfile",
				    client->euid);
				err = recv_packfile(client);
			} else {
				/* should not happen, see above */
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected client state");
				break;
			}
			break;
		case GOTD_IMSG_DONE:
			if (client->state != GOTD_STATE_EXPECT_HAVE &&
			    client->state != GOTD_STATE_EXPECT_DONE) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected flush-pkt received");
				break;
			}
			log_debug("received 'done' from uid %d", client->euid);
			err = ensure_client_is_reading(client);
			if (err)
				break;
			client->state = GOTD_STATE_DONE;
			err = send_packfile(client);
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}

	if (err) {
		if (err->code != GOT_ERR_EOF ||
		    client->state != GOTD_STATE_EXPECT_PACKFILE)
			disconnect_on_error(client, err);
	} else {
		gotd_imsg_event_add(&client->iev);
		if (client->state == GOTD_STATE_EXPECT_LIST_REFS)
			evtimer_add(&client->tmo, &auth_timeout);
		else
			evtimer_add(&client->tmo, &gotd.request_timeout);
	}
}

static void
gotd_request_timeout(int fd, short events, void *arg)
{
	struct gotd_client *client = arg;

	log_debug("disconnecting uid %d due to timeout", client->euid);
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

	s = imsg->fd;
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

	client->state = GOTD_STATE_EXPECT_LIST_REFS;
	client->id = iconnect.client_id;
	client->fd = s;
	s = -1;
	client->delta_cache_fd = -1;
	/* The auth process will verify UID/GID for us. */
	client->euid = iconnect.euid;
	client->egid = iconnect.egid;
	client->nref_updates = -1;

	imsg_init(&client->iev.ibuf, client->fd);
	client->iev.handler = gotd_request;
	client->iev.events = EV_READ;
	client->iev.handler_arg = client;

	event_set(&client->iev.ev, client->fd, EV_READ, gotd_request,
	    &client->iev);
	gotd_imsg_event_add(&client->iev);

	evtimer_set(&client->tmo, gotd_request_timeout, client);

	add_client(client);
	log_debug("%s: new client uid %d connected on fd %d", __func__,
	    client->euid, client->fd);
done:
	if (err) {
		struct gotd_child_proc *listen_proc = &gotd.listen_proc;
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
	"repo_read",
	"repo_write"
};

static void
kill_proc(struct gotd_child_proc *proc, int fatal)
{
	if (fatal) {
		log_warnx("sending SIGKILL to PID %d", proc->pid);
		kill(proc->pid, SIGKILL);
	} else
		kill(proc->pid, SIGTERM);
}

static void
gotd_shutdown(void)
{
	struct gotd_child_proc *proc;
	uint64_t slot;

	for (slot = 0; slot < nitems(gotd_clients); slot++) {
		struct gotd_client *c, *tmp;

		STAILQ_FOREACH_SAFE(c, &gotd_clients[slot], entry, tmp)
			disconnect(c);
	}

	proc = &gotd.listen_proc;
	msgbuf_clear(&proc->iev.ibuf.w);
	close(proc->iev.ibuf.fd);
	kill_proc(proc, 0);
	wait_for_child(proc->pid);

	log_info("terminating");
	exit(0);
}

void
gotd_sighdlr(int sig, short event, void *arg)
{
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
	struct gotd_child_proc *client_proc;
	int ret = 0;

	if (proc->type == PROC_REPO_READ || proc->type == PROC_REPO_WRITE) {
		client_proc = get_client_proc(client);
		if (client_proc == NULL)
			fatalx("no process found for uid %d", client->euid);
		if (proc->pid != client_proc->pid) {
			kill_proc(proc, 1);
			log_warnx("received message from PID %d for uid %d, "
			    "while PID %d is the process serving this user",
			    proc->pid, client->euid, client_proc->pid);
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
			    proc->pid, client->euid);
		} else
			ret = 1;
		break;
	case GOTD_IMSG_ACCESS_GRANTED:
		if (proc->type != PROC_AUTH) {
			err = got_error_fmt(GOT_ERR_BAD_PACKET,
			    "authentication of uid %d from PID %d "
			    "which is not the auth process",
			    proc->pid, client->euid);
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
list_refs_request(struct gotd_client *client, struct gotd_imsgev *iev)
{
	static const struct got_error *err;
	struct gotd_imsg_list_refs_internal ilref;
	int fd;

	memset(&ilref, 0, sizeof(ilref));
	ilref.client_id = client->id;

	fd = dup(client->fd);
	if (fd == -1)
		return got_error_from_errno("dup");

	if (gotd_imsg_compose_event(iev, GOTD_IMSG_LIST_REFS_INTERNAL,
	    PROC_GOTD, fd, &ilref, sizeof(ilref)) == -1) {
		err = got_error_from_errno("imsg compose WANT");
		close(fd);
		return err;
	}

	client->state = GOTD_STATE_EXPECT_CAPABILITIES;
	log_debug("uid %d: expecting capabilities", client->euid);
	return NULL;
}

static const struct got_error *
recv_packfile_done(uint32_t *client_id, struct imsg *imsg)
{
	struct gotd_imsg_packfile_done idone;
	size_t datalen;

	log_debug("packfile-done received");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(idone))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&idone, imsg->data, sizeof(idone));

	*client_id = idone.client_id;
	return NULL;
}

static const struct got_error *
recv_packfile_install(uint32_t *client_id, struct imsg *imsg)
{
	struct gotd_imsg_packfile_install inst;
	size_t datalen;

	log_debug("packfile-install received");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(inst))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&inst, imsg->data, sizeof(inst));

	*client_id = inst.client_id;
	return NULL;
}

static const struct got_error *
recv_ref_updates_start(uint32_t *client_id, struct imsg *imsg)
{
	struct gotd_imsg_ref_updates_start istart;
	size_t datalen;

	log_debug("ref-updates-start received");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(istart))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&istart, imsg->data, sizeof(istart));

	*client_id = istart.client_id;
	return NULL;
}

static const struct got_error *
recv_ref_update(uint32_t *client_id, struct imsg *imsg)
{
	struct gotd_imsg_ref_update iref;
	size_t datalen;

	log_debug("ref-update received");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(iref))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iref, imsg->data, sizeof(iref));

	*client_id = iref.client_id;
	return NULL;
}

static const struct got_error *
send_ref_update_ok(struct gotd_client *client,
    struct gotd_imsg_ref_update *iref, const char *refname)
{
	struct gotd_imsg_ref_update_ok iok;
	struct ibuf *wbuf;
	size_t len;

	memset(&iok, 0, sizeof(iok));
	iok.client_id = client->id;
	memcpy(iok.old_id, iref->old_id, SHA1_DIGEST_LENGTH);
	memcpy(iok.new_id, iref->new_id, SHA1_DIGEST_LENGTH);
	iok.name_len = strlen(refname);

	len = sizeof(iok) + iok.name_len;
	wbuf = imsg_create(&client->iev.ibuf, GOTD_IMSG_REF_UPDATE_OK,
	    PROC_GOTD, gotd.pid, len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create REF_UPDATE_OK");

	if (imsg_add(wbuf, &iok, sizeof(iok)) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE_OK");
	if (imsg_add(wbuf, refname, iok.name_len) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE_OK");

	wbuf->fd = -1;
	imsg_close(&client->iev.ibuf, wbuf);
	gotd_imsg_event_add(&client->iev);
	return NULL;
}

static void
send_refs_updated(struct gotd_client *client)
{
	if (gotd_imsg_compose_event(&client->iev,
	    GOTD_IMSG_REFS_UPDATED, PROC_GOTD, -1, NULL, 0) == -1)
		log_warn("imsg compose REFS_UPDATED");
}

static const struct got_error *
send_ref_update_ng(struct gotd_client *client,
    struct gotd_imsg_ref_update *iref, const char *refname,
    const char *reason)
{
	const struct got_error *ng_err;
	struct gotd_imsg_ref_update_ng ing;
	struct ibuf *wbuf;
	size_t len;

	memset(&ing, 0, sizeof(ing));
	ing.client_id = client->id;
	memcpy(ing.old_id, iref->old_id, SHA1_DIGEST_LENGTH);
	memcpy(ing.new_id, iref->new_id, SHA1_DIGEST_LENGTH);
	ing.name_len = strlen(refname);

	ng_err = got_error_fmt(GOT_ERR_REF_BUSY, "%s", reason);
	ing.reason_len = strlen(ng_err->msg);

	len = sizeof(ing) + ing.name_len + ing.reason_len;
	wbuf = imsg_create(&client->iev.ibuf, GOTD_IMSG_REF_UPDATE_NG,
	    PROC_GOTD, gotd.pid, len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create REF_UPDATE_NG");

	if (imsg_add(wbuf, &ing, sizeof(ing)) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE_NG");
	if (imsg_add(wbuf, refname, ing.name_len) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE_NG");
	if (imsg_add(wbuf, ng_err->msg, ing.reason_len) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE_NG");

	wbuf->fd = -1;
	imsg_close(&client->iev.ibuf, wbuf);
	gotd_imsg_event_add(&client->iev);
	return NULL;
}

static const struct got_error *
install_pack(struct gotd_client *client, const char *repo_path,
    struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_packfile_install inst;
	char hex[SHA1_DIGEST_STRING_LENGTH];
	size_t datalen;
	char *packfile_path = NULL, *packidx_path = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(inst))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&inst, imsg->data, sizeof(inst));

	if (client->packfile_path == NULL)
		return got_error_msg(GOT_ERR_BAD_REQUEST,
		    "client has no pack file");
	if (client->packidx_path == NULL)
		return got_error_msg(GOT_ERR_BAD_REQUEST,
		    "client has no pack file index");

	if (got_sha1_digest_to_str(inst.pack_sha1, hex, sizeof(hex)) == NULL)
		return got_error_msg(GOT_ERR_NO_SPACE,
		    "could not convert pack file SHA1 to hex");

	if (asprintf(&packfile_path, "/%s/%s/pack-%s.pack",
	    repo_path, GOT_OBJECTS_PACK_DIR, hex) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (asprintf(&packidx_path, "/%s/%s/pack-%s.idx",
	    repo_path, GOT_OBJECTS_PACK_DIR, hex) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (rename(client->packfile_path, packfile_path) == -1) {
		err = got_error_from_errno3("rename", client->packfile_path,
		    packfile_path);
		goto done;
	}

	free(client->packfile_path);
	client->packfile_path = NULL;

	if (rename(client->packidx_path, packidx_path) == -1) {
		err = got_error_from_errno3("rename", client->packidx_path,
		    packidx_path);
		goto done;
	}

	free(client->packidx_path);
	client->packidx_path = NULL;
done:
	free(packfile_path);
	free(packidx_path);
	return err;
}

static const struct got_error *
begin_ref_updates(struct gotd_client *client, struct imsg *imsg)
{
	struct gotd_imsg_ref_updates_start istart;
	size_t datalen;

	if (client->nref_updates != -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(istart))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&istart, imsg->data, sizeof(istart));

	if (istart.nref_updates <= 0)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	client->nref_updates = istart.nref_updates;
	return NULL;
}

static const struct got_error *
update_ref(struct gotd_client *client, const char *repo_path,
    struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct got_repository *repo = NULL;
	struct got_reference *ref = NULL;
	struct gotd_imsg_ref_update iref;
	struct got_object_id old_id, new_id;
	struct got_object_id *id = NULL;
	struct got_object *obj = NULL;
	char *refname = NULL;
	size_t datalen;
	int locked = 0;

	log_debug("update-ref from uid %d", client->euid);

	if (client->nref_updates <= 0)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(iref))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iref, imsg->data, sizeof(iref));
	if (datalen != sizeof(iref) + iref.name_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);
	refname = malloc(iref.name_len + 1);
	if (refname == NULL)
		return got_error_from_errno("malloc");
	memcpy(refname, imsg->data + sizeof(iref), iref.name_len);
	refname[iref.name_len] = '\0';

	log_debug("updating ref %s for uid %d", refname, client->euid);

	err = got_repo_open(&repo, repo_path, NULL, NULL);
	if (err)
		goto done;

	memcpy(old_id.sha1, iref.old_id, SHA1_DIGEST_LENGTH);
	memcpy(new_id.sha1, iref.new_id, SHA1_DIGEST_LENGTH);
	err = got_object_open(&obj, repo, &new_id);
	if (err)
		goto done;

	if (iref.ref_is_new) {
		err = got_ref_open(&ref, repo, refname, 0);
		if (err) {
			if (err->code != GOT_ERR_NOT_REF)
				goto done;
			err = got_ref_alloc(&ref, refname, &new_id);
			if (err)
				goto done;
			err = got_ref_write(ref, repo); /* will lock/unlock */
			if (err)
				goto done;
		} else {
			err = got_error_fmt(GOT_ERR_REF_BUSY,
			    "%s has been created by someone else "
			    "while transaction was in progress",
			    got_ref_get_name(ref));
			goto done;
		}
	} else {
		err = got_ref_open(&ref, repo, refname, 1 /* lock */);
		if (err)
			goto done;
		locked = 1;

		err = got_ref_resolve(&id, repo, ref);
		if (err)
			goto done;

		if (got_object_id_cmp(id, &old_id) != 0) {
			err = got_error_fmt(GOT_ERR_REF_BUSY,
			    "%s has been modified by someone else "
			    "while transaction was in progress",
			    got_ref_get_name(ref));
			goto done;
		}

		err = got_ref_change_ref(ref, &new_id);
		if (err)
			goto done;

		err = got_ref_write(ref, repo);
		if (err)
			goto done;

		free(id);
		id = NULL;
	}
done:
	if (err) {
		if (err->code == GOT_ERR_LOCKFILE_TIMEOUT) {
			err = got_error_fmt(GOT_ERR_LOCKFILE_TIMEOUT,
			    "could not acquire exclusive file lock for %s",
			    refname);
		}
		send_ref_update_ng(client, &iref, refname, err->msg);
	} else
		send_ref_update_ok(client, &iref, refname);

	if (client->nref_updates > 0) {
		client->nref_updates--;
		if (client->nref_updates == 0)
			send_refs_updated(client);

	}
	if (locked) {
		const struct got_error *unlock_err;
		unlock_err = got_ref_unlock(ref);
		if (unlock_err && err == NULL)
			err = unlock_err;
	}
	if (ref)
		got_ref_close(ref);
	if (obj)
		got_object_close(obj);
	if (repo)
		got_repo_close(repo);
	free(refname);
	free(id);
	return err;
}

static void
gotd_dispatch_listener(int fd, short event, void *arg)
{
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_child_proc *proc = &gotd.listen_proc;
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
	enum gotd_procid proc_type;

	client = find_client_by_proc_fd(fd);
	if (client == NULL)
		fatalx("cannot find client for fd %d", fd);

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

	switch (imsg.hdr.type) {
	case GOTD_IMSG_ERROR:
		do_disconnect = 1;
		err = gotd_imsg_recv_error(&client_id, &imsg);
		break;
	case GOTD_IMSG_ACCESS_GRANTED:
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
	imsg_free(&imsg);

	if (do_disconnect) {
		if (err)
			disconnect_on_error(client, err);
		else
			disconnect(client);
		goto done;
	}

	repo = find_repo_by_name(client->auth->repo_name);
	if (repo == NULL) {
		err = got_error(GOT_ERR_NOT_GIT_REPO);
		goto done;
	}
	kill_auth_proc(client);

	log_info("authenticated uid %d for repository %s\n",
	    client->euid, repo->name);

	if (client->required_auth & GOTD_AUTH_WRITE)
		proc_type = PROC_REPO_WRITE;
	else
		proc_type = PROC_REPO_READ;

	err = start_repo_child(client, proc_type, repo, gotd.argv0,
	    gotd.confpath, gotd.daemonize, gotd.verbosity);
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

static void
gotd_dispatch_repo_child(int fd, short event, void *arg)
{
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_child_proc *proc = NULL;
	struct gotd_client *client = NULL;
	ssize_t n;
	int shut = 0;
	struct imsg imsg;

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

	client = find_client_by_proc_fd(fd);
	if (client == NULL)
		fatalx("cannot find client for fd %d", fd);

	proc = get_client_proc(client);
	if (proc == NULL)
		fatalx("cannot find child process for fd %d", fd);

	for (;;) {
		const struct got_error *err = NULL;
		uint32_t client_id = 0;
		int do_disconnect = 0;
		int do_list_refs = 0, do_ref_updates = 0, do_ref_update = 0;
		int do_packfile_install = 0;

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
			do_list_refs = 1;
			break;
		case GOTD_IMSG_PACKFILE_DONE:
			do_disconnect = 1;
			err = recv_packfile_done(&client_id, &imsg);
			break;
		case GOTD_IMSG_PACKFILE_INSTALL:
			err = recv_packfile_install(&client_id, &imsg);
			if (err == NULL)
				do_packfile_install = 1;
			break;
		case GOTD_IMSG_REF_UPDATES_START:
			err = recv_ref_updates_start(&client_id, &imsg);
			if (err == NULL)
				do_ref_updates = 1;
			break;
		case GOTD_IMSG_REF_UPDATE:
			err = recv_ref_update(&client_id, &imsg);
			if (err == NULL)
				do_ref_update = 1;
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
		} else {
			if (do_list_refs)
				err = list_refs_request(client, iev);
			else if (do_packfile_install)
				err = install_pack(client, proc->repo_path,
				    &imsg);
			else if (do_ref_updates)
				err = begin_ref_updates(client, &imsg);
			else if (do_ref_update)
				err = update_ref(client, proc->repo_path,
				    &imsg);
			if (err)
				log_warnx("uid %d: %s", client->euid, err->msg);
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

static pid_t
start_child(enum gotd_procid proc_id, const char *repo_path,
    char *argv0, const char *confpath, int fd, int daemonize, int verbosity)
{
	char	*argv[11];
	int	 argc = 0;
	pid_t	 pid;

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
		argv[argc++] = (char *)"-L";
		break;
	case PROC_AUTH:
		argv[argc++] = (char *)"-A";
		break;
	case PROC_REPO_READ:
		argv[argc++] = (char *)"-R";
		break;
	case PROC_REPO_WRITE:
		argv[argc++] = (char *)"-W";
		break;
	default:
		fatalx("invalid process id %d", proc_id);
	}

	argv[argc++] = (char *)"-f";
	argv[argc++] = (char *)confpath;

	if (repo_path) {
		argv[argc++] = (char *)"-P";
		argv[argc++] = (char *)repo_path;
	}

	if (!daemonize)
		argv[argc++] = (char *)"-d";
	if (verbosity > 0)
		argv[argc++] = (char *)"-v";
	if (verbosity > 1)
		argv[argc++] = (char *)"-v";
	argv[argc++] = NULL;

	execvp(argv0, argv);
	fatal("execvp");
}

static void
start_listener(char *argv0, const char *confpath, int daemonize, int verbosity)
{
	struct gotd_child_proc *proc = &gotd.listen_proc;

	proc->type = PROC_LISTEN;

	if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,
	    PF_UNSPEC, proc->pipe) == -1)
		fatal("socketpair");

	proc->pid = start_child(proc->type, NULL, argv0, confpath,
	    proc->pipe[1], daemonize, verbosity);
	imsg_init(&proc->iev.ibuf, proc->pipe[0]);
	proc->iev.handler = gotd_dispatch_listener;
	proc->iev.events = EV_READ;
	proc->iev.handler_arg = NULL;
}

static const struct got_error *
start_repo_child(struct gotd_client *client, enum gotd_procid proc_type,
    struct gotd_repo *repo, char *argv0, const char *confpath,
    int daemonize, int verbosity)
{
	struct gotd_child_proc *proc;

	if (proc_type != PROC_REPO_READ && proc_type != PROC_REPO_WRITE)
		return got_error_msg(GOT_ERR_NOT_IMPL, "bad process type");

	proc = calloc(1, sizeof(*proc));
	if (proc == NULL)
		return got_error_from_errno("calloc");

	proc->type = proc_type;
	if (strlcpy(proc->repo_name, repo->name,
	    sizeof(proc->repo_name)) >= sizeof(proc->repo_name))
		fatalx("repository name too long: %s", repo->name);
	log_debug("starting %s for repository %s",
	    proc->type == PROC_REPO_READ ? "reader" : "writer", repo->name);
	if (strlcpy(proc->repo_path, repo->path, sizeof(proc->repo_path)) >=
	    sizeof(proc->repo_path))
		fatalx("repository path too long: %s", repo->path);
	if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,
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

	if (proc->type == PROC_REPO_READ)
		client->repo_read = proc;
	else
		client->repo_write = proc;

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

	proc->type = PROC_AUTH;
	if (strlcpy(proc->repo_name, repo->name,
	    sizeof(proc->repo_name)) >= sizeof(proc->repo_name))
		fatalx("repository name too long: %s", repo->name);
	log_debug("starting auth for uid %d repository %s",
	    client->euid, repo->name);
	if (strlcpy(proc->repo_path, repo->path, sizeof(proc->repo_path)) >=
	    sizeof(proc->repo_path))
		fatalx("repository path too long: %s", repo->path);
	if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,
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
apply_unveil_repo_readonly(const char *repo_path)
{
	if (unveil(repo_path, "r") == -1)
		fatal("unveil %s", repo_path);

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
apply_unveil(void)
{
	struct gotd_repo *repo;

	if (unveil(gotd.argv0, "x") == -1)
		fatal("unveil %s", gotd.argv0);

	TAILQ_FOREACH(repo, &gotd.repos, entry) {
		if (unveil(repo->path, "rwc") == -1)
			fatal("unveil %s", repo->path);
	}

	if (unveil(GOT_TMPDIR_STR, "rwc") == -1)
		fatal("unveil %s", GOT_TMPDIR_STR);

	if (unveil(NULL, NULL) == -1)
		fatal("unveil");
}

int
main(int argc, char **argv)
{
	const struct got_error *error = NULL;
	int ch, fd = -1, daemonize = 1, verbosity = 0, noaction = 0;
	const char *confpath = GOTD_CONF_PATH;
	char *argv0 = argv[0];
	char title[2048];
	struct passwd *pw = NULL;
	char *repo_path = NULL;
	enum gotd_procid proc_id = PROC_GOTD;
	struct event evsigint, evsigterm, evsighup, evsigusr1;
	int *pack_fds = NULL, *temp_fds = NULL;

	log_init(1, LOG_DAEMON); /* Log to stderr until daemonized. */

	while ((ch = getopt(argc, argv, "Adf:LnP:RvW")) != -1) {
		switch (ch) {
		case 'A':
			proc_id = PROC_AUTH;
			break;
		case 'd':
			daemonize = 0;
			break;
		case 'f':
			confpath = optarg;
			break;
		case 'L':
			proc_id = PROC_LISTEN;
			break;
		case 'n':
			noaction = 1;
			break;
		case 'P':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				fatal("realpath '%s'", optarg);
			break;
		case 'R':
			proc_id = PROC_REPO_READ;
			break;
		case 'v':
			if (verbosity < 3)
				verbosity++;
			break;
		case 'W':
			proc_id = PROC_REPO_WRITE;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	/* Require an absolute path in argv[0] for reliable re-exec. */
	if (!got_path_is_absolute(argv0))
		fatalx("bad path \"%s\": must be an absolute path", argv0);

	if (geteuid() && (proc_id == PROC_GOTD || proc_id == PROC_LISTEN))
		fatalx("need root privileges");

	log_init(daemonize ? 0 : 1, LOG_DAEMON);
	log_setverbose(verbosity);

	if (parse_config(confpath, proc_id, &gotd) != 0)
		return 1;

	gotd.argv0 = argv0;
	gotd.daemonize = daemonize;
	gotd.verbosity = verbosity;
	gotd.confpath = confpath;

	if (proc_id == PROC_GOTD &&
	    (gotd.nrepos == 0 || TAILQ_EMPTY(&gotd.repos)))
		fatalx("no repository defined in configuration file");

	pw = getpwnam(gotd.user_name);
	if (pw == NULL)
		fatalx("user %s not found", gotd.user_name);

	if (pw->pw_uid == 0) {
		fatalx("cannot run %s as %s: the user running %s "
		    "must not be the superuser",
		    getprogname(), pw->pw_name, getprogname());
	}

	if (proc_id == PROC_LISTEN &&
	    !got_path_is_absolute(gotd.unix_socket_path))
		fatalx("bad unix socket path \"%s\": must be an absolute path",
		    gotd.unix_socket_path);

	if (noaction)
		return 0;

	if (proc_id == PROC_GOTD) {
		gotd.pid = getpid();
		snprintf(title, sizeof(title), "%s", gotd_proc_names[proc_id]);
		start_listener(argv0, confpath, daemonize, verbosity);
		arc4random_buf(&clients_hash_key, sizeof(clients_hash_key));
		if (daemonize && daemon(1, 0) == -1)
			fatal("daemon");
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
		if (daemonize && daemon(0, 0) == -1)
			fatal("daemon");
	} else if (proc_id == PROC_AUTH) {
		snprintf(title, sizeof(title), "%s %s",
		    gotd_proc_names[proc_id], repo_path);
		if (daemonize && daemon(0, 0) == -1)
			fatal("daemon");
	} else if (proc_id == PROC_REPO_READ || proc_id == PROC_REPO_WRITE) {
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
		if (daemonize && daemon(0, 0) == -1)
			fatal("daemon");
	} else
		fatal("invalid process id %d", proc_id);

	setproctitle("%s", title);
	log_procinit(title);

	/* Drop root privileges. */
	if (setgid(pw->pw_gid) == -1)
		fatal("setgid %d failed", pw->pw_gid);
	if (setuid(pw->pw_uid) == -1)
		fatal("setuid %d failed", pw->pw_uid);

	event_init();

	switch (proc_id) {
	case PROC_GOTD:
#ifndef PROFILE
		if (pledge("stdio rpath wpath cpath proc exec "
		    "sendfd recvfd fattr flock unveil", NULL) == -1)
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

		auth_main(title, &gotd.repos, repo_path);
		/* NOTREACHED */
		break;
	case PROC_REPO_READ:
#ifndef PROFILE
		if (pledge("stdio rpath recvfd unveil", NULL) == -1)
			err(1, "pledge");
#endif
		apply_unveil_repo_readonly(repo_path);
		repo_read_main(title, repo_path, pack_fds, temp_fds);
		/* NOTREACHED */
		exit(0);
	case PROC_REPO_WRITE:
#ifndef PROFILE
		if (pledge("stdio rpath recvfd unveil", NULL) == -1)
			err(1, "pledge");
#endif
		apply_unveil_repo_readonly(repo_path);
		repo_write_main(title, repo_path, pack_fds, temp_fds);
		/* NOTREACHED */
		exit(0);
	default:
		fatal("invalid process id %d", proc_id);
	}

	if (proc_id != PROC_GOTD)
		fatal("invalid process id %d", proc_id);

	apply_unveil();

	signal_set(&evsigint, SIGINT, gotd_sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, gotd_sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, gotd_sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, gotd_sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);

	gotd_imsg_event_add(&gotd.listen_proc.iev);

	event_dispatch();

	if (pack_fds)
		got_repo_pack_fds_close(pack_fds);
	free(repo_path);
	return 0;
}
