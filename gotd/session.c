/*
 * Copyright (c) 2022, 2023 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <errno.h>
#include <event.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <imsg.h>
#include <unistd.h>

#include "got_compat.h"

#include "got_error.h"
#include "got_repository.h"
#include "got_object.h"
#include "got_path.h"
#include "got_reference.h"
#include "got_opentemp.h"

#include "got_lib_hash.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_object_cache.h"
#include "got_lib_pack.h"
#include "got_lib_repository.h"
#include "got_lib_gitproto.h"

#include "gotd.h"
#include "log.h"
#include "session.h"


static struct gotd_session {
	pid_t pid;
	const char *title;
	struct got_repository *repo;
	int *pack_fds;
	int *temp_fds;
	struct gotd_imsgev parent_iev;
	struct timeval request_timeout;
	enum gotd_procid proc_id;
} gotd_session;

static struct gotd_session_client {
	enum gotd_session_state		 state;
	int				 is_writing;
	struct gotd_client_capability	*capabilities;
	size_t				 ncapa_alloc;
	size_t				 ncapabilities;
	uint32_t			 id;
	int				 fd;
	int				 delta_cache_fd;
	struct gotd_imsgev		 iev;
	struct gotd_imsgev		 repo_child_iev;
	struct event			 tmo;
	uid_t				 euid;
	gid_t				 egid;
	char				*packfile_path;
	char				*packidx_path;
	int				 nref_updates;
	int				 accept_flush_pkt;
	int				 flush_disconnect;
} gotd_session_client;

void gotd_session_sighdlr(int sig, short event, void *arg);
static void gotd_session_shutdown(void);

static void
disconnect(struct gotd_session_client *client)
{
	log_debug("uid %d: disconnecting", client->euid);

	if (gotd_imsg_compose_event(&gotd_session.parent_iev,
	    GOTD_IMSG_DISCONNECT, gotd_session.proc_id, -1, NULL, 0) == -1)
		log_warn("imsg compose DISCONNECT");

	imsg_clear(&client->repo_child_iev.ibuf);
	event_del(&client->repo_child_iev.ev);
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

	gotd_session_shutdown();
}

static void
disconnect_on_error(struct gotd_session_client *client,
    const struct got_error *err)
{
	struct imsgbuf ibuf;

	if (err->code != GOT_ERR_EOF) {
		log_warnx("uid %d: %s", client->euid, err->msg);
		imsg_init(&ibuf, client->fd);
		gotd_imsg_send_error(&ibuf, 0, gotd_session.proc_id, err);
		imsg_clear(&ibuf);
	}

	disconnect(client);
}

static void
gotd_request_timeout(int fd, short events, void *arg)
{
	struct gotd_session_client *client = arg;

	log_debug("disconnecting uid %d due to timeout", client->euid);
	disconnect(client);
}

void
gotd_session_sighdlr(int sig, short event, void *arg)
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
		gotd_session_shutdown();
		/* NOTREACHED */
		break;
	default:
		fatalx("unexpected signal");
	}
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
send_ref_update_ok(struct gotd_session_client *client,
    struct gotd_imsg_ref_update *iref, const char *refname)
{
	struct gotd_imsg_ref_update_ok iok;
	struct gotd_imsgev *iev = &client->iev;
	struct ibuf *wbuf;
	size_t len;

	memset(&iok, 0, sizeof(iok));
	iok.client_id = client->id;
	memcpy(iok.old_id, iref->old_id, SHA1_DIGEST_LENGTH);
	memcpy(iok.new_id, iref->new_id, SHA1_DIGEST_LENGTH);
	iok.name_len = strlen(refname);

	len = sizeof(iok) + iok.name_len;
	wbuf = imsg_create(&iev->ibuf, GOTD_IMSG_REF_UPDATE_OK,
	    gotd_session.proc_id, gotd_session.pid, len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create REF_UPDATE_OK");

	if (imsg_add(wbuf, &iok, sizeof(iok)) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE_OK");
	if (imsg_add(wbuf, refname, iok.name_len) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE_OK");

	wbuf->fd = -1;
	imsg_close(&iev->ibuf, wbuf);
	gotd_imsg_event_add(iev);
	return NULL;
}

static void
send_refs_updated(struct gotd_session_client *client)
{
	if (gotd_imsg_compose_event(&client->iev, GOTD_IMSG_REFS_UPDATED,
	    gotd_session.proc_id, -1, NULL, 0) == -1)
		log_warn("imsg compose REFS_UPDATED");
}

static const struct got_error *
send_ref_update_ng(struct gotd_session_client *client,
    struct gotd_imsg_ref_update *iref, const char *refname,
    const char *reason)
{
	const struct got_error *ng_err;
	struct gotd_imsg_ref_update_ng ing;
	struct gotd_imsgev *iev = &client->iev;
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
	wbuf = imsg_create(&iev->ibuf, GOTD_IMSG_REF_UPDATE_NG,
	    gotd_session.proc_id, gotd_session.pid, len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create REF_UPDATE_NG");

	if (imsg_add(wbuf, &ing, sizeof(ing)) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE_NG");
	if (imsg_add(wbuf, refname, ing.name_len) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE_NG");
	if (imsg_add(wbuf, ng_err->msg, ing.reason_len) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE_NG");

	wbuf->fd = -1;
	imsg_close(&iev->ibuf, wbuf);
	gotd_imsg_event_add(iev);
	return NULL;
}

static const struct got_error *
install_pack(struct gotd_session_client *client, const char *repo_path,
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
begin_ref_updates(struct gotd_session_client *client, struct imsg *imsg)
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
update_ref(int *shut, struct gotd_session_client *client,
    const char *repo_path, struct imsg *imsg)
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
	char hex1[SHA1_DIGEST_STRING_LENGTH];
	char hex2[SHA1_DIGEST_STRING_LENGTH];

	log_debug("update-ref from uid %d", client->euid);

	if (client->nref_updates <= 0)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(iref))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iref, imsg->data, sizeof(iref));
	if (datalen != sizeof(iref) + iref.name_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);
	refname = strndup(imsg->data + sizeof(iref), iref.name_len);
	if (refname == NULL)
		return got_error_from_errno("strndup");

	log_debug("updating ref %s for uid %d", refname, client->euid);

	err = got_repo_open(&repo, repo_path, NULL, NULL);
	if (err)
		goto done;

	memcpy(old_id.sha1, iref.old_id, SHA1_DIGEST_LENGTH);
	memcpy(new_id.sha1, iref.new_id, SHA1_DIGEST_LENGTH);
	err = got_object_open(&obj, repo,
	    iref.delete_ref ? &old_id : &new_id);
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
			err = got_ref_resolve(&id, repo, ref);
			if (err)
				goto done;
			got_object_id_hex(&new_id, hex1, sizeof(hex1));
			got_object_id_hex(id, hex2, sizeof(hex2));
			err = got_error_fmt(GOT_ERR_REF_BUSY,
			    "Addition %s: %s failed; %s: %s has been "
			    "created by someone else while transaction "
			    "was in progress",
			    got_ref_get_name(ref), hex1,
			    got_ref_get_name(ref), hex2);
			goto done;
		}
	} else if (iref.delete_ref) {
		err = got_ref_open(&ref, repo, refname, 1 /* lock */);
		if (err)
			goto done;
		locked = 1;

		err = got_ref_resolve(&id, repo, ref);
		if (err)
			goto done;

		if (got_object_id_cmp(id, &old_id) != 0) {
			got_object_id_hex(&old_id, hex1, sizeof(hex1));
			got_object_id_hex(id, hex2, sizeof(hex2));
			err = got_error_fmt(GOT_ERR_REF_BUSY,
			    "Deletion %s: %s failed; %s: %s has been "
			    "created by someone else while transaction "
			    "was in progress",
			    got_ref_get_name(ref), hex1,
			    got_ref_get_name(ref), hex2);
			goto done;
		}

		err = got_ref_delete(ref, repo);
		if (err)
			goto done;

		free(id);
		id = NULL;
	} else {
		err = got_ref_open(&ref, repo, refname, 1 /* lock */);
		if (err)
			goto done;
		locked = 1;

		err = got_ref_resolve(&id, repo, ref);
		if (err)
			goto done;

		if (got_object_id_cmp(id, &old_id) != 0) {
			got_object_id_hex(&old_id, hex1, sizeof(hex1));
			got_object_id_hex(id, hex2, sizeof(hex2));
			err = got_error_fmt(GOT_ERR_REF_BUSY,
			    "Update %s: %s failed; %s: %s has been "
			    "created by someone else while transaction "
			    "was in progress",
			    got_ref_get_name(ref), hex1,
			    got_ref_get_name(ref), hex2);
			goto done;
		}

		if (got_object_id_cmp(&new_id, &old_id) != 0) {
			err = got_ref_change_ref(ref, &new_id);
			if (err)
				goto done;

			err = got_ref_write(ref, repo);
			if (err)
				goto done;
		}

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
		if (client->nref_updates == 0) {
			send_refs_updated(client);
			client->flush_disconnect = 1;
		}

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
session_dispatch_repo_child(int fd, short event, void *arg)
{
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_session_client *client = &gotd_session_client;
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

	for (;;) {
		const struct got_error *err = NULL;
		uint32_t client_id = 0;
		int do_disconnect = 0;
		int do_ref_updates = 0, do_ref_update = 0;
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

		if (do_disconnect) {
			if (err)
				disconnect_on_error(client, err);
			else
				disconnect(client);
		} else {
			if (do_packfile_install)
				err = install_pack(client,
				    gotd_session.repo->path, &imsg);
			else if (do_ref_updates)
				err = begin_ref_updates(client, &imsg);
			else if (do_ref_update)
				err = update_ref(&shut, client,
				    gotd_session.repo->path, &imsg);
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

static const struct got_error *
recv_capabilities(struct gotd_session_client *client, struct imsg *imsg)
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
recv_capability(struct gotd_session_client *client, struct imsg *imsg)
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

	key = strndup(imsg->data + sizeof(icapa), icapa.key_len);
	if (key == NULL)
		return got_error_from_errno("strndup");
	if (icapa.value_len > 0) {
		value = strndup(imsg->data + sizeof(icapa) + icapa.key_len,
		    icapa.value_len);
		if (value == NULL) {
			free(key);
			return got_error_from_errno("strndup");
		}
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
ensure_client_is_reading(struct gotd_session_client *client)
{
	if (client->is_writing) {
		return got_error_fmt(GOT_ERR_BAD_PACKET,
		    "uid %d made a read-request but is not reading from "
		    "a repository", client->euid);
	}

	return NULL;
}

static const struct got_error *
ensure_client_is_writing(struct gotd_session_client *client)
{
	if (!client->is_writing) {
		return got_error_fmt(GOT_ERR_BAD_PACKET,
		    "uid %d made a write-request but is not writing to "
		    "a repository", client->euid);
	}

	return NULL;
}

static const struct got_error *
forward_want(struct gotd_session_client *client, struct imsg *imsg)
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

	if (gotd_imsg_compose_event(&client->repo_child_iev, GOTD_IMSG_WANT,
	    gotd_session.proc_id, -1, &iwant, sizeof(iwant)) == -1)
		return got_error_from_errno("imsg compose WANT");

	return NULL;
}

static const struct got_error *
forward_ref_update(struct gotd_session_client *client, struct imsg *imsg)
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
	if (gotd_imsg_compose_event(&client->repo_child_iev,
	    GOTD_IMSG_REF_UPDATE, gotd_session.proc_id, -1,
	    iref, datalen) == -1)
		err = got_error_from_errno("imsg compose REF_UPDATE");
	free(iref);
	return err;
}

static const struct got_error *
forward_have(struct gotd_session_client *client, struct imsg *imsg)
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

	if (gotd_imsg_compose_event(&client->repo_child_iev, GOTD_IMSG_HAVE,
	    gotd_session.proc_id, -1, &ihave, sizeof(ihave)) == -1)
		return got_error_from_errno("imsg compose HAVE");

	return NULL;
}

static int
client_has_capability(struct gotd_session_client *client, const char *capastr)
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
recv_packfile(struct gotd_session_client *client)
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

	/* Send pack pipe end 0 to repo child process. */
	if (gotd_imsg_compose_event(&client->repo_child_iev,
	    GOTD_IMSG_PACKFILE_PIPE, gotd_session.proc_id, pipe[0],
	        &ipipe, sizeof(ipipe)) == -1) {
		err = got_error_from_errno("imsg compose PACKFILE_PIPE");
		pipe[0] = -1;
		goto done;
	}
	pipe[0] = -1;

	/* Send pack pipe end 1 to gotsh(1) (expects just an fd, no data). */
	if (gotd_imsg_compose_event(&client->iev,
	    GOTD_IMSG_PACKFILE_PIPE, gotd_session.proc_id, pipe[1],
	    NULL, 0) == -1)
		err = got_error_from_errno("imsg compose PACKFILE_PIPE");
	pipe[1] = -1;

	if (asprintf(&basepath, "%s/%s/receiving-from-uid-%d.pack",
	    got_repo_get_path(gotd_session.repo), GOT_OBJECTS_PACK_DIR,
	    client->euid) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_opentemp_named_fd(&pack_path, &packfd, basepath, "");
	if (err)
		goto done;
	if (fchmod(packfd, GOT_DEFAULT_PACK_MODE) == -1) {
		err = got_error_from_errno2("fchmod", pack_path);
		goto done;
	}

	free(basepath);
	if (asprintf(&basepath, "%s/%s/receiving-from-uid-%d.idx",
	    got_repo_get_path(gotd_session.repo), GOT_OBJECTS_PACK_DIR,
	    client->euid) == -1) {
		err = got_error_from_errno("asprintf");
		basepath = NULL;
		goto done;
	}
	err = got_opentemp_named_fd(&idx_path, &idxfd, basepath, "");
	if (err)
		goto done;
	if (fchmod(idxfd, GOT_DEFAULT_PACK_MODE) == -1) {
		err = got_error_from_errno2("fchmod", idx_path);
		goto done;
	}

	memset(&ifile, 0, sizeof(ifile));
	ifile.client_id = client->id;
	if (gotd_imsg_compose_event(&client->repo_child_iev,
	    GOTD_IMSG_PACKIDX_FILE, gotd_session.proc_id,
	    idxfd, &ifile, sizeof(ifile)) == -1) {
		err = got_error_from_errno("imsg compose PACKIDX_FILE");
		idxfd = -1;
		goto done;
	}
	idxfd = -1;

	memset(&ipack, 0, sizeof(ipack));
	ipack.client_id = client->id;
	if (client_has_capability(client, GOT_CAPA_REPORT_STATUS))
		ipack.report_status = 1;

	if (gotd_imsg_compose_event(&client->repo_child_iev,
	    GOTD_IMSG_RECV_PACKFILE, gotd_session.proc_id, packfd,
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

static const struct got_error *
send_packfile(struct gotd_session_client *client)
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

	if (gotd_imsg_compose_event(&client->repo_child_iev,
	    GOTD_IMSG_SEND_PACKFILE, PROC_GOTD, client->delta_cache_fd,
	    &ipack, sizeof(ipack)) == -1) {
		err = got_error_from_errno("imsg compose SEND_PACKFILE");
		close(pipe[0]);
		close(pipe[1]);
		return err;
	}

	ipipe.client_id = client->id;

	/* Send pack pipe end 0 to repo child process. */
	if (gotd_imsg_compose_event(&client->repo_child_iev,
	    GOTD_IMSG_PACKFILE_PIPE, PROC_GOTD,
	    pipe[0], &ipipe, sizeof(ipipe)) == -1) {
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

static void
session_dispatch_client(int fd, short events, void *arg)
{
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_session_client *client = &gotd_session_client;
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

		if (client->flush_disconnect) {
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
			else if (err->code == GOT_ERR_EOF &&
			    client->state == GOTD_STATE_EXPECT_CAPABILITIES) {
				/*
				 * The client has closed its socket before
				 * sending its capability announcement.
				 * This can happen when Git clients have
				 * no ref-updates to send.
				 */
				disconnect_on_error(client, err);
				return;
			}
			break;
		}

		evtimer_del(&client->tmo);

		switch (imsg.hdr.type) {
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
			if (!client->is_writing) {
				client->state = GOTD_STATE_EXPECT_WANT;
				client->accept_flush_pkt = 1;
				log_debug("uid %d: expecting want-lines",
				    client->euid);
			} else if (client->is_writing) {
				client->state = GOTD_STATE_EXPECT_REF_UPDATE;
				client->accept_flush_pkt = 1;
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
			client->accept_flush_pkt = 1;
			err = forward_want(client, &imsg);
			break;
		case GOTD_IMSG_REF_UPDATE:
			if (client->state != GOTD_STATE_EXPECT_REF_UPDATE &&
			    client->state !=
			    GOTD_STATE_EXPECT_MORE_REF_UPDATES) {
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
			client->accept_flush_pkt = 1;
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
			client->accept_flush_pkt = 1;
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
			} else if (client->state != GOTD_STATE_EXPECT_DONE) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected flush-pkt received");
				break;
			}
			if (!client->accept_flush_pkt) {
				err = got_error_msg(GOT_ERR_BAD_REQUEST,
				    "unexpected flush-pkt received");
				break;
			}

			/*
			 * Accept just one flush packet at a time.
			 * Future client state transitions will set this flag
			 * again if another flush packet is expected.
			 */
			client->accept_flush_pkt = 0;

			log_debug("received flush-pkt from uid %d",
			    client->euid);
			if (client->state == GOTD_STATE_EXPECT_WANT) {
				client->state = GOTD_STATE_EXPECT_HAVE;
				log_debug("uid %d: expecting have-lines",
				    client->euid);
			} else if (client->state == GOTD_STATE_EXPECT_HAVE) {
				client->state = GOTD_STATE_EXPECT_DONE;
				client->accept_flush_pkt = 1;
				log_debug("uid %d: expecting 'done'",
				    client->euid);
			} else if (client->state ==
			    GOTD_STATE_EXPECT_MORE_REF_UPDATES) {
				client->state = GOTD_STATE_EXPECT_PACKFILE;
				log_debug("uid %d: expecting packfile",
				    client->euid);
				err = recv_packfile(client);
			} else if (client->state != GOTD_STATE_EXPECT_DONE) {
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
			client->accept_flush_pkt = 1;
			err = send_packfile(client);
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
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
		gotd_imsg_event_add(iev);
		evtimer_add(&client->tmo, &gotd_session.request_timeout);
	}
}

static const struct got_error *
list_refs_request(void)
{
	static const struct got_error *err;
	struct gotd_session_client *client = &gotd_session_client;
	struct gotd_imsgev *iev = &client->repo_child_iev;
	struct gotd_imsg_list_refs_internal ilref;
	int fd;

	if (client->state != GOTD_STATE_EXPECT_LIST_REFS)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	memset(&ilref, 0, sizeof(ilref));
	ilref.client_id = client->id;

	fd = dup(client->fd);
	if (fd == -1)
		return got_error_from_errno("dup");

	if (gotd_imsg_compose_event(iev, GOTD_IMSG_LIST_REFS_INTERNAL,
	    gotd_session.proc_id, fd, &ilref, sizeof(ilref)) == -1) {
		err = got_error_from_errno("imsg compose LIST_REFS_INTERNAL");
		close(fd);
		return err;
	}

	client->state = GOTD_STATE_EXPECT_CAPABILITIES;
	log_debug("uid %d: expecting capabilities", client->euid);
	return NULL;
}

static const struct got_error *
recv_connect(struct imsg *imsg)
{
	struct gotd_session_client *client = &gotd_session_client;
	struct gotd_imsg_connect iconnect;
	size_t datalen;

	if (client->state != GOTD_STATE_EXPECT_LIST_REFS)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(iconnect))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iconnect, imsg->data, sizeof(iconnect));

	if (imsg->fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	client->fd = imsg->fd;
	client->euid = iconnect.euid;
	client->egid = iconnect.egid;

	imsg_init(&client->iev.ibuf, client->fd);
	client->iev.handler = session_dispatch_client;
	client->iev.events = EV_READ;
	client->iev.handler_arg = NULL;
	event_set(&client->iev.ev, client->iev.ibuf.fd, EV_READ,
	    session_dispatch_client, &client->iev);
	gotd_imsg_event_add(&client->iev);
	evtimer_set(&client->tmo, gotd_request_timeout, client);

	return NULL;
}

static const struct got_error *
recv_repo_child(struct imsg *imsg)
{
	struct gotd_imsg_connect_repo_child ichild;
	struct gotd_session_client *client = &gotd_session_client;
	size_t datalen;

	if (client->state != GOTD_STATE_EXPECT_LIST_REFS)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	/* We should already have received a pipe to the listener. */
	if (client->fd == -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ichild))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&ichild, imsg->data, sizeof(ichild));

	client->id = ichild.client_id;
	if (ichild.proc_id == PROC_REPO_WRITE)
		client->is_writing = 1;
	else if (ichild.proc_id == PROC_REPO_READ)
		client->is_writing = 0;
	else
		return got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "bad child process type");

	if (imsg->fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	imsg_init(&client->repo_child_iev.ibuf, imsg->fd);
	client->repo_child_iev.handler = session_dispatch_repo_child;
	client->repo_child_iev.events = EV_READ;
	client->repo_child_iev.handler_arg = NULL;
	event_set(&client->repo_child_iev.ev, client->repo_child_iev.ibuf.fd,
	    EV_READ, session_dispatch_repo_child, &client->repo_child_iev);
	gotd_imsg_event_add(&client->repo_child_iev);

	/* The "recvfd" pledge promise is no longer needed. */
	if (pledge("stdio rpath wpath cpath sendfd fattr flock", NULL) == -1)
		fatal("pledge");

	return NULL;
}

static void
session_dispatch(int fd, short event, void *arg)
{
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct gotd_session_client *client = &gotd_session_client;
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

	for (;;) {
		const struct got_error *err = NULL;
		uint32_t client_id = 0;
		int do_disconnect = 0, do_list_refs = 0;

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
			err = recv_connect(&imsg);
			break;
		case GOTD_IMSG_DISCONNECT:
			do_disconnect = 1;
			break;
		case GOTD_IMSG_CONNECT_REPO_CHILD:
			err = recv_repo_child(&imsg);
			if (err)
				break;
			do_list_refs = 1;
			break;
		default:
			log_debug("unexpected imsg %d", imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);

		if (do_disconnect) {
			if (err)
				disconnect_on_error(client, err);
			else
				disconnect(client);
		} else if (do_list_refs)
			err = list_refs_request();

		if (err)
			log_warnx("uid %d: %s", client->euid, err->msg);
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

void
session_main(const char *title, const char *repo_path,
    int *pack_fds, int *temp_fds, struct timeval *request_timeout,
    enum gotd_procid proc_id)
{
	const struct got_error *err = NULL;
	struct event evsigint, evsigterm, evsighup, evsigusr1;

	gotd_session.title = title;
	gotd_session.pid = getpid();
	gotd_session.pack_fds = pack_fds;
	gotd_session.temp_fds = temp_fds;
	memcpy(&gotd_session.request_timeout, request_timeout,
	    sizeof(gotd_session.request_timeout));
	gotd_session.proc_id = proc_id;

	err = got_repo_open(&gotd_session.repo, repo_path, NULL, pack_fds);
	if (err)
		goto done;
	if (!got_repo_is_bare(gotd_session.repo)) {
		err = got_error_msg(GOT_ERR_NOT_GIT_REPO,
		    "bare git repository required");
		goto done;
	}

	got_repo_temp_fds_set(gotd_session.repo, temp_fds);

	signal_set(&evsigint, SIGINT, gotd_session_sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, gotd_session_sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, gotd_session_sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, gotd_session_sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);

	gotd_session_client.state = GOTD_STATE_EXPECT_LIST_REFS;
	gotd_session_client.fd = -1;
	gotd_session_client.nref_updates = -1;
	gotd_session_client.delta_cache_fd = -1;
	gotd_session_client.accept_flush_pkt = 1;

	imsg_init(&gotd_session.parent_iev.ibuf, GOTD_FILENO_MSG_PIPE);
	gotd_session.parent_iev.handler = session_dispatch;
	gotd_session.parent_iev.events = EV_READ;
	gotd_session.parent_iev.handler_arg = NULL;
	event_set(&gotd_session.parent_iev.ev, gotd_session.parent_iev.ibuf.fd,
	    EV_READ, session_dispatch, &gotd_session.parent_iev);
	if (gotd_imsg_compose_event(&gotd_session.parent_iev,
	    GOTD_IMSG_CLIENT_SESSION_READY, gotd_session.proc_id,
	    -1, NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose CLIENT_SESSION_READY");
		goto done;
	}

	event_dispatch();
done:
	if (err)
		log_warnx("%s: %s", title, err->msg);
	gotd_session_shutdown();
}

void
gotd_session_shutdown(void)
{
	log_debug("shutting down");
	if (gotd_session.repo)
		got_repo_close(gotd_session.repo);
	got_repo_pack_fds_close(gotd_session.pack_fds);
	got_repo_temp_fds_close(gotd_session.temp_fds);
	exit(0);
}
