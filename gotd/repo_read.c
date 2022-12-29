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
#include <sys/types.h>

#include <event.h>
#include <errno.h>
#include <imsg.h>
#include <signal.h>
#include <stdlib.h>
#include <limits.h>
#include <poll.h>
#include <sha1.h>
#include <siphash.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "got_error.h"
#include "got_cancel.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_reference.h"
#include "got_repository_admin.h"

#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_object_idset.h"
#include "got_lib_sha1.h"
#include "got_lib_pack.h"
#include "got_lib_ratelimit.h"
#include "got_lib_pack_create.h"
#include "got_lib_poll.h"

#include "log.h"
#include "gotd.h"
#include "repo_read.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static struct repo_read {
	pid_t pid;
	const char *title;
	struct got_repository *repo;
	int *pack_fds;
	int *temp_fds;
} repo_read;

struct repo_read_client {
	STAILQ_ENTRY(repo_read_client)	 entry;
	uint32_t			 id;
	int				 fd;
	int				 delta_cache_fd;
	int				 report_progress;
	int				 pack_pipe;
	struct gotd_object_id_array	 want_ids;
	struct gotd_object_id_array	 have_ids;
};
STAILQ_HEAD(repo_read_clients, repo_read_client);

static struct repo_read_clients repo_read_clients[GOTD_CLIENT_TABLE_SIZE];
static SIPHASH_KEY clients_hash_key;

static uint64_t
client_hash(uint32_t client_id)
{
	return SipHash24(&clients_hash_key, &client_id, sizeof(client_id));
}

static void
add_client(struct repo_read_client *client, uint32_t client_id, int fd)
{
	uint64_t slot;

	client->id = client_id;
	client->fd = fd;
	client->delta_cache_fd = -1;
	client->pack_pipe = -1;
	slot = client_hash(client->id) % nitems(repo_read_clients);
	STAILQ_INSERT_HEAD(&repo_read_clients[slot], client, entry);
}

static struct repo_read_client *
find_client(uint32_t client_id)
{
	uint64_t slot;
	struct repo_read_client *c;

	slot = client_hash(client_id) % nitems(repo_read_clients);
	STAILQ_FOREACH(c, &repo_read_clients[slot], entry) {
		if (c->id == client_id)
			return c;
	}

	return NULL;
}

static volatile sig_atomic_t sigint_received;
static volatile sig_atomic_t sigterm_received;

static void
catch_sigint(int signo)
{
	sigint_received = 1;
}

static void
catch_sigterm(int signo)
{
	sigterm_received = 1;
}

static const struct got_error *
check_cancelled(void *arg)
{
	if (sigint_received || sigterm_received)
		return got_error(GOT_ERR_CANCELLED);

	return NULL;
}

static const struct got_error *
send_symref(struct got_reference *symref, struct got_object_id *target_id,
    struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_symref isymref;
	const char *refname = got_ref_get_name(symref);
	const char *target = got_ref_get_symref_target(symref);
	size_t len;
	struct ibuf *wbuf;

	memset(&isymref, 0, sizeof(isymref));
	isymref.name_len = strlen(refname);
	isymref.target_len = strlen(target);
	memcpy(isymref.target_id, target_id->sha1, sizeof(isymref.target_id));

	len = sizeof(isymref) + isymref.name_len + isymref.target_len;
	if (len > MAX_IMSGSIZE - IMSG_HEADER_SIZE) {
		err = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}

	wbuf = imsg_create(ibuf, GOTD_IMSG_SYMREF, 0, 0, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create SYMREF");
		goto done;
	}

	if (imsg_add(wbuf, &isymref, sizeof(isymref)) == -1) {
		err = got_error_from_errno("imsg_add SYMREF");
		goto done;
	}
	if (imsg_add(wbuf, refname, isymref.name_len) == -1) {
		err = got_error_from_errno("imsg_add SYMREF");
		goto done;
	}
	if (imsg_add(wbuf, target, isymref.target_len) == -1) {
		err = got_error_from_errno("imsg_add SYMREF");
		goto done;
	}

	wbuf->fd = -1;
	imsg_close(ibuf, wbuf);
done:
	free(target_id);
	return err;
}

static const struct got_error *
send_peeled_tag_ref(struct got_reference *ref, struct got_object *obj,
    struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct got_tag_object *tag;
	size_t namelen, len;
	char *peeled_refname = NULL;
	struct got_object_id *id;
	struct ibuf *wbuf;

	err = got_object_tag_open(&tag, repo_read.repo, obj);
	if (err)
		return err;

	if (asprintf(&peeled_refname, "%s^{}", got_ref_get_name(ref)) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	id = got_object_tag_get_object_id(tag);
	namelen = strlen(peeled_refname);

	len = sizeof(struct gotd_imsg_ref) + namelen;
	if (len > MAX_IMSGSIZE - IMSG_HEADER_SIZE) {
		err = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}

	wbuf = imsg_create(ibuf, GOTD_IMSG_REF, PROC_REPO_READ,
	    repo_read.pid, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create MREF");
		goto done;
	}

	/* Keep in sync with struct gotd_imsg_ref definition. */
	if (imsg_add(wbuf, id->sha1, SHA1_DIGEST_LENGTH) == -1) {
		err = got_error_from_errno("imsg_add REF");
		goto done;
	}
	if (imsg_add(wbuf, &namelen, sizeof(namelen)) == -1) {
		err = got_error_from_errno("imsg_add REF");
		goto done;
	}
	if (imsg_add(wbuf, peeled_refname, namelen) == -1) {
		err = got_error_from_errno("imsg_add REF");
		goto done;
	}

	wbuf->fd = -1;
	imsg_close(ibuf, wbuf);
done:
	got_object_tag_close(tag);
	return err;
}

static const struct got_error *
send_ref(struct got_reference *ref, struct imsgbuf *ibuf)
{
	const struct got_error *err;
	const char *refname = got_ref_get_name(ref);
	size_t namelen;
	struct got_object_id *id = NULL;
	struct got_object *obj = NULL;
	size_t len;
	struct ibuf *wbuf;

	namelen = strlen(refname);

	len = sizeof(struct gotd_imsg_ref) + namelen;
	if (len > MAX_IMSGSIZE - IMSG_HEADER_SIZE)
		return got_error(GOT_ERR_NO_SPACE);

	err = got_ref_resolve(&id, repo_read.repo, ref);
	if (err)
		return err;

	wbuf = imsg_create(ibuf, GOTD_IMSG_REF, PROC_REPO_READ,
	    repo_read.pid, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create REF");
		goto done;
	}

	/* Keep in sync with struct gotd_imsg_ref definition. */
	if (imsg_add(wbuf, id->sha1, SHA1_DIGEST_LENGTH) == -1)
		return got_error_from_errno("imsg_add REF");
	if (imsg_add(wbuf, &namelen, sizeof(namelen)) == -1)
		return got_error_from_errno("imsg_add REF");
	if (imsg_add(wbuf, refname, namelen) == -1)
		return got_error_from_errno("imsg_add REF");

	wbuf->fd = -1;
	imsg_close(ibuf, wbuf);

	err = got_object_open(&obj, repo_read.repo, id);
	if (err)
		goto done;
	if (obj->type == GOT_OBJ_TYPE_TAG)
		err = send_peeled_tag_ref(ref, obj, ibuf);
done:
	if (obj)
		got_object_close(obj);
	free(id);
	return err;
}

static const struct got_error *
list_refs(struct repo_read_client **client, struct imsg *imsg)
{
	const struct got_error *err;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	struct gotd_imsg_list_refs_internal ireq;
	size_t datalen;
	struct gotd_imsg_reflist irefs;
	struct imsgbuf ibuf;
	int client_fd = imsg->fd;
	struct got_object_id *head_target_id = NULL;

	TAILQ_INIT(&refs);

	if (client_fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ireq, imsg->data, sizeof(ireq));

	*client = find_client(ireq.client_id);
	if (*client)
		return got_error_msg(GOT_ERR_CLIENT_ID, "duplicate client ID");

	*client = calloc(1, sizeof(**client));
	if (*client == NULL)
		return got_error_from_errno("calloc");
	add_client(*client, ireq.client_id, client_fd);

	imsg_init(&ibuf, client_fd);

	err = got_ref_list(&refs, repo_read.repo, "",
	    got_ref_cmp_by_name, NULL);
	if (err)
		return err;

	memset(&irefs, 0, sizeof(irefs));
	TAILQ_FOREACH(re, &refs, entry) {
		struct got_object_id *id;
		int obj_type;

		if (got_ref_is_symbolic(re->ref)) {
			const char *refname = got_ref_get_name(re->ref);
			if (strcmp(refname, GOT_REF_HEAD) != 0)
				continue;
			err = got_ref_resolve(&head_target_id, repo_read.repo,
			    re->ref);
			if (err) {
				if (err->code != GOT_ERR_NOT_REF)
					return err;
				/*
				 * HEAD points to a non-existent branch.
				 * Do not advertise it.
				 * Matches git-daemon's behaviour.
				 */
				head_target_id = NULL;
				err = NULL;
			} else
				irefs.nrefs++;
			continue;
		}

		irefs.nrefs++;

		/* Account for a peeled tag refs. */
		err = got_ref_resolve(&id, repo_read.repo, re->ref);
		if (err)
			goto done;
		err = got_object_get_type(&obj_type, repo_read.repo, id);	
		free(id);
		if (err)
			goto done;
		if (obj_type == GOT_OBJ_TYPE_TAG)
			irefs.nrefs++;
	}

	if (imsg_compose(&ibuf, GOTD_IMSG_REFLIST, PROC_REPO_READ,
	    repo_read.pid, -1, &irefs, sizeof(irefs)) == -1) {
		err = got_error_from_errno("imsg_compose REFLIST");
		goto done;
	}

	/*
	 * Send the HEAD symref first. In Git-protocol versions < 2
	 * the HEAD symref must be announced on the initial line of
	 * the server's ref advertisement.
	 * For now, we do not advertise symrefs other than HEAD.
	 */
	TAILQ_FOREACH(re, &refs, entry) {
		if (!got_ref_is_symbolic(re->ref) ||
		    strcmp(got_ref_get_name(re->ref), GOT_REF_HEAD) != 0 ||
		    head_target_id == NULL)
			continue;
		err = send_symref(re->ref, head_target_id, &ibuf);
		if (err)
			goto done;
		break;
	}
	TAILQ_FOREACH(re, &refs, entry) {
		if (got_ref_is_symbolic(re->ref))
			continue;
		err = send_ref(re->ref, &ibuf);
		if (err)
			goto done;
	}

	err = gotd_imsg_flush(&ibuf);
done:
	got_ref_list_free(&refs);
	imsg_clear(&ibuf);
	return err;
}

static const struct got_error *
record_object_id(struct gotd_object_id_array *array, struct got_object_id *id)
{
	const size_t alloc_chunksz = 256;

	if (array->ids == NULL) {
		array->ids = reallocarray(NULL, alloc_chunksz,
		    sizeof(*array->ids));
		if (array->ids == NULL)
			return got_error_from_errno("reallocarray");
		array->nalloc = alloc_chunksz;
		array->nids = 0;
	} else if (array->nalloc <= array->nids) {
		struct got_object_id **new;
		new = recallocarray(array->ids, array->nalloc,
		    array->nalloc + alloc_chunksz, sizeof(*new));
		if (new == NULL)
			return got_error_from_errno("recallocarray");
		array->ids = new;
		array->nalloc += alloc_chunksz;
	}

	array->ids[array->nids] = got_object_id_dup(id);
	if (array->ids[array->nids] == NULL)
		return got_error_from_errno("got_object_id_dup");
	array->nids++;
	return NULL;
}

static void
free_object_ids(struct gotd_object_id_array *array)
{
	size_t i;

	for (i = 0; i < array->nids; i++)
		free(array->ids[i]);
	free(array->ids);

	array->ids = NULL;
	array->nalloc = 0;
	array->nids = 0;
}

static const struct got_error *
recv_want(struct repo_read_client **client, struct imsg *imsg)
{
	const struct got_error *err;
	struct gotd_imsg_want iwant;
	size_t datalen;
	char hex[SHA1_DIGEST_STRING_LENGTH];
	struct got_object_id id;
	int obj_type;
	struct imsgbuf ibuf;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(iwant))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iwant, imsg->data, sizeof(iwant));

	memset(&id, 0, sizeof(id));
	memcpy(id.sha1, iwant.object_id, SHA1_DIGEST_LENGTH);

	if (log_getverbose() > 0 &&
	    got_sha1_digest_to_str(id.sha1, hex, sizeof(hex)))
		log_debug("client wants %s", hex);

	*client = find_client(iwant.client_id);
	if (*client == NULL)
		return got_error(GOT_ERR_CLIENT_ID);

	imsg_init(&ibuf, (*client)->fd);

	err = got_object_get_type(&obj_type, repo_read.repo, &id);
	if (err)
		return err;

	if (obj_type != GOT_OBJ_TYPE_COMMIT &&
	    obj_type != GOT_OBJ_TYPE_TAG)
		return got_error(GOT_ERR_OBJ_TYPE);

	err = record_object_id(&(*client)->want_ids, &id);
	if (err)
		return err;

	gotd_imsg_send_ack(&id, &ibuf, PROC_REPO_READ, repo_read.pid);
	imsg_clear(&ibuf);
	return err;
}

static const struct got_error *
recv_have(struct repo_read_client **client, struct imsg *imsg)
{
	const struct got_error *err;
	struct gotd_imsg_have ihave;
	size_t datalen;
	char hex[SHA1_DIGEST_STRING_LENGTH];
	struct got_object_id id;
	int obj_type;
	struct imsgbuf ibuf;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ihave))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ihave, imsg->data, sizeof(ihave));

	memset(&id, 0, sizeof(id));
	memcpy(id.sha1, ihave.object_id, SHA1_DIGEST_LENGTH);

	if (log_getverbose() > 0 &&
	    got_sha1_digest_to_str(id.sha1, hex, sizeof(hex)))
		log_debug("client has %s", hex);

	*client = find_client(ihave.client_id);
	if (*client == NULL)
		return got_error(GOT_ERR_CLIENT_ID);

	imsg_init(&ibuf, (*client)->fd);

	err = got_object_get_type(&obj_type, repo_read.repo, &id);
	if (err) {
		if (err->code == GOT_ERR_NO_OBJ) {
			gotd_imsg_send_nak(&id, &ibuf,
			    PROC_REPO_READ, repo_read.pid);
			err = NULL;
		}
		goto done;
	}

	if (obj_type != GOT_OBJ_TYPE_COMMIT &&
	    obj_type != GOT_OBJ_TYPE_TAG) {
		gotd_imsg_send_nak(&id, &ibuf, PROC_REPO_READ, repo_read.pid);
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = record_object_id(&(*client)->have_ids, &id);
	if (err)
		return err;

	gotd_imsg_send_ack(&id, &ibuf, PROC_REPO_READ, repo_read.pid);
done:
	imsg_clear(&ibuf);
	return err;
}

struct repo_read_pack_progress_arg {
	int report_progress;
	struct imsgbuf *ibuf;
	int sent_ready;
};

static const struct got_error *
pack_progress(void *arg, int ncolored, int nfound, int ntrees,
    off_t packfile_size, int ncommits, int nobj_total, int nobj_deltify,
    int nobj_written)
{
	struct repo_read_pack_progress_arg *a = arg;
	struct gotd_imsg_packfile_progress iprog;
	int ret;

	if (!a->report_progress)
		return NULL;
	if (packfile_size > 0 && a->sent_ready)
		return NULL;

	memset(&iprog, 0, sizeof(iprog));
	iprog.ncolored = ncolored;
	iprog.nfound = nfound;
	iprog.ntrees = ntrees;
	iprog.packfile_size = packfile_size;
	iprog.ncommits = ncommits;
	iprog.nobj_total = nobj_total;
	iprog.nobj_deltify = nobj_deltify;
	iprog.nobj_written = nobj_written;

	/* Using synchronous writes since we are blocking the event loop. */
	if (packfile_size == 0) {
		ret = imsg_compose(a->ibuf, GOTD_IMSG_PACKFILE_PROGRESS,
		    PROC_REPO_READ, repo_read.pid, -1, &iprog, sizeof(iprog));
		if (ret == -1) {
			return got_error_from_errno("imsg compose "
			    "PACKFILE_PROGRESS");
		}	
	} else {
		a->sent_ready = 1;
		ret = imsg_compose(a->ibuf, GOTD_IMSG_PACKFILE_READY,
		    PROC_REPO_READ, repo_read.pid, -1, &iprog, sizeof(iprog));
		if (ret == -1) {
			return got_error_from_errno("imsg compose "
			    "PACKFILE_READY");
		}
	}

	return gotd_imsg_flush(a->ibuf);
}

static const struct got_error *
receive_delta_cache_fd(struct repo_read_client **client, struct imsg *imsg,
    struct gotd_imsgev *iev)
{
	struct gotd_imsg_send_packfile ireq;
	size_t datalen;

	log_debug("receving delta cache file");

	if (imsg->fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ireq, imsg->data, sizeof(ireq));

	*client = find_client(ireq.client_id);
	if (*client == NULL)
		return got_error(GOT_ERR_CLIENT_ID);

	if ((*client)->delta_cache_fd != -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	(*client)->delta_cache_fd = imsg->fd;
	(*client)->report_progress = ireq.report_progress;
	return NULL;
}

static const struct got_error *
receive_pack_pipe(struct repo_read_client **client, struct imsg *imsg,
    struct gotd_imsgev *iev)
{
	struct gotd_imsg_packfile_pipe ireq;
	size_t datalen;

	log_debug("receving pack pipe descriptor");

	if (imsg->fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ireq, imsg->data, sizeof(ireq));

	*client = find_client(ireq.client_id);
	if (*client == NULL)
		return got_error(GOT_ERR_CLIENT_ID);
	if ((*client)->pack_pipe != -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	(*client)->pack_pipe = imsg->fd;
	return NULL;
}

static const struct got_error *
send_packfile(struct repo_read_client *client, struct imsg *imsg,
    struct gotd_imsgev *iev)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_packfile_done idone;
	uint8_t packsha1[SHA1_DIGEST_LENGTH];
	char hex[SHA1_DIGEST_STRING_LENGTH];
	FILE *delta_cache = NULL;
	struct imsgbuf ibuf;
	struct repo_read_pack_progress_arg pa;
	struct got_ratelimit rl;

	log_debug("packfile request received");

	got_ratelimit_init(&rl, 2, 0);

	if (client->delta_cache_fd == -1 || client->pack_pipe == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	imsg_init(&ibuf, client->fd);

	delta_cache = fdopen(client->delta_cache_fd, "w+");
	if (delta_cache == NULL) {
		err = got_error_from_errno("fdopen");
		goto done;
	}
	client->delta_cache_fd = -1;

	memset(&pa, 0, sizeof(pa));
	pa.ibuf = &ibuf;
	pa.report_progress = client->report_progress;

	err = got_pack_create(packsha1, client->pack_pipe, delta_cache,
	    client->have_ids.ids, client->have_ids.nids,
	    client->want_ids.ids, client->want_ids.nids,
	    repo_read.repo, 0, 1, pack_progress, &pa, &rl,
	    check_cancelled, NULL);
	if (err)
		goto done;
	
	if (log_getverbose() > 0 &&
	    got_sha1_digest_to_str(packsha1, hex, sizeof(hex)))
		log_debug("sent pack-%s.pack", hex);

	memset(&idone, 0, sizeof(idone));
	idone.client_id = client->id;
	if (gotd_imsg_compose_event(iev, GOTD_IMSG_PACKFILE_DONE,
	    PROC_REPO_READ, -1, &idone, sizeof(idone)) == -1)
		err = got_error_from_errno("imsg compose PACKFILE_DONE");
done:
	if (delta_cache != NULL && fclose(delta_cache) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	imsg_clear(&ibuf);
	return err;
}

static const struct got_error *
recv_disconnect(struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_disconnect idisconnect;
	size_t datalen;
	int client_fd, delta_cache_fd, pack_pipe;
	struct repo_read_client *client = NULL;
	uint64_t slot;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(idisconnect))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&idisconnect, imsg->data, sizeof(idisconnect));

	log_debug("client disconnecting");

	client = find_client(idisconnect.client_id);
	if (client == NULL)
		return got_error(GOT_ERR_CLIENT_ID);

	slot = client_hash(client->id) % nitems(repo_read_clients);
	STAILQ_REMOVE(&repo_read_clients[slot], client, repo_read_client,
	    entry);
	free_object_ids(&client->have_ids);
	free_object_ids(&client->want_ids);
	client_fd = client->fd;
	delta_cache_fd = client->delta_cache_fd;
	pack_pipe = client->pack_pipe;
	free(client);
	if (close(client_fd) == -1)
		err = got_error_from_errno("close");
	if (delta_cache_fd != -1 && close(delta_cache_fd) == -1 && err == NULL)
		return got_error_from_errno("close");
	if (pack_pipe != -1 && close(pack_pipe) == -1 && err == NULL)
		return got_error_from_errno("close");
	return err;
}

static void
repo_read_dispatch(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	int shut = 0;
	struct repo_read_client *client = NULL;

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

	while (err == NULL && check_cancelled(NULL) == NULL) {
		client = NULL;
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_LIST_REFS_INTERNAL:
			err = list_refs(&client, &imsg);
			if (err)
				log_warnx("%s: ls-refs: %s", repo_read.title,
				    err->msg);
			break;
		case GOTD_IMSG_WANT:
			err = recv_want(&client, &imsg);
			if (err)
				log_warnx("%s: want-line: %s", repo_read.title,
				    err->msg);
			break;
		case GOTD_IMSG_HAVE:
			err = recv_have(&client, &imsg);
			if (err)
				log_warnx("%s: have-line: %s", repo_read.title,
				    err->msg);
			break;
		case GOTD_IMSG_SEND_PACKFILE:
			err = receive_delta_cache_fd(&client, &imsg, iev);
			if (err)
				log_warnx("%s: receiving delta cache: %s",
				    repo_read.title, err->msg);
			break;
		case GOTD_IMSG_PACKFILE_PIPE:
			err = receive_pack_pipe(&client, &imsg, iev);
			if (err) {
				log_warnx("%s: receiving pack pipe: %s",
				    repo_read.title, err->msg);
				break;
			}
			if (client->pack_pipe == -1)
				break;
			err = send_packfile(client, &imsg, iev);
			if (err)
				log_warnx("%s: sending packfile: %s",
				    repo_read.title, err->msg);
			break;
		case GOTD_IMSG_DISCONNECT:
			err = recv_disconnect(&imsg);
			if (err)
				log_warnx("%s: disconnect: %s",
				    repo_read.title, err->msg);
			break;
		default:
			log_debug("%s: unexpected imsg %d", repo_read.title,
			    imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);
	}

	if (!shut && check_cancelled(NULL) == NULL) {
		if (err &&
		    gotd_imsg_send_error_event(iev, PROC_REPO_READ,
		        client ? client->id : 0, err) == -1) {
			log_warnx("could not send error to parent: %s",
			    err->msg);
		}
		gotd_imsg_event_add(iev);
	} else {
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
repo_read_main(const char *title, const char *repo_path,
    int *pack_fds, int *temp_fds)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev iev;

	repo_read.title = title;
	repo_read.pid = getpid();
	repo_read.pack_fds = pack_fds;
	repo_read.temp_fds = temp_fds;

	arc4random_buf(&clients_hash_key, sizeof(clients_hash_key));

	err = got_repo_open(&repo_read.repo, repo_path, NULL, pack_fds);
	if (err)
		goto done;
	if (!got_repo_is_bare(repo_read.repo)) {
		err = got_error_msg(GOT_ERR_NOT_GIT_REPO,
		    "bare git repository required");
		goto done;
	}

	got_repo_temp_fds_set(repo_read.repo, temp_fds);

	signal(SIGINT, catch_sigint);
	signal(SIGTERM, catch_sigterm);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	imsg_init(&iev.ibuf, GOTD_FILENO_MSG_PIPE);
	iev.handler = repo_read_dispatch;
	iev.events = EV_READ;
	iev.handler_arg = NULL;
	event_set(&iev.ev, iev.ibuf.fd, EV_READ, repo_read_dispatch, &iev);

	if (gotd_imsg_compose_event(&iev, GOTD_IMSG_REPO_CHILD_READY,
	    PROC_REPO_READ, -1, NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose REPO_CHILD_READY");
		goto done;
	}

	event_dispatch();
done:
	if (err)
		log_warnx("%s: %s", title, err->msg);
	repo_read_shutdown();
}

void
repo_read_shutdown(void)
{
	log_debug("%s: shutting down", repo_read.title);
	if (repo_read.repo)
		got_repo_close(repo_read.repo);
	got_repo_pack_fds_close(repo_read.pack_fds);
	got_repo_temp_fds_close(repo_read.temp_fds);
	exit(0);
}
