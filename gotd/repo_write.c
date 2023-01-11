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
#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/types.h>

#include <event.h>
#include <errno.h>
#include <imsg.h>
#include <signal.h>
#include <siphash.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <poll.h>
#include <sha1.h>
#include <unistd.h>
#include <zlib.h>

#include "buf.h"

#include "got_error.h"
#include "got_repository.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_path.h"

#include "got_lib_delta.h"
#include "got_lib_delta_cache.h"
#include "got_lib_object.h"
#include "got_lib_object_cache.h"
#include "got_lib_ratelimit.h"
#include "got_lib_pack.h"
#include "got_lib_pack_index.h"
#include "got_lib_repository.h"
#include "got_lib_poll.h"

#include "got_lib_sha1.h" /* XXX temp include for debugging */

#include "log.h"
#include "gotd.h"
#include "repo_write.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static struct repo_write {
	pid_t pid;
	const char *title;
	struct got_repository *repo;
	int *pack_fds;
	int *temp_fds;
	int session_fd;
	struct gotd_imsgev session_iev;
} repo_write;

struct gotd_ref_update {
	STAILQ_ENTRY(gotd_ref_update) entry;
	struct got_reference *ref;
	int ref_is_new;
	struct got_object_id old_id;
	struct got_object_id new_id;
};
STAILQ_HEAD(gotd_ref_updates, gotd_ref_update);

static struct repo_write_client {
	uint32_t			 id;
	int				 fd;
	int				 pack_pipe[2];
	struct got_pack			 pack;
	uint8_t				 pack_sha1[SHA1_DIGEST_LENGTH];
	int				 packidx_fd;
	struct gotd_ref_updates		 ref_updates;
	int				 nref_updates;
} repo_write_client;

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
send_peeled_tag_ref(struct got_reference *ref, struct got_object *obj,
    struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct got_tag_object *tag;
	size_t namelen, len;
	char *peeled_refname = NULL;
	struct got_object_id *id;
	struct ibuf *wbuf;

	err = got_object_tag_open(&tag, repo_write.repo, obj);
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

	wbuf = imsg_create(ibuf, GOTD_IMSG_REF, PROC_REPO_WRITE,
	    repo_write.pid, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create REF");
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

	err = got_ref_resolve(&id, repo_write.repo, ref);
	if (err)
		return err;

	wbuf = imsg_create(ibuf, GOTD_IMSG_REF, PROC_REPO_WRITE,
	    repo_write.pid, len);
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

	err = got_object_open(&obj, repo_write.repo, id);
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
list_refs(struct imsg *imsg)
{
	const struct got_error *err;
	struct repo_write_client *client = &repo_write_client;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	struct gotd_imsg_list_refs_internal ireq;
	size_t datalen;
	struct gotd_imsg_reflist irefs;
	struct imsgbuf ibuf;
	int client_fd = imsg->fd;

	TAILQ_INIT(&refs);

	if (client_fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ireq, imsg->data, sizeof(ireq));

	if (ireq.client_id == 0)
		return got_error(GOT_ERR_CLIENT_ID);
	if (client->id != 0) {
		return got_error_msg(GOT_ERR_CLIENT_ID,
		    "duplicate list-refs request");
	}
	client->id = ireq.client_id;
	client->fd = client_fd;
	client->pack_pipe = -1;
	client->packidx_fd = -1;
	client->nref_updates = 0;

	imsg_init(&ibuf, client_fd);

	err = got_ref_list(&refs, repo_write.repo, "",
	    got_ref_cmp_by_name, NULL);
	if (err)
		return err;

	memset(&irefs, 0, sizeof(irefs));
	TAILQ_FOREACH(re, &refs, entry) {
		struct got_object_id *id;
		int obj_type;

		if (got_ref_is_symbolic(re->ref))
			continue;

		irefs.nrefs++;

		/* Account for a peeled tag refs. */
		err = got_ref_resolve(&id, repo_write.repo, re->ref);
		if (err)
			goto done;
		err = got_object_get_type(&obj_type, repo_write.repo, id);
		free(id);
		if (err)
			goto done;
		if (obj_type == GOT_OBJ_TYPE_TAG)
			irefs.nrefs++;
	}

	if (imsg_compose(&ibuf, GOTD_IMSG_REFLIST, PROC_REPO_WRITE,
	    repo_write.pid, -1, &irefs, sizeof(irefs)) == -1) {
		err = got_error_from_errno("imsg_compose REFLIST");
		goto done;
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
protect_ref_namespace(struct got_reference *ref, const char *namespace)
{
	size_t len = strlen(namespace);

	if (len < 5 || strncmp("refs/", namespace, 5) != 0 ||
	    namespace[len -1] != '/') {
		return got_error_fmt(GOT_ERR_BAD_REF_NAME,
		    "reference namespace '%s'", namespace);
	}

	if (strncmp(namespace, got_ref_get_name(ref), len) == 0)
		return got_error_fmt(GOT_ERR_REFS_PROTECTED, "%s", namespace);

	return NULL;
}

static const struct got_error *
recv_ref_update(struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct repo_write_client *client = &repo_write_client;
	struct gotd_imsg_ref_update iref;
	size_t datalen;
	char *refname = NULL;
	struct got_reference *ref = NULL;
	struct got_object_id *id = NULL;
	struct imsgbuf ibuf;
	struct gotd_ref_update *ref_update = NULL;

	log_debug("ref-update received");

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(iref))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iref, imsg->data, sizeof(iref));
	if (datalen != sizeof(iref) + iref.name_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	imsg_init(&ibuf, client->fd);

	refname = strndup(imsg->data + sizeof(iref), iref.name_len);
	if (refname == NULL)
		return got_error_from_errno("strndup");

	ref_update = calloc(1, sizeof(*ref_update));
	if (ref_update == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}

	memcpy(ref_update->old_id.sha1, iref.old_id, SHA1_DIGEST_LENGTH);
	memcpy(ref_update->new_id.sha1, iref.new_id, SHA1_DIGEST_LENGTH);

	err = got_ref_open(&ref, repo_write.repo, refname, 0);
	if (err) {
		if (err->code != GOT_ERR_NOT_REF)
			goto done;
		err = got_ref_alloc(&ref, refname, &ref_update->new_id);
		if (err)
			goto done;
		ref_update->ref_is_new = 1;
	}
	if (got_ref_is_symbolic(ref)) {
		err = got_error_fmt(GOT_ERR_BAD_REF_TYPE,
		    "'%s' is a symbolic reference and cannot "
		    "be updated", got_ref_get_name(ref));
		goto done;
	}
	if (strncmp("refs/", got_ref_get_name(ref), 5) != 0) {
		err = got_error_fmt(GOT_ERR_BAD_REF_NAME,
		    "%s: does not begin with 'refs/'",
		    got_ref_get_name(ref));
		goto done;
	}

	err = protect_ref_namespace(ref, "refs/got/");
	if (err)
		goto done;
	err = protect_ref_namespace(ref, "refs/remotes/");
	if (err)
		goto done;

	if (!ref_update->ref_is_new) {
		/*
		 * Ensure the client's idea of this update is still valid.
		 * At this point we can only return an error, to prevent
		 * the client from uploading a pack file which will likely
		 * have to be discarded.
		 */
		err = got_ref_resolve(&id, repo_write.repo, ref);
		if (err)
			goto done;

		if (got_object_id_cmp(id, &ref_update->old_id) != 0) {
			err = got_error_fmt(GOT_ERR_REF_BUSY,
			    "%s has been modified by someone else "
			    "while transaction was in progress",
			    got_ref_get_name(ref));
			goto done;
		}
	}

	gotd_imsg_send_ack(&ref_update->new_id, &ibuf, PROC_REPO_WRITE,
	    repo_write.pid);

	ref_update->ref = ref;
	STAILQ_INSERT_HEAD(&client->ref_updates, ref_update, entry);
	client->nref_updates++;
	ref = NULL;
	ref_update = NULL;
done:
	if (ref)
		got_ref_close(ref);
	free(ref_update);
	free(refname);
	free(id);
	return err;
}

static const struct got_error *
pack_index_progress(void *arg, uint32_t nobj_total, uint32_t nobj_indexed,
    uint32_t nobj_loose, uint32_t nobj_resolved)
{
	int p_indexed = 0, p_resolved = 0;
	int nobj_delta = nobj_total - nobj_loose;

	if (nobj_total > 0)
		p_indexed = (nobj_indexed * 100) / nobj_total;

	if (nobj_delta > 0)
		p_resolved = (nobj_resolved * 100) / nobj_delta;

	if (p_resolved > 0) {
		log_debug("indexing %d objects %d%%; resolving %d deltas %d%%",
		    nobj_total, p_indexed, nobj_delta, p_resolved);
	} else
		log_debug("indexing %d objects %d%%", nobj_total, p_indexed);

	return NULL;
}

static const struct got_error *
read_more_pack_stream(int infd, BUF *buf, size_t minsize)
{
	const struct got_error *err = NULL;
	uint8_t readahead[65536];
	size_t have, newlen;

	err = got_poll_read_full(infd, &have,
	    readahead, sizeof(readahead), minsize);
	if (err)
		return err;

	err = buf_append(&newlen, buf, readahead, have);
	if (err)
		return err;
	return NULL;
}

static const struct got_error *
copy_object_type_and_size(uint8_t *type, uint64_t *size, int infd, int outfd,
    off_t *outsize, BUF *buf, size_t *buf_pos, SHA1_CTX *ctx)
{
	const struct got_error *err = NULL;
	uint8_t t = 0;
	uint64_t s = 0;
	uint8_t sizebuf[8];
	size_t i = 0;
	off_t obj_offset = *outsize;

	do {
		/* We do not support size values which don't fit in 64 bit. */
		if (i > 9)
			return got_error_fmt(GOT_ERR_OBJ_TOO_LARGE,
			    "packfile offset %lld", (long long)obj_offset);

		if (buf_len(buf) - *buf_pos < sizeof(sizebuf[0])) {
			err = read_more_pack_stream(infd, buf,
			    sizeof(sizebuf[0]));
			if (err)
				return err;
		}

		sizebuf[i] = buf_getc(buf, *buf_pos);
		*buf_pos += sizeof(sizebuf[i]);

		if (i == 0) {
			t = (sizebuf[i] & GOT_PACK_OBJ_SIZE0_TYPE_MASK) >>
			    GOT_PACK_OBJ_SIZE0_TYPE_MASK_SHIFT;
			s = (sizebuf[i] & GOT_PACK_OBJ_SIZE0_VAL_MASK);
		} else {
			size_t shift = 4 + 7 * (i - 1);
			s |= ((sizebuf[i] & GOT_PACK_OBJ_SIZE_VAL_MASK) <<
			    shift);
		}
		i++;
	} while (sizebuf[i - 1] & GOT_PACK_OBJ_SIZE_MORE);

	err = got_pack_hwrite(outfd, sizebuf, i, ctx);
	if (err)
		return err;
	*outsize += i;

	*type = t;
	*size = s;
	return NULL;
}

static const struct got_error *
copy_ref_delta(int infd, int outfd, off_t *outsize, BUF *buf, size_t *buf_pos,
    SHA1_CTX *ctx)
{
	const struct got_error *err = NULL;
	size_t remain = buf_len(buf) - *buf_pos;

	if (remain < SHA1_DIGEST_LENGTH) {
		err = read_more_pack_stream(infd, buf,
		    SHA1_DIGEST_LENGTH - remain);
		if (err)
			return err;
	}

	err = got_pack_hwrite(outfd, buf_get(buf) + *buf_pos,
	    SHA1_DIGEST_LENGTH, ctx);
	if (err)
		return err;

	*buf_pos += SHA1_DIGEST_LENGTH;
	return NULL;
}

static const struct got_error *
copy_offset_delta(int infd, int outfd, off_t *outsize, BUF *buf, size_t *buf_pos,
    SHA1_CTX *ctx)
{
	const struct got_error *err = NULL;
	uint64_t o = 0;
	uint8_t offbuf[8];
	size_t i = 0;
	off_t obj_offset = *outsize;

	do {
		/* We do not support offset values which don't fit in 64 bit. */
		if (i > 8)
			return got_error_fmt(GOT_ERR_OBJ_TOO_LARGE,
			    "packfile offset %lld", (long long)obj_offset);

		if (buf_len(buf) - *buf_pos < sizeof(offbuf[0])) {
			err = read_more_pack_stream(infd, buf,
			    sizeof(offbuf[0]));
			if (err)
				return err;
		}

		offbuf[i] = buf_getc(buf, *buf_pos);
		*buf_pos += sizeof(offbuf[i]);

		if (i == 0)
			o = (offbuf[i] & GOT_PACK_OBJ_DELTA_OFF_VAL_MASK);
		else {
			o++;
			o <<= 7;
			o += (offbuf[i] & GOT_PACK_OBJ_DELTA_OFF_VAL_MASK);
		}
		i++;
	} while (offbuf[i - 1] & GOT_PACK_OBJ_DELTA_OFF_MORE);

	if (o < sizeof(struct got_packfile_hdr) || o > *outsize)
		return got_error(GOT_ERR_PACK_OFFSET);

	err = got_pack_hwrite(outfd, offbuf, i, ctx);
	if (err)
		return err;

	*outsize += i;
	return NULL;
}

static const struct got_error *
copy_zstream(int infd, int outfd, off_t *outsize, BUF *buf, size_t *buf_pos,
    SHA1_CTX *ctx)
{
	const struct got_error *err = NULL;
	z_stream z;
	int zret;
	char voidbuf[1024];
	size_t consumed_total = 0;
	off_t zstream_offset = *outsize;

	memset(&z, 0, sizeof(z));

	z.zalloc = Z_NULL;
	z.zfree = Z_NULL;
	zret = inflateInit(&z);
	if (zret != Z_OK) {
		if  (zret == Z_ERRNO)
			return got_error_from_errno("inflateInit");
		if  (zret == Z_MEM_ERROR) {
			errno = ENOMEM;
			return got_error_from_errno("inflateInit");
		}
		return got_error_msg(GOT_ERR_DECOMPRESSION,
		    "inflateInit failed");
	}

	while (zret != Z_STREAM_END) {
		size_t last_total_in, consumed;

		/*
		 * Decompress into the void. Object data will be parsed
		 * later, when the pack file is indexed. For now, we just
		 * want to locate the end of the compressed stream.
		 */
		while (zret != Z_STREAM_END && buf_len(buf) - *buf_pos > 0) {
			last_total_in = z.total_in;
			z.next_in = buf_get(buf) + *buf_pos;
			z.avail_in = buf_len(buf) - *buf_pos;
			z.next_out = voidbuf;
			z.avail_out = sizeof(voidbuf);

			zret = inflate(&z, Z_SYNC_FLUSH);
			if (zret != Z_OK && zret != Z_BUF_ERROR &&
			    zret != Z_STREAM_END) {
				err = got_error_fmt(GOT_ERR_DECOMPRESSION,
				    "packfile offset %lld",
				    (long long)zstream_offset);
				goto done;
			}
			consumed = z.total_in - last_total_in;

			err = got_pack_hwrite(outfd, buf_get(buf) + *buf_pos,
			    consumed, ctx);
			if (err)
				goto done;

			err = buf_discard(buf, *buf_pos + consumed);
			if (err)
				goto done;
			*buf_pos = 0;

			consumed_total += consumed;
		}

		if (zret != Z_STREAM_END) {
			err = read_more_pack_stream(infd, buf, 1);
			if (err)
				goto done;
		}
	}

	if (err == NULL)
		*outsize += consumed_total;
done:
	inflateEnd(&z);
	return err;
}

static const struct got_error *
validate_object_type(int obj_type)
{
	switch (obj_type) {
	case GOT_OBJ_TYPE_BLOB:
	case GOT_OBJ_TYPE_COMMIT:
	case GOT_OBJ_TYPE_TREE:
	case GOT_OBJ_TYPE_TAG:
	case GOT_OBJ_TYPE_REF_DELTA:
	case GOT_OBJ_TYPE_OFFSET_DELTA:
		return NULL;
	default:
		break;
	}

	return got_error(GOT_ERR_OBJ_TYPE);
}

static const struct got_error *
recv_packdata(off_t *outsize, uint8_t *sha1, int infd, int outfd)
{
	const struct got_error *err;
	struct got_packfile_hdr hdr;
	size_t have;
	uint32_t nobj, nhave = 0;
	SHA1_CTX ctx;
	uint8_t expected_sha1[SHA1_DIGEST_LENGTH];
	char hex[SHA1_DIGEST_STRING_LENGTH];
	BUF *buf = NULL;
	size_t buf_pos = 0, remain;
	ssize_t w;

	*outsize = 0;
	SHA1Init(&ctx);

	err = got_poll_read_full(infd, &have, &hdr, sizeof(hdr), sizeof(hdr));
	if (err)
		return err;
	if (have != sizeof(hdr))
		return got_error_msg(GOT_ERR_BAD_PACKFILE, "short pack file");
	*outsize += have;

	if (hdr.signature != htobe32(GOT_PACKFILE_SIGNATURE))
		return got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "bad packfile signature");
	if (hdr.version != htobe32(GOT_PACKFILE_VERSION))
		return got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "bad packfile version");

	nobj = be32toh(hdr.nobjects);
	if (nobj == 0)
		return got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "bad packfile with zero objects");

	log_debug("expecting %d objects", nobj);

	err = got_pack_hwrite(outfd, &hdr, sizeof(hdr), &ctx);
	if (err)
		return err;

	err = buf_alloc(&buf, 65536);
	if (err)
		return err;

	while (nhave != nobj) {
		uint8_t obj_type;
		uint64_t obj_size;

		err = copy_object_type_and_size(&obj_type, &obj_size,
		    infd, outfd, outsize, buf, &buf_pos, &ctx);
		if (err)
			goto done;

		err = validate_object_type(obj_type);
		if (err)
			goto done;

		if (obj_type == GOT_OBJ_TYPE_REF_DELTA) {
			err = copy_ref_delta(infd, outfd, outsize,
			    buf, &buf_pos, &ctx);
			if (err)
				goto done;
		} else if (obj_type == GOT_OBJ_TYPE_OFFSET_DELTA) {
			err = copy_offset_delta(infd, outfd, outsize,
			    buf, &buf_pos, &ctx);
			if (err)
				goto done;
		}

		err = copy_zstream(infd, outfd, outsize, buf, &buf_pos, &ctx);
		if (err)
			goto done;

		nhave++;
	}

	log_debug("received %u objects", nobj);

	SHA1Final(expected_sha1, &ctx);

	remain = buf_len(buf) - buf_pos;
	if (remain < SHA1_DIGEST_LENGTH) {
		err = read_more_pack_stream(infd, buf,
		    SHA1_DIGEST_LENGTH - remain);
		if (err)
			return err;
	}

	got_sha1_digest_to_str(expected_sha1, hex, sizeof(hex));
	log_debug("expect SHA1: %s", hex);
	got_sha1_digest_to_str(buf_get(buf) + buf_pos, hex, sizeof(hex));
	log_debug("actual SHA1: %s", hex);

	if (memcmp(buf_get(buf) + buf_pos, expected_sha1,
	    SHA1_DIGEST_LENGTH) != 0) {
		err = got_error(GOT_ERR_PACKFILE_CSUM);
		goto done;
	}

	memcpy(sha1, expected_sha1, SHA1_DIGEST_LENGTH);

	w = write(outfd, expected_sha1, SHA1_DIGEST_LENGTH);
	if (w == -1) {
		err = got_error_from_errno("write");
		goto done;
	}
	if (w != SHA1_DIGEST_LENGTH) {
		err = got_error(GOT_ERR_IO);
		goto done;
	}

	*outsize += SHA1_DIGEST_LENGTH;

	if (fsync(outfd) == -1) {
		err = got_error_from_errno("fsync");
		goto done;
	}
	if (lseek(outfd, 0L, SEEK_SET) == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}
done:
	buf_free(buf);
	return err;
}

static const struct got_error *
report_pack_status(const struct got_error *unpack_err)
{
	const struct got_error *err = NULL;
	struct repo_write_client *client = &repo_write_client;
	struct gotd_imsg_packfile_status istatus;
	struct ibuf *wbuf;
	struct imsgbuf ibuf;
	const char *unpack_ok = "unpack ok\n";
	size_t len;

	imsg_init(&ibuf, client->fd);

	if (unpack_err)
		istatus.reason_len = strlen(unpack_err->msg);
	else
		istatus.reason_len = strlen(unpack_ok);

	len = sizeof(istatus) + istatus.reason_len;
	wbuf = imsg_create(&ibuf, GOTD_IMSG_PACKFILE_STATUS, PROC_REPO_WRITE,
	    repo_write.pid, len);
	if (wbuf == NULL) {
		err = got_error_from_errno("imsg_create PACKFILE_STATUS");
		goto done;
	}

	if (imsg_add(wbuf, &istatus, sizeof(istatus)) == -1) {
		err = got_error_from_errno("imsg_add PACKFILE_STATUS");
		goto done;
	}

	if (imsg_add(wbuf, err ? err->msg : unpack_ok,
	    istatus.reason_len) == -1) {
		err = got_error_from_errno("imsg_add PACKFILE_STATUS");
		goto done;
	}

	wbuf->fd = -1;
	imsg_close(&ibuf, wbuf);

	err = gotd_imsg_flush(&ibuf);
done:
	imsg_clear(&ibuf);
	return err;
}

static const struct got_error *
recv_packfile(struct imsg *imsg)
{
	const struct got_error *err = NULL, *unpack_err;
	struct repo_write_client *client = &repo_write_client;
	struct gotd_imsg_recv_packfile ireq;
	FILE *tempfiles[3] = { NULL, NULL, NULL };
	struct repo_tempfile {
		int fd;
		int idx;
	} repo_tempfiles[3] = { { - 1, - 1 }, { - 1, - 1 }, { - 1, - 1 }, };
	int i;
	size_t datalen;
	struct imsgbuf ibuf;
	struct got_ratelimit rl;
	struct got_pack *pack = NULL;
	off_t pack_filesize = 0;

	log_debug("packfile request received");

	got_ratelimit_init(&rl, 2, 0);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ireq, imsg->data, sizeof(ireq));

	if (client->pack_pipe == -1 || client->packidx_fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	imsg_init(&ibuf, client->fd);

	if (imsg->fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	pack = &client->pack;
	memset(pack, 0, sizeof(*pack));
	pack->fd = imsg->fd;
	err = got_delta_cache_alloc(&pack->delta_cache);
	if (err)
		return err;

	for (i = 0; i < nitems(repo_tempfiles); i++) {
		struct repo_tempfile *t = &repo_tempfiles[i];
		err = got_repo_temp_fds_get(&t->fd, &t->idx, repo_write.repo);
		if (err)
			goto done;
	}

	for (i = 0; i < nitems(tempfiles); i++) {
		int fd = dup(repo_tempfiles[i].fd);
		FILE *f;
		if (fd == -1) {
			err = got_error_from_errno("dup");
			goto done;
		}
		f = fdopen(fd, "w+");
		if (f == NULL) {
			err = got_error_from_errno("dup");
			close(fd);
			goto done;
		}
		tempfiles[i] = f;
	}

	/* Send pack file pipe to gotsh(1). */
	if (imsg_compose(&ibuf, GOTD_IMSG_RECV_PACKFILE, PROC_REPO_WRITE,
	    repo_write.pid, (*client)->pack_pipe[1], NULL, 0) == -1) {
		(*client)->pack_pipe[1] = -1;
		err = got_error_from_errno("imsg_compose ACK");
		if (err)	
			goto done;
	}
	(*client)->pack_pipe[1] = -1;
	err = gotd_imsg_flush(&ibuf);
	if (err)
		goto done;

	log_debug("receiving pack data");
	unpack_err = recv_packdata(&pack_filesize, client->pack_sha1,
	    client->pack_pipe, pack->fd);
	if (ireq.report_status) {
		err = report_pack_status(unpack_err);
		if (err) {
			/* Git clients hang up after sending the pack file. */
			if (err->code == GOT_ERR_EOF)
				err = NULL;
		}
	}
	if (unpack_err)
		err = unpack_err;
	if (err)
		goto done;

	log_debug("pack data received");

	pack->filesize = pack_filesize;

	log_debug("begin indexing pack (%lld bytes in size)",
	    (long long)pack->filesize);
	err = got_pack_index(pack, client->packidx_fd,
	    tempfiles[0], tempfiles[1], tempfiles[2], client->pack_sha1,
	    pack_index_progress, NULL, &rl);
	if (err)
		goto done;
	log_debug("done indexing pack");

	if (fsync(client->packidx_fd) == -1) {
		err = got_error_from_errno("fsync");
		goto done;
	}
	if (lseek(client->packidx_fd, 0L, SEEK_SET) == -1)
		err = got_error_from_errno("lseek");
done:
	if (close(client->pack_pipe) == -1 && err == NULL)
		err = got_error_from_errno("close");
	client->pack_pipe = -1;
	for (i = 0; i < nitems(repo_tempfiles); i++) {
		struct repo_tempfile *t = &repo_tempfiles[i];
		if (t->idx != -1)
			got_repo_temp_fds_put(t->idx, repo_write.repo);
	}
	for (i = 0; i < nitems(tempfiles); i++) {
		if (tempfiles[i] && fclose(tempfiles[i]) == EOF && err == NULL)
			err = got_error_from_errno("fclose");
	}
	if (err)
		got_pack_close(pack);
	imsg_clear(&ibuf);
	return err;
}

static const struct got_error *
verify_packfile(void)
{
	const struct got_error *err = NULL, *close_err;
	struct repo_write_client *client = &repo_write_client;
	struct gotd_ref_update *ref_update;
	struct got_packidx *packidx = NULL;
	struct stat sb;
	char *id_str = NULL;
	int idx = -1;

	if (STAILQ_EMPTY(&client->ref_updates)) {
		return got_error_msg(GOT_ERR_BAD_REQUEST,
		    "cannot verify pack file without any ref-updates");
	}

	if (client->pack.fd == -1) {
		return got_error_msg(GOT_ERR_BAD_REQUEST,
		    "invalid pack file handle during pack verification");
	}
	if (client->packidx_fd == -1) {
		return got_error_msg(GOT_ERR_BAD_REQUEST,
		    "invalid pack index handle during pack verification");
	}

	if (fstat(client->packidx_fd, &sb) == -1)
		return got_error_from_errno("pack index fstat");

	packidx = malloc(sizeof(*packidx));
	memset(packidx, 0, sizeof(*packidx));
	packidx->fd = client->packidx_fd;
	client->packidx_fd = -1;
	packidx->len = sb.st_size;

	err = got_packidx_init_hdr(packidx, 1, client->pack.filesize);
	if (err)
		return err;

	STAILQ_FOREACH(ref_update, &client->ref_updates, entry) {
		err = got_object_id_str(&id_str, &ref_update->new_id);
		if (err)
			goto done;

		idx = got_packidx_get_object_idx(packidx, &ref_update->new_id);
		if (idx == -1) {
			err = got_error_fmt(GOT_ERR_BAD_PACKFILE,
			    "advertised object %s is missing from pack file",
			    id_str);
			goto done;
		}
	}

done:
	close_err = got_packidx_close(packidx);
	if (close_err && err == NULL)
		err = close_err;
	free(id_str);
	return err;
}

static const struct got_error *
install_packfile(struct gotd_imsgev *iev)
{
	struct repo_write_client *client = &repo_write_client;
	struct gotd_imsg_packfile_install inst;
	int ret;

	memset(&inst, 0, sizeof(inst));
	inst.client_id = client->id;
	memcpy(inst.pack_sha1, client->pack_sha1, SHA1_DIGEST_LENGTH);

	ret = gotd_imsg_compose_event(iev, GOTD_IMSG_PACKFILE_INSTALL,
	    PROC_REPO_WRITE, -1, &inst, sizeof(inst));
	if (ret == -1)
		return got_error_from_errno("imsg_compose PACKFILE_INSTALL");

	return NULL;
}

static const struct got_error *
send_ref_updates_start(int nref_updates, struct gotd_imsgev *iev)
{
	struct repo_write_client *client = &repo_write_client;
	struct gotd_imsg_ref_updates_start istart;
	int ret;

	memset(&istart, 0, sizeof(istart));
	istart.nref_updates = nref_updates;
	istart.client_id = client->id;

	ret = gotd_imsg_compose_event(iev, GOTD_IMSG_REF_UPDATES_START,
	    PROC_REPO_WRITE, -1, &istart, sizeof(istart));
	if (ret == -1)
		return got_error_from_errno("imsg_compose REF_UPDATES_START");

	return NULL;
}


static const struct got_error *
send_ref_update(struct gotd_ref_update *ref_update, struct gotd_imsgev *iev)
{
	struct repo_write_client *client = &repo_write_client;
	struct gotd_imsg_ref_update iref;
	const char *refname = got_ref_get_name(ref_update->ref);
	struct ibuf *wbuf;
	size_t len;

	memset(&iref, 0, sizeof(iref));
	memcpy(iref.old_id, ref_update->old_id.sha1, SHA1_DIGEST_LENGTH);
	memcpy(iref.new_id, ref_update->new_id.sha1, SHA1_DIGEST_LENGTH);
	iref.ref_is_new = ref_update->ref_is_new;
	iref.client_id = client->id;
	iref.name_len = strlen(refname);

	len = sizeof(iref) + iref.name_len;
	wbuf = imsg_create(&iev->ibuf, GOTD_IMSG_REF_UPDATE, PROC_REPO_WRITE,
	    repo_write.pid, len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create REF_UPDATE");

	if (imsg_add(wbuf, &iref, sizeof(iref)) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE");
	if (imsg_add(wbuf, refname, iref.name_len) == -1)
		return got_error_from_errno("imsg_add REF_UPDATE");

	wbuf->fd = -1;
	imsg_close(&iev->ibuf, wbuf);

	gotd_imsg_event_add(iev);
	return NULL;
}

static const struct got_error *
update_refs(struct gotd_imsgev *iev)
{
	const struct got_error *err = NULL;
	struct repo_write_client *client = &repo_write_client;
	struct gotd_ref_update *ref_update;

	err = send_ref_updates_start(client->nref_updates, iev);
	if (err)
		return err;

	STAILQ_FOREACH(ref_update, &client->ref_updates, entry) {
		err = send_ref_update(ref_update, iev);
		if (err)
			goto done;
	}
done:
	return err;
}

static const struct got_error *
recv_disconnect(struct imsg *imsg)
{
	const struct got_error *err = NULL;
	struct gotd_imsg_disconnect idisconnect;
	size_t datalen;
	int pack_pipe = -1, idxfd = -1;
	struct repo_write_client *client = &repo_write_client;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(idisconnect))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&idisconnect, imsg->data, sizeof(idisconnect));

	log_debug("client disconnecting");

	while (!STAILQ_EMPTY(&client->ref_updates)) {
		struct gotd_ref_update *ref_update;
		ref_update = STAILQ_FIRST(&client->ref_updates);
		STAILQ_REMOVE_HEAD(&client->ref_updates, entry);
		got_ref_close(ref_update->ref);
		free(ref_update);
	}
	err = got_pack_close(&client->pack);
	if (client->fd != -1 && close(client->fd) == -1)
		err = got_error_from_errno("close");
	pack_pipe = client->pack_pipe;
	if (pack_pipe != -1 && close(pack_pipe) == -1 && err == NULL)
		err = got_error_from_errno("close");
	idxfd = client->packidx_fd;
	if (idxfd != -1 && close(idxfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err;
}

static const struct got_error *
receive_pack_pipe(struct imsg *imsg, struct gotd_imsgev *iev)
{
	struct repo_write_client *client = &repo_write_client;
	struct gotd_imsg_packfile_pipe ireq;
	size_t datalen;

	log_debug("receving pack pipe descriptor");

	if (imsg->fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ireq, imsg->data, sizeof(ireq));

	if (client->pack_pipe != -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	client->pack_pipe = imsg->fd;
	return NULL;
}

static const struct got_error *
receive_pack_idx(struct imsg *imsg, struct gotd_imsgev *iev)
{
	struct repo_write_client *client = &repo_write_client;
	struct gotd_imsg_packidx_file ireq;
	size_t datalen;

	log_debug("receving pack index output file");

	if (imsg->fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ireq))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&ireq, imsg->data, sizeof(ireq));

	if (client->packidx_fd != -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	client->packidx_fd = imsg->fd;
	return NULL;
}

static void
repo_write_dispatch_session(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	struct repo_write_client *client = &repo_write_client;
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
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		if (imsg.hdr.type != GOTD_IMSG_LIST_REFS_INTERNAL &&
		    client->id == 0) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		switch (imsg.hdr.type) {
		case GOTD_IMSG_LIST_REFS_INTERNAL:
			err = list_refs(&imsg);
			if (err)
				log_warnx("%s: ls-refs: %s", repo_write.title,
				    err->msg);
			break;
		case GOTD_IMSG_REF_UPDATE:
			err = recv_ref_update(&imsg);
			if (err)
				log_warnx("%s: ref-update: %s",
				    repo_write.title, err->msg);
			break;
		case GOTD_IMSG_PACKFILE_PIPE:
			err = receive_pack_pipe(&imsg, iev);
			if (err) {
				log_warnx("%s: receiving pack pipe: %s",
				    repo_write.title, err->msg);
				break;
			}
			break;
		case GOTD_IMSG_PACKIDX_FILE:
			err = receive_pack_idx(&imsg, iev);
			if (err) {
				log_warnx("%s: receiving pack index: %s",
				    repo_write.title, err->msg);
				break;
			}
			break;
		case GOTD_IMSG_RECV_PACKFILE:
			err = recv_packfile(&imsg);
			if (err) {
				log_warnx("%s: receive packfile: %s",
				    repo_write.title, err->msg);
				break;
			}
			err = verify_packfile();
			if (err) {
				log_warnx("%s: verify packfile: %s",
				    repo_write.title, err->msg);
				break;
			}
			err = install_packfile(iev);
			if (err) {
				log_warnx("%s: install packfile: %s",
				    repo_write.title, err->msg);
				break;
			}
			err = update_refs(iev);
			if (err) {
				log_warnx("%s: update refs: %s",
				    repo_write.title, err->msg);
			}
			break;
		case GOTD_IMSG_DISCONNECT:
			err = recv_disconnect(&imsg);
			if (err)
				log_warnx("%s: disconnect: %s",
				    repo_write.title, err->msg);
			shut = 1;
			break;
		default:
			log_debug("%s: unexpected imsg %d", repo_write.title,
			    imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);
	}

	if (!shut && check_cancelled(NULL) == NULL) {
		if (err &&
		    gotd_imsg_send_error_event(iev, PROC_REPO_WRITE,
		        client->id, err) == -1) {
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

static const struct got_error *
recv_connect(struct imsg *imsg)
{
	struct gotd_imsgev *iev = &repo_write.session_iev;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != 0)
		return got_error(GOT_ERR_PRIVSEP_LEN);
	if (imsg->fd == -1)
		return got_error(GOT_ERR_PRIVSEP_NO_FD);

	if (repo_write.session_fd != -1)
		return got_error(GOT_ERR_PRIVSEP_MSG);

	repo_write.session_fd = imsg->fd;

	imsg_init(&iev->ibuf, repo_write.session_fd);
	iev->handler = repo_write_dispatch_session;
	iev->events = EV_READ;
	iev->handler_arg = NULL;
	event_set(&iev->ev, iev->ibuf.fd, EV_READ,
	    repo_write_dispatch_session, iev);
	gotd_imsg_event_add(iev);

	return NULL;
}

static void
repo_write_dispatch(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	int shut = 0;
	struct repo_write_client *client = &repo_write_client;

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
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTD_IMSG_CONNECT_REPO_CHILD:
			err = recv_connect(&imsg);
			break;
		default:
			log_debug("%s: unexpected imsg %d", repo_write.title,
			    imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);
	}

	if (!shut && check_cancelled(NULL) == NULL) {
		if (err &&
		    gotd_imsg_send_error_event(iev, PROC_REPO_WRITE,
		        client->id, err) == -1) {
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
repo_write_main(const char *title, const char *repo_path,
    int *pack_fds, int *temp_fds)
{
	const struct got_error *err = NULL;
	struct gotd_imsgev iev;

	repo_write.title = title;
	repo_write.pid = getpid();
	repo_write.pack_fds = pack_fds;
	repo_write.temp_fds = temp_fds;
	repo_write.session_fd = -1;
	repo_write.session_iev.ibuf.fd = -1;

	STAILQ_INIT(&repo_write_client.ref_updates);

	err = got_repo_open(&repo_write.repo, repo_path, NULL, pack_fds);
	if (err)
		goto done;
	if (!got_repo_is_bare(repo_write.repo)) {
		err = got_error_msg(GOT_ERR_NOT_GIT_REPO,
		    "bare git repository required");
		goto done;
	}

	got_repo_temp_fds_set(repo_write.repo, temp_fds);

	signal(SIGINT, catch_sigint);
	signal(SIGTERM, catch_sigterm);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	imsg_init(&iev.ibuf, GOTD_FILENO_MSG_PIPE);
	iev.handler = repo_write_dispatch;
	iev.events = EV_READ;
	iev.handler_arg = NULL;
	event_set(&iev.ev, iev.ibuf.fd, EV_READ, repo_write_dispatch, &iev);
	if (gotd_imsg_compose_event(&iev, GOTD_IMSG_REPO_CHILD_READY,
	    PROC_REPO_WRITE, -1, NULL, 0) == -1) {
		err = got_error_from_errno("imsg compose REPO_CHILD_READY");
		goto done;
	}

	event_dispatch();
done:
	if (err)
		log_warnx("%s: %s", title, err->msg);
	repo_write_shutdown();
}

void
repo_write_shutdown(void)
{
	log_debug("%s: shutting down", repo_write.title);
	if (repo_write.repo)
		got_repo_close(repo_write.repo);
	got_repo_pack_fds_close(repo_write.pack_fds);
	got_repo_temp_fds_close(repo_write.temp_fds);
	if (repo_write.session_fd != -1)
		close(repo_write.session_fd);
	exit(0);
}
