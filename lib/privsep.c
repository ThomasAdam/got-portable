/*
 * Copyright (c) 2018 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/uio.h>
#include <sys/syslimits.h>
#include <sys/wait.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <poll.h>
#include <imsg.h>
#include <sha1.h>
#include <zlib.h>
#include <time.h>

#include "got_object.h"
#include "got_error.h"

#include "got_lib_sha1.h"
#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_privsep.h"
#include "got_lib_pack.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

static const struct got_error *
poll_fd(int fd, int events, int timeout)
{
	struct pollfd pfd[1];
	int n;

	pfd[0].fd = fd;
	pfd[0].events = events;

	n = poll(pfd, 1, timeout);
	if (n == -1)
		return got_error_from_errno();
	if (n == 0)
		return got_error(GOT_ERR_TIMEOUT);
	if (pfd[0].revents & (POLLERR | POLLNVAL))
		return got_error_from_errno();
	if (pfd[0].revents & (events | POLLHUP))
		return NULL;

	return got_error(GOT_ERR_INTERRUPT);
}

static const struct got_error *
read_imsg(struct imsgbuf *ibuf)
{
	const struct got_error *err;
	size_t n;

	err = poll_fd(ibuf->fd, POLLIN, INFTIM);
	if (err)
		return err;

	n = imsg_read(ibuf);
	if (n == -1) {
		if (errno == EAGAIN) /* Could be a file-descriptor leak. */
			return got_error(GOT_ERR_PRIVSEP_NO_FD);
		return got_error(GOT_ERR_PRIVSEP_READ);
	}
	if (n == 0)
		return got_error(GOT_ERR_PRIVSEP_PIPE);

	return NULL;
}

const struct got_error *
got_privsep_wait_for_child(pid_t pid)
{
	int child_status;

	waitpid(pid, &child_status, 0);

	if (!WIFEXITED(child_status))
		return got_error(GOT_ERR_PRIVSEP_DIED);

	if (WEXITSTATUS(child_status) != 0)
		return got_error(GOT_ERR_PRIVSEP_EXIT);

	return NULL;
}

const struct got_error *
got_privsep_recv_imsg(struct imsg *imsg, struct imsgbuf *ibuf,
    size_t min_datalen)
{
	const struct got_error *err;
	ssize_t n;

	n = imsg_get(ibuf, imsg);
	if (n == -1)
		return got_error_from_errno();

	while (n == 0) {
		err = read_imsg(ibuf);
		if (err)
			return err;
		n = imsg_get(ibuf, imsg);
	}

	if (imsg->hdr.len < IMSG_HEADER_SIZE + min_datalen)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	return NULL;
}

static const struct got_error *
recv_imsg_error(struct imsg *imsg, size_t datalen)
{
	struct got_imsg_error *ierr;

	if (datalen != sizeof(*ierr))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	ierr = imsg->data;
	if (ierr->code == GOT_ERR_ERRNO) {
		static struct got_error serr;
		serr.code = GOT_ERR_ERRNO;
		serr.msg = strerror(ierr->errno_code);
		return &serr;
	}

	return got_error(ierr->code);
}

/* Attempt to send an error in an imsg. Complain on stderr as a last resort. */
void
got_privsep_send_error(struct imsgbuf *ibuf, const struct got_error *err)
{
	const struct got_error *poll_err;
	struct got_imsg_error ierr;
	int ret;

	ierr.code = err->code;
	if (err->code == GOT_ERR_ERRNO)
		ierr.errno_code = errno;
	else
		ierr.errno_code = 0;
	ret = imsg_compose(ibuf, GOT_IMSG_ERROR, 0, 0, -1, &ierr, sizeof(ierr));
	if (ret == -1) {
		fprintf(stderr, "%s: error %d \"%s\": imsg_compose: %s\n",
		    getprogname(), err->code, err->msg, strerror(errno));
		return;
	}

	poll_err = poll_fd(ibuf->fd, POLLOUT, INFTIM);
	if (poll_err) {
		fprintf(stderr, "%s: error %d \"%s\": poll: %s\n",
		    getprogname(), err->code, err->msg, poll_err->msg);
		return;
	}

	ret = imsg_flush(ibuf);
	if (ret == -1) {
		fprintf(stderr, "%s: error %d \"%s\": imsg_flush: %s\n",
		    getprogname(), err->code, err->msg, strerror(errno));
		return;
	}
}

static const struct got_error *
flush_imsg(struct imsgbuf *ibuf)
{
	const struct got_error *err;

	err = poll_fd(ibuf->fd, POLLOUT, INFTIM);
	if (err)
		return err;

	if (imsg_flush(ibuf) == -1)
		return got_error_from_errno();

	return NULL;
}

const struct got_error *
got_privsep_send_stop(int fd)
{
	const struct got_error *err = NULL;
	struct imsgbuf ibuf;

	imsg_init(&ibuf, fd);

	if (imsg_compose(&ibuf, GOT_IMSG_STOP, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno();

	err = flush_imsg(&ibuf);
	imsg_clear(&ibuf);
	return err;
}

const struct got_error *
got_privsep_send_obj_req(struct imsgbuf *ibuf, int fd, struct got_object *obj)
{
	struct got_imsg_object iobj, *iobjp = NULL;
	size_t iobj_size = 0;
	int imsg_code = GOT_IMSG_OBJECT_REQUEST;

	if (obj) {
		switch (obj->type) {
		case GOT_OBJ_TYPE_TREE:
			imsg_code = GOT_IMSG_TREE_REQUEST;
			break;
		case GOT_OBJ_TYPE_COMMIT:
			imsg_code = GOT_IMSG_COMMIT_REQUEST;
			break;
		case GOT_OBJ_TYPE_BLOB:
			imsg_code = GOT_IMSG_BLOB_REQUEST;
			break;
		default:
			return got_error(GOT_ERR_OBJ_TYPE);
		}

		memcpy(iobj.id, obj->id.sha1, sizeof(iobj.id));
		iobj.type = obj->type;
		iobj.flags = obj->flags;
		iobj.hdrlen = obj->hdrlen;
		iobj.size = obj->size;
		if (iobj.flags & GOT_OBJ_FLAG_PACKED) {
			iobj.pack_offset = obj->pack_offset;
			iobj.pack_idx = obj->pack_idx;
		}

		iobjp = &iobj;
		iobj_size = sizeof(iobj);
	}

	if (imsg_compose(ibuf, imsg_code, 0, 0, fd, iobjp, iobj_size) == -1)
		return got_error_from_errno();

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_blob_req(struct imsgbuf *ibuf, int infd)
{
	if (imsg_compose(ibuf, GOT_IMSG_BLOB_REQUEST, 0, 0, infd, NULL, 0)
	    == -1)
		return got_error_from_errno();

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_blob_outfd(struct imsgbuf *ibuf, int outfd)
{
	if (imsg_compose(ibuf, GOT_IMSG_BLOB_OUTFD, 0, 0, outfd, NULL, 0)
	    == -1)
		return got_error_from_errno();

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_tmpfd(struct imsgbuf *ibuf, int fd)
{
	if (imsg_compose(ibuf, GOT_IMSG_TMPFD, 0, 0, fd, NULL, 0)
	    == -1)
		return got_error_from_errno();

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_obj(struct imsgbuf *ibuf, struct got_object *obj)
{
	struct got_imsg_object iobj;

	memcpy(iobj.id, obj->id.sha1, sizeof(iobj.id));
	iobj.type = obj->type;
	iobj.flags = obj->flags;
	iobj.hdrlen = obj->hdrlen;
	iobj.size = obj->size;
	if (iobj.flags & GOT_OBJ_FLAG_PACKED) {
		iobj.pack_offset = obj->pack_offset;
		iobj.pack_idx = obj->pack_idx;
	}

	if (imsg_compose(ibuf, GOT_IMSG_OBJECT, 0, 0, -1, &iobj, sizeof(iobj))
	    == -1)
		return got_error_from_errno();

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_get_imsg_obj(struct got_object **obj, struct imsg *imsg,
    struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct got_imsg_object *iobj;
	size_t datalen = imsg->hdr.len - IMSG_HEADER_SIZE;

	if (datalen != sizeof(*iobj))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	iobj = imsg->data;

	*obj = calloc(1, sizeof(**obj));
	if (*obj == NULL)
		return got_error_from_errno();

	memcpy((*obj)->id.sha1, iobj->id, SHA1_DIGEST_LENGTH);
	(*obj)->type = iobj->type;
	(*obj)->flags = iobj->flags;
	(*obj)->hdrlen = iobj->hdrlen;
	(*obj)->size = iobj->size;
	/* path_packfile is handled by caller */
	if (iobj->flags & GOT_OBJ_FLAG_PACKED) {
		(*obj)->pack_offset = iobj->pack_offset;
		(*obj)->pack_idx = iobj->pack_idx;
	}

	return err;
}

const struct got_error *
got_privsep_recv_obj(struct got_object **obj, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	size_t datalen;
	const size_t min_datalen =
	    MIN(sizeof(struct got_imsg_error), sizeof(struct got_imsg_object));

	*obj = NULL;

	err = got_privsep_recv_imsg(&imsg, ibuf, min_datalen);
	if (err)
		return err;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case GOT_IMSG_ERROR:
		err = recv_imsg_error(&imsg, datalen);
		break;
	case GOT_IMSG_OBJECT:
		err = got_privsep_get_imsg_obj(obj, &imsg, ibuf);
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);

	return err;
}

static const struct got_error *
send_commit_logmsg(struct imsgbuf *ibuf, struct got_commit_object *commit,
    size_t logmsg_len)
{
	const struct got_error *err = NULL;
	size_t offset, remain;

	offset = 0;
	remain = logmsg_len;
	while (remain > 0) {
		size_t n = MIN(MAX_IMSGSIZE - IMSG_HEADER_SIZE, remain);

		if (imsg_compose(ibuf, GOT_IMSG_COMMIT_LOGMSG, 0, 0, -1,
		    commit->logmsg + offset, n) == -1) {
			err = got_error_from_errno();
			break;
		}

		err = flush_imsg(ibuf);
		if (err)
			break;

		offset += n;
		remain -= n;
	}

	return err;
}

const struct got_error *
got_privsep_send_commit(struct imsgbuf *ibuf, struct got_commit_object *commit)
{
	const struct got_error *err = NULL;
	struct got_imsg_commit_object *icommit;
	uint8_t *buf;
	size_t len, total;
	struct got_object_qid *qid;
	size_t author_len = strlen(commit->author);
	size_t committer_len = strlen(commit->committer);
	size_t logmsg_len = strlen(commit->logmsg);

	total = sizeof(*icommit) + author_len + committer_len +
	    commit->nparents * SHA1_DIGEST_LENGTH;

	buf = malloc(total);
	if (buf == NULL)
		return got_error_from_errno();

	icommit = (struct got_imsg_commit_object *)buf;
	memcpy(icommit->tree_id, commit->tree_id->sha1, sizeof(icommit->tree_id));
	icommit->author_len = author_len;
	icommit->author_time = commit->author_time;
	icommit->author_gmtoff = commit->author_gmtoff;
	icommit->committer_len = committer_len;
	icommit->committer_time = commit->committer_time;
	icommit->committer_gmtoff = commit->committer_gmtoff;
	icommit->logmsg_len = logmsg_len;
	icommit->nparents = commit->nparents;

	len = sizeof(*icommit);
	memcpy(buf + len, commit->author, author_len);
	len += author_len;
	memcpy(buf + len, commit->committer, committer_len);
	len += committer_len;
	SIMPLEQ_FOREACH(qid, &commit->parent_ids, entry) {
		memcpy(buf + len, qid->id, SHA1_DIGEST_LENGTH);
		len += SHA1_DIGEST_LENGTH;
	}

	if (imsg_compose(ibuf, GOT_IMSG_COMMIT, 0, 0, -1, buf, len) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	if (logmsg_len == 0 ||
	    logmsg_len + len > MAX_IMSGSIZE - IMSG_HEADER_SIZE) {
		err = flush_imsg(ibuf);
		if (err)
			goto done;
	}
	err = send_commit_logmsg(ibuf, commit, logmsg_len);
done:
	free(buf);
	return err;
}

const struct got_error *
got_privsep_recv_commit(struct got_commit_object **commit, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_commit_object *icommit;
	size_t len, datalen;
	int i;
	const size_t min_datalen =
	    MIN(sizeof(struct got_imsg_error),
	    sizeof(struct got_imsg_commit_object));

	*commit = NULL;

	err = got_privsep_recv_imsg(&imsg, ibuf, min_datalen);
	if (err)
		return err;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	len = 0;

	switch (imsg.hdr.type) {
	case GOT_IMSG_ERROR:
		err = recv_imsg_error(&imsg, datalen);
		break;
	case GOT_IMSG_COMMIT:
		if (datalen < sizeof(*icommit)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		icommit = imsg.data;
		if (datalen != sizeof(*icommit) + icommit->author_len +
		    icommit->committer_len +
		    icommit->nparents * SHA1_DIGEST_LENGTH) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		if (icommit->nparents < 0) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		len += sizeof(*icommit);

		*commit = got_object_commit_alloc_partial();
		if (*commit == NULL) {
			err = got_error_from_errno();
			break;
		}

		memcpy((*commit)->tree_id->sha1, icommit->tree_id,
		    SHA1_DIGEST_LENGTH);
		(*commit)->author_time = icommit->author_time;
		(*commit)->author_gmtoff = icommit->author_gmtoff;
		(*commit)->committer_time = icommit->committer_time;
		(*commit)->committer_gmtoff = icommit->committer_gmtoff;

		if (icommit->author_len == 0) {
			(*commit)->author = strdup("");
			if ((*commit)->author == NULL) {
				err = got_error_from_errno();
				break;
			}
		} else {
			(*commit)->author = malloc(icommit->author_len + 1);
			if ((*commit)->author == NULL) {
				err = got_error_from_errno();
				break;
			}
			memcpy((*commit)->author, imsg.data + len,
			    icommit->author_len);
			(*commit)->author[icommit->author_len] = '\0';
		}
		len += icommit->author_len;

		if (icommit->committer_len == 0) {
			(*commit)->committer = strdup("");
			if ((*commit)->committer == NULL) {
				err = got_error_from_errno();
				break;
			}
		} else {
			(*commit)->committer =
			    malloc(icommit->committer_len + 1);
			if ((*commit)->committer == NULL) {
				err = got_error_from_errno();
				break;
			}
			memcpy((*commit)->committer, imsg.data + len,
			    icommit->committer_len);
			(*commit)->committer[icommit->committer_len] = '\0';
		}
		len += icommit->committer_len;

		if (icommit->logmsg_len == 0) {
			(*commit)->logmsg = strdup("");
			if ((*commit)->logmsg == NULL) {
				err = got_error_from_errno();
				break;
			}
		} else {
			size_t offset = 0, remain = icommit->logmsg_len;

			(*commit)->logmsg = malloc(icommit->logmsg_len + 1);
			if ((*commit)->logmsg == NULL) {
				err = got_error_from_errno();
				break;
			}
			while (remain > 0) {
				struct imsg imsg_log;
				size_t n = MIN(MAX_IMSGSIZE - IMSG_HEADER_SIZE,
				    remain);

				err = got_privsep_recv_imsg(&imsg_log, ibuf, n);
				if (err)
					return err;

				if (imsg_log.hdr.type != GOT_IMSG_COMMIT_LOGMSG)
					return got_error(GOT_ERR_PRIVSEP_MSG);

				memcpy((*commit)->logmsg + offset,
				    imsg_log.data, n);
				imsg_free(&imsg_log);
				offset += n;
				remain -= n;
			}
			(*commit)->logmsg[icommit->logmsg_len] = '\0';
		}

		for (i = 0; i < icommit->nparents; i++) {
			struct got_object_qid *qid;

			err = got_object_qid_alloc_partial(&qid);
			if (err)
				break;
			memcpy(qid->id, imsg.data + len +
			    i * SHA1_DIGEST_LENGTH, sizeof(*qid->id));
			SIMPLEQ_INSERT_TAIL(&(*commit)->parent_ids, qid, entry);
			(*commit)->nparents++;
		}
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);

	return err;
}

const struct got_error *
got_privsep_send_tree(struct imsgbuf *ibuf, struct got_tree_object *tree)
{
	const struct got_error *err = NULL;
	struct got_imsg_tree_object itree;
	struct got_tree_entry *te;
	size_t totlen;
	int nimsg; /* number of imsg queued in ibuf */

	itree.nentries = tree->entries.nentries;
	if (imsg_compose(ibuf, GOT_IMSG_TREE, 0, 0, -1, &itree, sizeof(itree))
	    == -1)
		return got_error_from_errno();

	totlen = sizeof(itree);
	nimsg = 1;
	SIMPLEQ_FOREACH(te, &tree->entries.head, entry) {
		struct got_imsg_tree_entry *ite;
		uint8_t *buf = NULL;
		size_t len = sizeof(*ite) + strlen(te->name);

		if (len > MAX_IMSGSIZE)
			return got_error(GOT_ERR_NO_SPACE);

		nimsg++;
		if (totlen + len >= MAX_IMSGSIZE - (IMSG_HEADER_SIZE * nimsg)) {
			err = flush_imsg(ibuf);
			if (err)
				return err;
			nimsg = 0;
		}

		buf = malloc(len);
		if (buf == NULL)
			return got_error_from_errno();

		ite = (struct got_imsg_tree_entry *)buf;
		memcpy(ite->id, te->id->sha1, sizeof(ite->id));
		ite->mode = te->mode;
		memcpy(buf + sizeof(*ite), te->name, strlen(te->name));

		if (imsg_compose(ibuf, GOT_IMSG_TREE_ENTRY, 0, 0, -1,
		    buf, len) == -1)
			err = got_error_from_errno();
		free(buf);
		if (err)
			return err;
		totlen += len;
	}

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_recv_tree(struct got_tree_object **tree, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	const size_t min_datalen =
	    MIN(sizeof(struct got_imsg_error),
	    sizeof(struct got_imsg_tree_object));
	struct got_imsg_tree_object *itree;
	int nentries = 0;

	*tree = NULL;
get_more:
	err = read_imsg(ibuf);
	if (err)
		goto done;

	while (1) {
		struct imsg imsg;
		size_t n;
		size_t datalen;
		struct got_imsg_tree_entry *ite;
		struct got_tree_entry *te = NULL;

		n = imsg_get(ibuf, &imsg);
		if (n == 0) {
			if (*tree && (*tree)->entries.nentries != nentries)
				goto get_more;
			break;
		}

		if (imsg.hdr.len < IMSG_HEADER_SIZE + min_datalen)
			return got_error(GOT_ERR_PRIVSEP_LEN);

		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case GOT_IMSG_ERROR:
			err = recv_imsg_error(&imsg, datalen);
			break;
		case GOT_IMSG_TREE:
			/* This message should only appear once. */
			if (*tree != NULL) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			if (datalen != sizeof(*itree)) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			itree = imsg.data;
			*tree = malloc(sizeof(**tree));
			if (*tree == NULL) {
				err = got_error_from_errno();
				break;
			}
			(*tree)->entries.nentries = itree->nentries;
			SIMPLEQ_INIT(&(*tree)->entries.head);
			(*tree)->refcnt = 0;
			break;
		case GOT_IMSG_TREE_ENTRY:
			/* This message should be preceeded by GOT_IMSG_TREE. */
			if (*tree == NULL) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			if (datalen < sizeof(*ite) || datalen > MAX_IMSGSIZE) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}

			/* Remaining data contains the entry's name. */
			datalen -= sizeof(*ite);
			if (datalen == 0 || datalen > MAX_IMSGSIZE) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			ite = imsg.data;

			te = got_alloc_tree_entry_partial();
			if (te == NULL) {
				err = got_error_from_errno();
				break;
			}
			te->name = malloc(datalen + 1);
			if (te->name == NULL) {
				free(te);
				err = got_error_from_errno();
				break;
			}
			memcpy(te->name, imsg.data + sizeof(*ite), datalen);
			te->name[datalen] = '\0';

			memcpy(te->id->sha1, ite->id, SHA1_DIGEST_LENGTH);
			te->mode = ite->mode;
			SIMPLEQ_INSERT_TAIL(&(*tree)->entries.head, te, entry);
			nentries++;
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}
done:
	if (*tree && (*tree)->entries.nentries != nentries) {
		if (err == NULL)
			err = got_error(GOT_ERR_PRIVSEP_LEN);
		got_object_tree_close(*tree);
		*tree = NULL;
	}

	return err;
}

const struct got_error *
got_privsep_send_blob(struct imsgbuf *ibuf, size_t size)
{
	struct got_imsg_blob iblob;

	iblob.size = size;
	/* Data has already been written to file descriptor. */

	if (imsg_compose(ibuf, GOT_IMSG_BLOB, 0, 0, -1, &iblob, sizeof(iblob))
	    == -1)
		return got_error_from_errno();

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_recv_blob(size_t *size, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_blob *iblob;
	size_t datalen;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case GOT_IMSG_ERROR:
		err = recv_imsg_error(&imsg, datalen);
		break;
	case GOT_IMSG_BLOB:
		if (datalen != sizeof(*iblob)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		iblob = imsg.data;
		*size = iblob->size;
		/* Data has been written to file descriptor. */
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);

	return err;
}

const struct got_error *
got_privsep_init_pack_child(struct imsgbuf *ibuf, struct got_pack *pack,
    struct got_packidx *packidx)
{
	struct got_imsg_packidx ipackidx;
	struct got_imsg_pack ipack;
	int fd;

	ipackidx.len = packidx->len;
	fd = dup(packidx->fd);
	if (fd == -1)
		return got_error_from_errno();

	if (imsg_compose(ibuf, GOT_IMSG_PACKIDX, 0, 0, fd, &ipackidx,
	    sizeof(ipackidx)) == -1)
		return got_error_from_errno();

	if (strlcpy(ipack.path_packfile, pack->path_packfile,
	    sizeof(ipack.path_packfile)) >= sizeof(ipack.path_packfile))
		return got_error(GOT_ERR_NO_SPACE);
	ipack.filesize = pack->filesize;

	fd = dup(pack->fd);
	if (fd == -1)
		return got_error_from_errno();

	if (imsg_compose(ibuf, GOT_IMSG_PACK, 0, 0, fd, &ipack, sizeof(ipack))
	    == -1)
		return got_error_from_errno();

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_send_packed_obj_req(struct imsgbuf *ibuf, int idx,
    struct got_object_id *id)
{
	struct got_imsg_packed_object iobj;

	iobj.idx = idx;
	memcpy(iobj.id, id->sha1, sizeof(iobj.id));

	if (imsg_compose(ibuf, GOT_IMSG_PACKED_OBJECT_REQUEST, 0, 0, -1,
	    &iobj, sizeof(iobj)) == -1)
		return got_error_from_errno();

	return flush_imsg(ibuf);
}
