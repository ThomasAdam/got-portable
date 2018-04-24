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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <poll.h>
#include <imsg.h>
#include <sha1.h>
#include <zlib.h>

#include "got_object.h"
#include "got_error.h"

#include "got_lib_sha1.h"
#include "got_lib_delta.h"
#include "got_lib_zbuf.h"
#include "got_lib_object.h"
#include "got_lib_privsep.h"

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

static const struct got_error *
recv_one_imsg(struct imsg *imsg, struct imsgbuf *ibuf, size_t min_datalen)
{
	const struct got_error *err;
	ssize_t n;

	err = read_imsg(ibuf);
	if (err)
		return err;

	n = imsg_get(ibuf, imsg);
	if (n == 0)
		return got_error(GOT_ERR_PRIVSEP_READ);

	if (imsg->hdr.len < IMSG_HEADER_SIZE + min_datalen)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	return NULL;
}

static const struct got_error *
recv_imsg_error(struct imsg *imsg, size_t datalen)
{
	struct got_imsg_error ierr;

	if (datalen != sizeof(ierr))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&ierr, imsg->data, sizeof(ierr));
	if (ierr.code == GOT_ERR_ERRNO) {
		static struct got_error serr;
		serr.code = GOT_ERR_ERRNO;
		serr.msg = strerror(ierr.errno_code);
		return &serr;
	}

	return got_error(ierr.code);
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
	if (ret != -1) {
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
got_privsep_send_obj(struct imsgbuf *ibuf, struct got_object *obj, int ndeltas)
{
	struct got_imsg_object iobj;

	iobj.type = obj->type;
	iobj.flags = obj->flags;
	iobj.hdrlen = obj->hdrlen;
	iobj.size = obj->size;
	iobj.ndeltas = ndeltas;

	if (ndeltas > 0) {
		/* TODO: Handle deltas */
	}

	if (imsg_compose(ibuf, GOT_IMSG_OBJECT, 0, 0, -1, &iobj, sizeof(iobj))
	    == -1)
		return got_error_from_errno();

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_recv_obj(struct got_object **obj, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_object iobj;
	size_t datalen;
	int i;
	const size_t min_datalen =
	    MIN(sizeof(struct got_imsg_error), sizeof(struct got_imsg_object));

	*obj = NULL;

	err = recv_one_imsg(&imsg, ibuf, min_datalen);
	if (err)
		return err;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case GOT_IMSG_ERROR:
		err = recv_imsg_error(&imsg, datalen);
		break;
	case GOT_IMSG_OBJECT:
		if (datalen != sizeof(iobj)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}

		memcpy(&iobj, imsg.data, sizeof(iobj));
		if (iobj.ndeltas < 0 ||
		    iobj.ndeltas > GOT_DELTA_CHAIN_RECURSION_MAX) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}

		*obj = calloc(1, sizeof(**obj));
		if (*obj == NULL) {
			err = got_error_from_errno();
			break;
		}

		(*obj)->type = iobj.type;
		(*obj)->hdrlen = iobj.hdrlen;
		(*obj)->size = iobj.size;
		for (i = 0; i < iobj.ndeltas; i++) {
			/* TODO: Handle deltas */
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
got_privsep_send_commit(struct imsgbuf *ibuf, struct got_commit_object *commit)
{
	const struct got_error *err = NULL;
	struct got_imsg_commit_object icommit;
	uint8_t *buf;
	size_t len, total;
	struct got_parent_id *pid;

	memcpy(icommit.tree_id, commit->tree_id->sha1, sizeof(icommit.tree_id));
	icommit.author_len = strlen(commit->author);
	icommit.committer_len = strlen(commit->committer);
	icommit.logmsg_len = strlen(commit->logmsg);
	icommit.nparents = commit->nparents;

	total = sizeof(icommit) + icommit.author_len +
	    icommit.committer_len + icommit.logmsg_len +
	    icommit.nparents * SHA1_DIGEST_LENGTH;
	/* XXX TODO support very large log messages properly */
	if (total > MAX_IMSGSIZE)
		return got_error(GOT_ERR_NO_SPACE);

	buf = malloc(total);
	if (buf == NULL)
		return got_error_from_errno();

	len = 0;
	memcpy(buf + len, &icommit, sizeof(icommit));
	len += sizeof(icommit);
	memcpy(buf + len, commit->author, icommit.author_len);
	len += icommit.author_len;
	memcpy(buf + len, commit->committer, icommit.committer_len);
	len += icommit.committer_len;
	memcpy(buf + len, commit->logmsg, icommit.logmsg_len);
	len += icommit.logmsg_len;
	SIMPLEQ_FOREACH(pid, &commit->parent_ids, entry) {
		memcpy(buf + len, pid->id, SHA1_DIGEST_LENGTH);
		len += SHA1_DIGEST_LENGTH;
	}

	if (imsg_compose(ibuf, GOT_IMSG_COMMIT, 0, 0, -1, buf, len) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	err = flush_imsg(ibuf);
done:
	free(buf);
	return err;
}
const struct got_error *
got_privsep_recv_commit(struct got_commit_object **commit, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_commit_object icommit;
	size_t len, datalen;
	int i;
	const size_t min_datalen =
	    MIN(sizeof(struct got_imsg_error),
	    sizeof(struct got_imsg_commit_object));
	uint8_t *data;

	*commit = NULL;

	err = recv_one_imsg(&imsg, ibuf, min_datalen);
	if (err)
		return err;

	data = imsg.data;
	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	len = 0;

	switch (imsg.hdr.type) {
	case GOT_IMSG_ERROR:
		err = recv_imsg_error(&imsg, datalen);
		break;
	case GOT_IMSG_COMMIT:
		if (datalen < sizeof(icommit)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}

		memcpy(&icommit, data, sizeof(icommit));
		if (datalen != sizeof(icommit) + icommit.author_len +
		    icommit.committer_len + icommit.logmsg_len +
		    icommit.nparents * SHA1_DIGEST_LENGTH) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		if (icommit.nparents < 0) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			break;
		}
		len += sizeof(icommit);

		*commit = got_object_commit_alloc_partial();
		if (*commit == NULL) {
			err = got_error_from_errno();
			break;
		}

		memcpy((*commit)->tree_id->sha1, icommit.tree_id,
		    SHA1_DIGEST_LENGTH);

		if (icommit.author_len == 0) {
			(*commit)->author = strdup("");
			if ((*commit)->author == NULL) {
				err = got_error_from_errno();
				break;
			}
		} else {
			(*commit)->author = malloc(icommit.author_len + 1);
			if ((*commit)->author == NULL) {
				err = got_error_from_errno();
				break;
			}
			memcpy((*commit)->author, data + len,
			    icommit.author_len);
			(*commit)->author[icommit.author_len] = '\0';
		}
		len += icommit.author_len;

		if (icommit.committer_len == 0) {
			(*commit)->committer = strdup("");
			if ((*commit)->committer == NULL) {
				err = got_error_from_errno();
				break;
			}
		} else {
			(*commit)->committer =
			    malloc(icommit.committer_len + 1);
			if ((*commit)->committer == NULL) {
				err = got_error_from_errno();
				break;
			}
			memcpy((*commit)->committer, data + len,
			    icommit.committer_len);
			(*commit)->committer[icommit.committer_len] = '\0';
		}
		len += icommit.committer_len;

		if (icommit.logmsg_len == 0) {
			(*commit)->logmsg = strdup("");
			if ((*commit)->logmsg == NULL) {
				err = got_error_from_errno();
				break;
			}
		} else {
			(*commit)->logmsg = malloc(icommit.logmsg_len + 1);
			if ((*commit)->logmsg == NULL) {
				err = got_error_from_errno();
				break;
			}
			memcpy((*commit)->logmsg, data + len,
			    icommit.logmsg_len);
			(*commit)->logmsg[icommit.logmsg_len] = '\0';
		}
		len += icommit.logmsg_len;

		for (i = 0; i < icommit.nparents; i++) {
			struct got_parent_id *pid;

			pid = calloc(1, sizeof(*pid));
			if (pid == NULL) {
				err = got_error_from_errno();
				break;
			}
			pid->id = calloc(1, sizeof(*pid->id));
			if (pid->id == NULL) {
				err = got_error_from_errno();
				free(pid);
				break;
			}

			memcpy(pid->id, data + len + i * SHA1_DIGEST_LENGTH,
			    sizeof(*pid->id));
			SIMPLEQ_INSERT_TAIL(&(*commit)->parent_ids, pid, entry);
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

	itree.nentries = tree->nentries;
	if (imsg_compose(ibuf, GOT_IMSG_TREE, 0, 0, -1, &itree, sizeof(itree))
	    == -1)
		return got_error_from_errno();

	err = flush_imsg(ibuf);
	if (err)
		return err;

	SIMPLEQ_FOREACH(te, &tree->entries, entry) {
		struct got_imsg_tree_entry ite;
		uint8_t *buf = NULL;
		size_t len = sizeof(ite) + strlen(te->name);

		if (len > MAX_IMSGSIZE)
			return got_error(GOT_ERR_NO_SPACE);

		buf = malloc(len);
		if (buf == NULL)
			return got_error_from_errno();

		memcpy(ite.id, te->id->sha1, sizeof(ite.id));
		ite.mode = te->mode;
		memcpy(buf, &ite, sizeof(ite));
		memcpy(buf + sizeof(ite), te->name, strlen(te->name));

		if (imsg_compose(ibuf, GOT_IMSG_TREE_ENTRY, 0, 0, -1,
		    buf, len) == -1)
			err = got_error_from_errno();
		free(buf);
		if (err)
			return err;

		err = flush_imsg(ibuf);
		if (err)
			return err;
	}

	return NULL;
}

const struct got_error *
got_privsep_recv_tree(struct got_tree_object **tree, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	const size_t min_datalen =
	    MIN(sizeof(struct got_imsg_error),
	    sizeof(struct got_imsg_tree_object));
	struct got_imsg_tree_object itree = { 0 };
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
		struct got_imsg_tree_entry ite;
		struct got_tree_entry *te = NULL;

		n = imsg_get(ibuf, &imsg);
		if (n == 0) {
			if (*tree && (*tree)->nentries != nentries)
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
			if (datalen != sizeof(itree)) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}
			memcpy(&itree, imsg.data, sizeof(itree));
			*tree = calloc(1, sizeof(**tree));
			if (*tree == NULL) {
				err = got_error_from_errno();
				break;
			}
			(*tree)->nentries = itree.nentries;
			SIMPLEQ_INIT(&(*tree)->entries);
			break;
		case GOT_IMSG_TREE_ENTRY:
			/* This message should be preceeded by GOT_IMSG_TREE. */
			if (*tree == NULL) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			if (datalen < sizeof(ite) || datalen > MAX_IMSGSIZE) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}

			/* Remaining data contains the entry's name. */
			datalen -= sizeof(ite);
			memcpy(&ite, imsg.data, sizeof(ite));
			if (datalen == 0 || datalen > MAX_IMSGSIZE) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				break;
			}

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
			memcpy(te->name, imsg.data + sizeof(ite), datalen);
			te->name[datalen] = '\0';

			memcpy(te->id->sha1, ite.id, SHA1_DIGEST_LENGTH);
			te->mode = ite.mode;
			SIMPLEQ_INSERT_TAIL(&(*tree)->entries, te, entry);
			nentries++;
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}
done:
	if (*tree && (*tree)->nentries != nentries) {
		if (err == NULL)
			err = got_error(GOT_ERR_PRIVSEP_LEN);
		got_object_tree_close(*tree);
		*tree = NULL;
	}

	return err;
}

const struct got_error *
got_privsep_send_blob(struct imsgbuf *ibuf)
{
	/* Data has already been written to file descriptor. */
	if (imsg_compose(ibuf, GOT_IMSG_BLOB, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno();

	return flush_imsg(ibuf);
}

const struct got_error *
got_privsep_recv_blob(struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	size_t datalen;

	err = recv_one_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case GOT_IMSG_ERROR:
		err = recv_imsg_error(&imsg, datalen);
		break;
	case GOT_IMSG_BLOB:
		if (datalen != 0)
			err = got_error(GOT_ERR_PRIVSEP_LEN);
		/* Data has been written to file descriptor. */
		break;
	default:
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		break;
	}

	imsg_free(&imsg);

	return err;
}
