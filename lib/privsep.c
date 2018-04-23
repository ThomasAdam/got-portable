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
recv_one_imsg(struct imsg *imsg, struct imsgbuf *ibuf, size_t min_datalen)
{
	const struct got_error *err;
	ssize_t n, m;

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

	m = imsg_get(ibuf, imsg);
	if (m == 0)
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
	}

	poll_err = poll_fd(ibuf->fd, POLLOUT, INFTIM);
	if (poll_err)
		fprintf(stderr, "%s: error %d \"%s\": poll: %s\n",
		    getprogname(), err->code, err->msg, poll_err->msg);

	ret = imsg_flush(ibuf);
	if (ret == -1)
		fprintf(stderr, "%s: error %d \"%s\": imsg_flush: %s\n",
		    getprogname(), err->code, err->msg, strerror(errno));
}

const struct got_error *
got_privsep_send_obj(struct imsgbuf *ibuf, struct got_object *obj, int ndeltas)
{
	const struct got_error *err = NULL;
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

	err = poll_fd(ibuf->fd, POLLOUT, INFTIM);
	if (err)
		return err;

	if (imsg_flush(ibuf) == -1)
		return got_error_from_errno();

	return NULL;
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
