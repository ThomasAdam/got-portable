/*	$OpenBSD: buf.c,v 1.27 2016/10/16 13:35:51 okan Exp $	*/
/*
 * Copyright (c) 2003 Jean-Francois Brousseau <jfb@openbsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL  DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "buf.h"

#include "got_error.h"

#define BUF_INCR	128

#define SIZE_LEFT(b)	((b)->cb_size - (b)->cb_len)

static const struct got_error *buf_grow(BUF *, size_t);

/*
 * Create a new buffer structure and return a pointer to it.  This structure
 * uses dynamically-allocated memory and must be freed with buf_free(), once
 * the buffer is no longer needed.
 */
const struct got_error *
buf_alloc(BUF **b, size_t len)
{
	const struct got_error *err = NULL;

	*b = malloc(sizeof(**b));
	if (*b == NULL)
		return got_error_from_errno("malloc");
	/* Postpone creation of zero-sized buffers */
	if (len > 0) {
		(*b)->cb_buf = calloc(1, len);
		if ((*b)->cb_buf == NULL) {
			err = got_error_from_errno("calloc");
			free(*b);
			*b = NULL;
			return err;
		}
	} else
		(*b)->cb_buf = NULL;

	(*b)->cb_size = len;
	(*b)->cb_len = 0;

	return NULL;
}

/*
 * Open the file specified by <path> and load all of its contents into a
 * buffer.
 * Returns the loaded buffer on success or NULL on failure.
 * Sets errno on error.
 */
const struct got_error *
buf_load(BUF **buf, FILE *f)
{
	const struct got_error *err = NULL;
	size_t ret;
	size_t len;
	u_char *bp;
	struct stat st;

	*buf = NULL;

	if (fstat(fileno(f), &st) == -1) {
		err = got_error_from_errno("fstat");
		goto out;
	}

	if ((uintmax_t)st.st_size > SIZE_MAX) {
		err = got_error_set_errno(EFBIG,
		    "cannot fit file into memory buffer");
		goto out;
	}
	err = buf_alloc(buf, st.st_size);
	if (err)
		goto out;
	for (bp = (*buf)->cb_buf; ; bp += ret) {
		len = SIZE_LEFT(*buf);
		ret = fread(bp, 1, len, f);
		if (ret == 0 && ferror(f)) {
			err = got_ferror(f, GOT_ERR_IO);
			goto out;
		} else if (ret == 0)
			break;

		(*buf)->cb_len += (size_t)ret;
	}

out:
	if (err) {
		buf_free(*buf);
		*buf = NULL;
	}
	return err;
}

void
buf_free(BUF *b)
{
	if (b == NULL)
		return;
	free(b->cb_buf);
	free(b);
}

/*
 * Free the buffer <b>'s structural information but do not free the contents
 * of the buffer.  Instead, they are returned and should be freed later using
 * free().
 */
void *
buf_release(BUF *b)
{
	void *tmp;

	tmp = b->cb_buf;
	free(b);
	return (tmp);
}

u_char *
buf_get(BUF *b)
{
	return (b->cb_buf);
}

/*
 * Empty the contents of the buffer <b> and reset pointers.
 */
void
buf_empty(BUF *b)
{
	memset(b->cb_buf, 0, b->cb_size);
	b->cb_len = 0;
}

/*
 * Append a single character <c> to the end of the buffer <b>.
 */
const struct got_error *
buf_putc(BUF *b, int c)
{
	const struct got_error *err = NULL;
	u_char *bp;

	if (SIZE_LEFT(b) == 0) {
		err = buf_grow(b, BUF_INCR);
		if (err)
			return err;
	}
	bp = b->cb_buf + b->cb_len;
	*bp = (u_char)c;
	b->cb_len++;
	return NULL;
}

/*
 * Append a string <s> to the end of buffer <b>.
 */
const struct got_error *
buf_puts(size_t *newlen, BUF *b, const char *str)
{
	return buf_append(newlen, b, str, strlen(str));
}

/*
 * Return u_char at buffer position <pos>.
 */
u_char
buf_getc(BUF *b, size_t pos)
{
	return (b->cb_buf[pos]);
}

/*
 * Append <len> bytes of data pointed to by <data> to the buffer <b>.  If the
 * buffer is too small to accept all data, it will get resized to an
 * appropriate size to accept all data.
 * Returns the number of bytes successfully appended to the buffer.
 */
const struct got_error *
buf_append(size_t *newlen, BUF *b, const void *data, size_t len)
{
	const struct got_error *err = NULL;
	size_t left, rlen;
	u_char *bp;

	left = SIZE_LEFT(b);
	rlen = len;

	if (left < len) {
		err = buf_grow(b, len - left);
		if (err)
			return err;
	}
	bp = b->cb_buf + b->cb_len;
	memcpy(bp, data, rlen);
	b->cb_len += rlen;

	*newlen = rlen;
	return NULL;
}

/*
 * Returns the size of the buffer that is being used.
 */
size_t
buf_len(BUF *b)
{
	return (b->cb_len);
}

/*
 * Write the contents of the buffer <b> to the specified <fd>
 */
int
buf_write_fd(BUF *b, int fd)
{
	u_char *bp;
	size_t len;
	ssize_t ret;

	len = b->cb_len;
	bp = b->cb_buf;

	do {
		ret = write(fd, bp, len);
		if (ret == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return (-1);
		}

		len -= (size_t)ret;
		bp += (size_t)ret;
	} while (len > 0);

	return (0);
}

/*
 * Write the contents of the buffer <b> to the file whose path is given in
 * <path>.  If the file does not exist, it is created with mode <mode>.
 */
const struct got_error *
buf_write(BUF *b, const char *path, mode_t mode)
{
	const struct got_error *err = NULL;
	int fd;
 open:
	if ((fd = open(path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, mode)) == -1) {
		err = got_error_from_errno2("open", path);
		if (errno == EACCES && unlink(path) != -1)
			goto open;
		else
			return err;
	}

	if (buf_write_fd(b, fd) == -1) {
		err = got_error_from_errno("buf_write_fd");
		(void)unlink(path);
		return err;
	}

	if (fchmod(fd, mode) < 0)
		err = got_error_from_errno2("fchmod", path);

	if (close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", path);

	return err;
}

/*
 * Write the contents of the buffer <b> to a temporary file whose path is
 * specified using <template> (see mkstemp.3).
 * NB. This function will modify <template>, as per mkstemp
 */
const struct got_error *
buf_write_stmp(BUF *b, char *template)
{
	const struct got_error *err = NULL;
	int fd;

	if ((fd = mkstemp(template)) == -1)
		return got_error_from_errno("mkstemp");

	if (buf_write_fd(b, fd) == -1) {
		err = got_error_from_errno("buf_write_fd");
		(void)unlink(template);
	}

	if (close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");

	return err;
}

/*
 * Grow the buffer <b> by <len> bytes.  The contents are unchanged by this
 * operation regardless of the result.
 */
static const struct got_error *
buf_grow(BUF *b, size_t len)
{
	u_char *buf;
	buf = reallocarray(b->cb_buf, 1, b->cb_size + len);
	if (buf == NULL)
		return got_error_from_errno("reallocarray");
	b->cb_buf = buf;
	b->cb_size += len;
	return NULL;
}
