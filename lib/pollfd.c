/*
 * Copyright (c) 2018, 2022 Stefan Sperling <stsp@openbsd.org>
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

#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

#include "got_error.h"

#include "got_lib_poll.h"

const struct got_error *
got_poll_fd(int fd, int events, int timeout)
{
	struct pollfd pfd[1];
	struct timespec ts;
	sigset_t sigset;
	int n;

	pfd[0].fd = fd;
	pfd[0].events = events;

	ts.tv_sec = timeout;
	ts.tv_nsec = 0;

	if (sigemptyset(&sigset) == -1)
		return got_error_from_errno("sigemptyset");
	if (sigaddset(&sigset, SIGWINCH) == -1)
		return got_error_from_errno("sigaddset");

	n = ppoll(pfd, 1, timeout == INFTIM ? NULL : &ts, &sigset);
	if (n == -1)
		return got_error_from_errno("ppoll");
	if (n == 0) {
		if (pfd[0].revents & POLLHUP)
			return got_error(GOT_ERR_EOF);
		return got_error(GOT_ERR_TIMEOUT);
	}
	if (pfd[0].revents & (POLLERR | POLLNVAL))
		return got_error_from_errno("poll error");
	if (pfd[0].revents & events)
		return NULL;
	if (pfd[0].revents & POLLHUP)
		return got_error(GOT_ERR_EOF);

	return got_error(GOT_ERR_INTERRUPT);
}

const struct got_error *
got_poll_read_full(int fd, size_t *len, void *buf, size_t bufsize,
    size_t minbytes)
{
	const struct got_error *err = NULL;
	size_t have = 0;
	ssize_t r;

	if (minbytes > bufsize)
		return got_error(GOT_ERR_NO_SPACE);

	while (have < minbytes) {
		err = got_poll_fd(fd, POLLIN, INFTIM);
		if (err)
			return err;
		r = read(fd, buf + have, bufsize - have);
		if (r == -1)
			return got_error_from_errno("read");
		if (r == 0)
			return got_error(GOT_ERR_EOF);
		have += r;
	}

	*len = have;
	return NULL;
}

const struct got_error *
got_poll_write_full(int fd, const void *buf, off_t len)
{
	const struct got_error *err = NULL;
	off_t wlen = 0;
	ssize_t w = 0;

	while (wlen != len) {
		if (wlen > 0) {
			err = got_poll_fd(fd, POLLOUT, INFTIM);
			if (err)
				return err;
		}
		w = write(fd, buf + wlen, len - wlen);
		if (w == -1) {
			if (errno != EAGAIN)
				return got_error_from_errno("write");
		} else
			wlen += w;
	}

	return NULL;
}
