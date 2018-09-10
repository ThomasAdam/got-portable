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
#include <sys/time.h>
#include <sys/limits.h>
#include <sys/syslimits.h>

#include <stdint.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <zlib.h>

#include "got_error.h"
#include "got_object.h"

#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_privsep.h"

int
main(int argc, char *argv[])
{
	const struct got_error *err = NULL;
	struct imsgbuf ibuf;
	size_t datalen;

	imsg_init(&ibuf, GOT_IMSG_FD_CHILD);

	/* revoke access to most system calls */
	if (pledge("stdio recvfd", NULL) == -1) {
		err = got_error_from_errno();
		got_privsep_send_error(&ibuf, err);
		return 1;
	}

	while (1) {
		struct imsg imsg, imsg_outfd;
		FILE *f = NULL;
		size_t size;
	
		memset(&imsg, 0, sizeof(imsg));
		imsg.fd = -1;
		memset(&imsg_outfd, 0, sizeof(imsg_outfd));
		imsg_outfd.fd = -1;

		err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
		if (err) {
			if (err->code == GOT_ERR_PRIVSEP_PIPE)
				err = NULL;
			break;
		}

		if (imsg.hdr.type == GOT_IMSG_STOP)
			break;

		if (imsg.hdr.type != GOT_IMSG_BLOB_REQUEST) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			goto done;
		}

		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
		if (datalen != 0) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
		if (imsg.fd == -1) {
			err = got_error(GOT_ERR_PRIVSEP_NO_FD);
			goto done;
		}

		err = got_privsep_recv_imsg(&imsg_outfd, &ibuf, 0);
		if (err) {
			if (imsg.hdr.len == 0)
				err = NULL;
			break;
		}

		if (imsg_outfd.hdr.type == GOT_IMSG_STOP)
			break;

		if (imsg_outfd.hdr.type != GOT_IMSG_BLOB_OUTFD) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			goto done;
		}

		datalen = imsg_outfd.hdr.len - IMSG_HEADER_SIZE;
		if (datalen != 0) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
		if (imsg_outfd.fd == -1) {
			err = got_error(GOT_ERR_PRIVSEP_NO_FD);
			goto done;
		}

		f = fdopen(imsg.fd, "rb");
		if (f == NULL) {
			err = got_error_from_errno();
			goto done;
		}

		err = got_inflate_to_fd(&size, f, imsg_outfd.fd);
		if (err)
			goto done;

		err = got_privsep_send_blob(&ibuf, size);
done:
		if (f)
			fclose(f);
		else if (imsg.fd != -1)
			close(imsg.fd);
		if (imsg_outfd.fd != -1)
			close(imsg_outfd.fd);
		imsg_free(&imsg);
		imsg_free(&imsg_outfd);
		if (err) {
			if (err->code == GOT_ERR_PRIVSEP_PIPE)
				err = NULL;
			else
				got_privsep_send_error(&ibuf, err);
			break;
		}
	}

	imsg_clear(&ibuf);
	if (err)
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
	close(GOT_IMSG_FD_CHILD);
	return err ? 1 : 0;
}
