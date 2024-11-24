/*
 * Copyright (c) 2024 Mark Jamsek <mark@jamsek.dev>
 * Copyright (c) 2014 Florian Obser <florian@openbsd.org>
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

#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "got_error.h"
#include "got_lib_poll.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#define GOTWEBD_TEST_HARNESS		"gotwebd_test_harness"

/*
 * Socket path should be passed on the command line or set as an envvar.
 * Query string and request method can be passed on the command line;
 * if not provided, use the index summary page and GET request method.
 */
#define GOTWEBD_TEST_QUERYSTRING	"action=summary&path=repo.git"

#define GOTWEBD_TEST_PATH_INFO		"/"GOTWEBD_TEST_HARNESS"/"
#define GOTWEBD_TEST_REMOTE_ADDR	"::1"
#define GOTWEBD_TEST_REMOTE_PORT	"32768"
#define GOTWEBD_TEST_SERVER_ADDR	"::1"
#define GOTWEBD_TEST_SERVER_PORT	"80"
#define GOTWEBD_TEST_SERVER_NAME	"gotwebd"
#define GOTWEBD_TEST_SCRIPT_NAME	GOTWEBD_TEST_HARNESS
#define GOTWEBD_TEST_REQUEST_URI	"/"GOTWEBD_TEST_HARNESS"/"
#define GOTWEBD_TEST_DOCUMENT_URI	"/"GOTWEBD_TEST_HARNESS"/"
#define GOTWEBD_TEST_DOCUMENT_ROOT	"/cgi-bin/"GOTWEBD_TEST_HARNESS
#define GOTWEBD_TEST_REQUEST_METHOD	"GET"
#define GOTWEBD_TEST_SCRIPT_FILENAME	"/cgi-bin/"GOTWEBD_TEST_HARNESS
#define GOTWEBD_TEST_SERVER_PROTOCOL	"HTTP/1.1"
#define GOTWEBD_TEST_SERVER_SOFTWARE	GOTWEBD_TEST_HARNESS
#define GOTWEBD_TEST_GATEWAY_INTERFACE	"CGI/1.1"

#define PARAM(_p)	{ #_p, GOTWEBD_TEST_##_p }

static const char *mock_params[][2] = {
	PARAM(PATH_INFO),
	PARAM(REMOTE_ADDR),
	PARAM(REMOTE_PORT),
	PARAM(SERVER_ADDR),
	PARAM(SERVER_PORT),
	PARAM(SERVER_NAME),
	PARAM(SCRIPT_NAME),
	PARAM(REQUEST_URI),
	PARAM(DOCUMENT_URI),
	PARAM(DOCUMENT_ROOT),
	PARAM(REQUEST_METHOD),
	PARAM(SCRIPT_FILENAME),
	PARAM(SERVER_PROTOCOL),
	PARAM(SERVER_SOFTWARE),
	PARAM(GATEWAY_INTERFACE)
};

#undef PARAM

#define FCGI_CONTENT_SIZE	65535
#define FCGI_PADDING_SIZE	255
#define FCGI_RECORD_SIZE	\
    (sizeof(struct fcgi_record_header) + FCGI_CONTENT_SIZE + FCGI_PADDING_SIZE)

#define FCGI_BEGIN_REQUEST	1
#define FCGI_ABORT_REQUEST	2
#define FCGI_END_REQUEST	3
#define FCGI_PARAMS		4
#define FCGI_STDIN		5
#define FCGI_STDOUT		6
#define FCGI_STDERR		7
#define FCGI_DATA		8
#define FCGI_GET_VALUES		9
#define FCGI_GET_VALUES_RESULT	10
#define FCGI_UNKNOWN_TYPE	11
#define FCGI_MAXTYPE		(FCGI_UNKNOWN_TYPE)

#define FCGI_RESPONDER		1

struct fcgi_record_header {
	uint8_t		version;
	uint8_t		type;
	uint16_t	id;
	uint16_t	content_len;
	uint8_t		padding_len;
	uint8_t		reserved;
}__attribute__((__packed__));

struct fcgi_begin_request_body {
	uint16_t	role;
	uint8_t		flags;
	uint8_t		reserved[5];
}__attribute__((__packed__));

struct server_fcgi_param {
	int		total_len;
	uint8_t		buf[FCGI_RECORD_SIZE];
};

enum fcgistate {
	FCGI_READ_HEADER,
	FCGI_READ_CONTENT,
	FCGI_READ_PADDING
};

struct fcgi_data {
	enum fcgistate		state;
	int			toread;
	int			padding_len;
	int			type;
	int			status;
};

__dead static void
usage(void)
{
	fprintf(stderr, "usage: %s [-m method] [-q query] [-s socket]\n",
	    getprogname());
	exit(1);
}

static const struct got_error *
fcgi_writechunk(int type, uint8_t *dat, size_t datlen)
{
	if (type == FCGI_END_REQUEST)
		datlen = 0;

	if (datlen > 0) {
		if (write(STDOUT_FILENO, dat, datlen) == -1)
			return got_error_from_errno("write");
	} else if (fputs("\r\n", stdout) == EOF)
		return got_error_from_errno("fputs");

	return NULL;
}

static const struct got_error *
fcgi_read(int fd, struct fcgi_data *fcgi)
{
	const struct got_error		*err;
	struct fcgi_record_header	*h;
	char				 buf[FCGI_RECORD_SIZE];
	size_t				 len;

	do {
		if (fcgi->toread > sizeof(buf)) {
			/* cannot happen with gotwebd response */
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "bad fcgi response size");
		}

		err = got_poll_read_full(fd, &len, buf,
		    fcgi->toread, fcgi->toread);
		if (err != NULL) {
			if (err->code != GOT_ERR_EOF)
				return err;
			err = NULL;
			break;
		}

		fcgi->toread -= len;
		if (fcgi->toread != 0)
			return got_error_msg(GOT_ERR_BAD_PACKET,
			    "short fcgi response");

		switch (fcgi->state) {
		case FCGI_READ_HEADER:
			h = (struct fcgi_record_header *)buf;
			fcgi->type = h->type;
			fcgi->state = FCGI_READ_CONTENT;
			fcgi->padding_len = h->padding_len;
			fcgi->toread = ntohs(h->content_len);

			if (fcgi->toread != 0)
				break;

			/* fallthrough if content_len == 0 */
		case FCGI_READ_CONTENT:
			switch (fcgi->type) {
			case FCGI_STDERR:  /* gotwebd doesn't send STDERR */
			case FCGI_STDOUT:
			case FCGI_END_REQUEST:
				err = fcgi_writechunk(fcgi->type, buf, len);
				if (err != NULL)
					return err;
				break;
			}
			if (fcgi->padding_len == 0) {
				fcgi->state = FCGI_READ_HEADER;
				fcgi->toread = sizeof(*h);
			} else {
				fcgi->state = FCGI_READ_PADDING;
				fcgi->toread = fcgi->padding_len;
			}
			break;
		case FCGI_READ_PADDING:
			fcgi->state = FCGI_READ_HEADER;
			fcgi->toread = sizeof(*h);
			break;
		default:
			/* should not happen with gotwebd */
			return got_error_msg(GOT_ERR_RANGE, "bad fcgi state");
		}
	} while (len > 0);

	return NULL;
}

static const struct got_error *
fcgi_add_stdin(int fd)
{
	struct fcgi_record_header h;

	memset(&h, 0, sizeof(h));
	h.version = 1;
	h.type = FCGI_STDIN;
	h.id = htons(1);
	h.padding_len = 0;
	h.content_len = 0;

	return got_poll_write_full(fd, &h, sizeof(h));
}

static const struct got_error *
fcgi_add_param(int fd, struct server_fcgi_param *p,
    const char *key, const char *val)
{
	struct fcgi_record_header	*h;
	int				 len, key_len, val_len;
	uint8_t				*param;

	key_len = strlen(key);
	val_len = strlen(val);
	len = key_len + val_len;
	len += key_len > 127 ? 4 : 1;
	len += val_len > 127 ? 4 : 1;

	if (len > FCGI_CONTENT_SIZE)
		return got_error_msg(GOT_ERR_RANGE, "parameter too large");

	if (p->total_len + len > FCGI_CONTENT_SIZE) {
		const struct got_error *err;

		err = got_poll_write_full(fd, p->buf,
		    sizeof(*h) + p->total_len);
		if (err != NULL)
			return err;
		p->total_len = 0;
	}

	h = (struct fcgi_record_header *)p->buf;
	param = p->buf + sizeof(*h) + p->total_len;

	if (key_len > 127) {
		*param++ = ((key_len >> 24) & 0xff) | 0x80;
		*param++ = ((key_len >> 16) & 0xff);
		*param++ = ((key_len >> 8) & 0xff);
		*param++ = (key_len & 0xff);
	} else
		*param++ = key_len;

	if (val_len > 127) {
		*param++ = ((val_len >> 24) & 0xff) | 0x80;
		*param++ = ((val_len >> 16) & 0xff);
		*param++ = ((val_len >> 8) & 0xff);
		*param++ = (val_len & 0xff);
	} else
		*param++ = val_len;

	memcpy(param, key, key_len);
	param += key_len;
	memcpy(param, val, val_len);

	p->total_len += len;

	h->content_len = htons(p->total_len);
	return NULL;
}

static const struct got_error *
fcgi_send_params(int fd, struct server_fcgi_param *param,
    const char *meth, const char *qs)
{
	const struct got_error		*err;
	struct fcgi_record_header	*h;
	const char			*k, *v;
	int				 i;

	h = (struct fcgi_record_header *)&param->buf;
	h->type = FCGI_PARAMS;
	h->content_len = 0;

	for (i = 0; i < nitems(mock_params); ++i) {
		k = mock_params[i][0];
		v = mock_params[i][1];
		if ((err = fcgi_add_param(fd, param, k, v)) != NULL)
			return err;
	}
	if (qs == NULL)
		qs = GOTWEBD_TEST_QUERYSTRING;
	if ((err = fcgi_add_param(fd, param, "QUERY_STRING", qs)) != NULL)
		return err;
	if (meth == NULL)
		meth = GOTWEBD_TEST_REQUEST_METHOD;
	if ((err = fcgi_add_param(fd, param, "REQUEST_METHOD", meth)) != NULL)
		return err;

	err = got_poll_write_full(fd, param->buf,
	    sizeof(*h) + ntohs(h->content_len));
	if (err != NULL)
		return err;

	/* send "no more params" message */
	h->content_len = 0;
	return got_poll_write_full(fd, param->buf, sizeof(*h));
}

static const struct got_error *
fcgi(const char *sock, const char *meth, const char *qs)
{
	const struct got_error		*err;
	struct server_fcgi_param	 param;
	struct fcgi_record_header	*h;
	struct fcgi_begin_request_body	*begin;
	struct fcgi_data		 fcgi;
	struct sockaddr_un		 sun;
	int				 fd = -1;

	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1)
		return got_error_from_errno("socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;

	if (strlcpy(sun.sun_path, sock, sizeof(sun.sun_path))
	    >= sizeof(sun.sun_path)) {
		err = got_error_fmt(GOT_ERR_NO_SPACE,
		    "socket path too long: %s", sock);
		goto done;
	}

	if ((connect(fd, (struct sockaddr *)&sun, sizeof(sun))) == -1) {
		err = got_error_from_errno_fmt("connect: %s", sock);
		goto done;
	}

	if (pledge("stdio", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}

	memset(&fcgi, 0, sizeof(fcgi));

	fcgi.state = FCGI_READ_HEADER;
	fcgi.toread = sizeof(*h);
	fcgi.status = 200;

	memset(&param, 0, sizeof(param));

	h = (struct fcgi_record_header *)&param.buf;
	h->version = 1;
	h->type = FCGI_BEGIN_REQUEST;
	h->id = htons(1);
	h->content_len = htons(sizeof(*begin));
	h->padding_len = 0;

	begin = (struct fcgi_begin_request_body *)&param.buf[sizeof(*h)];
	begin->role = htons(FCGI_RESPONDER);

	err = got_poll_write_full(fd, param.buf, sizeof(*h) + sizeof(*begin));
	if (err != NULL)
		goto done;

	if ((err = fcgi_send_params(fd, &param, meth, qs)) != NULL)
		goto done;

	if ((err = fcgi_add_stdin(fd)) != NULL)
		goto done;

	err = fcgi_read(fd, &fcgi);

 done:
	if (fd != -1 && close(fd) == EOF && err == NULL)
		err = got_error_from_errno("close");
	return err;
}

int
main(int argc, char *argv[])
{
	const struct got_error	*error;
	const char		*meth = NULL, *qs = NULL, *sock = NULL;
	int			 ch;

	while ((ch = getopt(argc, argv, "m:q:s:")) != -1) {
		switch (ch) {
		case 'm':
			meth = optarg;
			break;
		case 'q':
			qs = optarg;
			break;
		case 's':
			sock = optarg;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	if (sock == NULL) {
		sock = getenv("GOTWEBD_TEST_SOCK");
		if (sock == NULL)
			errx(1, "socket path not provided");
	}

	if (unveil(sock, "rw") != 0)
		err(1, "unveil");
	if (pledge("stdio unix", NULL) == -1)
		err(1, "pledge");

	error = fcgi(sock, meth, qs);
	if (error != NULL)
		errx(1, "%s", error->msg);

	return 0;
}
