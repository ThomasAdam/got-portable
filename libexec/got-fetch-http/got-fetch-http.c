/*
 * Copyright (c) 2022 Omar Polo <op@openbsd.org>
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
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include "got_version.h"

#define UPLOAD_PACK_ADV "application/x-git-upload-pack-advertisement"
#define UPLOAD_PACK_REQ "application/x-git-upload-pack-request"
#define UPLOAD_PACK_RES "application/x-git-upload-pack-result"

#define HTTP_BUFSIZ	4096
#define	GOT_USERAGENT	"got/" GOT_VERSION_STR
#define MINIMUM(a, b)	((a) < (b) ? (a) : (b))
#define hasprfx(str, p)	(strncasecmp(str, p, strlen(p)) == 0)

#define DEBUG_HTTP 1

FILE *tmp;

static int	verbose;

static long long
hexstrtonum(const char *str, long long min, long long max, const char **errstr)
{
	long long	 lval;
	char		*cp;

	errno = 0;
	lval = strtoll(str, &cp, 16);
	if (*str == '\0' || *cp != '\0') {
		*errstr = "not a number";
		return 0;
	}
	if ((errno == ERANGE && (lval == LONG_MAX || lval == LONG_MIN)) ||
	    lval < min || lval > max) {
		*errstr = "out of range";
		return 0;
	}

	*errstr = NULL;
	return lval;
}

static int
stdio_tls_write(void *arg, const char *buf, int len)
{
	struct tls	*ctx = arg;
	ssize_t		 ret;

	do {
		ret = tls_write(ctx, buf, len);
	} while (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT);

	if (ret == -1)
		warn("tls_write: %s", tls_error(ctx));

	return ret;
}

static int
stdio_tls_read(void *arg, char *buf, int len)
{
	struct tls	*ctx = arg;
	ssize_t		 ret;

	do {
		ret = tls_read(ctx, buf, len);
	} while (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT);

	if (ret == -1)
		warn("tls_read: %s", tls_error(ctx));

	return ret;
}

static int
stdio_tls_close(void *arg)
{
	struct tls	*ctx = arg;
	int		 ret;

	do {
		ret = tls_close(ctx);
	} while (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT);

	return ret;
}

static FILE *
dial(int https, const char *host, const char *port)
{
	FILE			*fp;
	struct tls		*ctx;
	struct tls_config	*conf;
	struct addrinfo		 hints, *res, *res0;
	int			 r, error, saved_errno, fd = -1;
	const char		*cause = NULL;

	if (https) {
		if ((conf = tls_config_new()) == NULL)
			errx(1, "failed to create TLS configuration");
		if ((ctx = tls_client()) == NULL)
			errx(1, "failed to create TLS client");
		if (tls_configure(ctx, conf) == -1)
			errx(1, "TLS configuration failure: %s",
			    tls_error(ctx));
		tls_config_free(conf);

		if (tls_connect(ctx, host, port) == -1) {
			warnx("connect to %s:%s: %s", host, port,
			    tls_error(ctx));
			tls_close(ctx);
			return NULL;
		}
		do {
			r = tls_handshake(ctx);
		} while (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT);
		fp = funopen(ctx, stdio_tls_read, stdio_tls_write, NULL,
		    stdio_tls_close);
		if (fp == NULL) {
			warn("funopen");
			tls_free(ctx);
		}
		return fp;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(host, port, &hints, &res0);
	if (error) {
		warnx("%s", gai_strerror(error));
		return NULL;
	}

	for (res = res0; res; res = res->ai_next) {
		fd = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (fd == -1) {
			cause = "socket";
			continue;
		}

		if (connect(fd, res->ai_addr, res->ai_addrlen) == 0)
			break;

		cause = "connect";
		saved_errno = errno;
		close(fd);
		fd = -1;
		errno = saved_errno;
	}
	freeaddrinfo(res0);

	if (fd == -1) {
		warn("%s", cause);
		return NULL;
	}

	if ((fp = fdopen(fd, "r+")) == NULL) {
		warn("fdopen");
		close(fd);
	}
	return fp;
}

static FILE *
http_open(int https, const char *method, const char *host, const char *port,
    const char *path, const char *path_sufx, const char *query,
    const char *ctype)
{
	FILE		*fp;
	const char	*chdr = NULL, *te = "";
	char		*p, *req;
	int		 r;

	if ((fp = dial(https, host, port)) == NULL)
		return NULL;

	if (path_sufx != NULL && *path && path[strlen(path) - 1] == '/')
		path_sufx++; /* skip the slash */

	if (strcmp(method, "POST") == 0)
		te = "\r\nTransfer-Encoding: chunked\r\n";

	if (ctype)
		chdr = "Content-Type: ";

	r = asprintf(&p, "%s/%s%s%s", path, path_sufx,
	    query ? "?" : "", query ? query : "");
	if (r == -1)
		err(1, "asprintf");

	r = asprintf(&req, "%s %s HTTP/1.1\r\n"
	    "Host: %s\r\n"
	    "Connection: close\r\n"
	    "User-agent: %s\r\n"
	    "%s%s%s\r\n",
	    method, p, host, GOT_USERAGENT,
	    chdr ? chdr : "", ctype ? ctype : "", te);
	free(p);
	if (r == -1)
		err(1, "asprintf");

	if (verbose > 0)
		fprintf(stderr, "%s: request: %s", getprogname(), req);

	if (fwrite(req, 1, r, fp) != r) {
		free(req);
		fclose(fp);
		return NULL;
	}
	free(req);

	return fp;
}

static int
http_parse_reply(FILE *fp, int *chunked, const char *expected_ctype)
{
	char		*cp, *line = NULL;
	size_t		 linesize = 0;
	ssize_t		 linelen;

	*chunked = 0;

	if ((linelen = getline(&line, &linesize, fp)) == -1) {
		warn("%s: getline", __func__);
		return -1;
	}

	if (verbose > 0)
		fprintf(stderr, "%s: response: %s", getprogname(), line);

	if ((cp = strchr(line, '\r')) == NULL) {
		warnx("malformed HTTP response");
		goto err;
	}
	*cp = '\0';

	if ((cp = strchr(line, ' ')) == NULL) {
		warnx("malformed HTTP response");
		goto err;
	}
	cp++;

	if (strncmp(cp, "200 ", 4) != 0) {
		warnx("malformed HTTP response");
		goto err;
	}

	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		if (line[linelen-1] == '\n')
			line[--linelen] = '\0';
		if (linelen > 0 && line[linelen-1] == '\r')
			line[--linelen] = '\0';

		if (*line == '\0')
			break;

		if (hasprfx(line, "content-type:")) {
			cp = strchr(line, ':') + 1;
			cp += strspn(cp, " \t");
			cp[strcspn(cp, " \t")] = '\0';
			if (strcmp(cp, expected_ctype) != 0) {
				warnx("server not using the \"smart\" "
				    "HTTP protocol.");
				goto err;
			}
		}

		if (hasprfx(line, "transfer-encoding:")) {
			cp = strchr(line, ':') + 1;
			cp += strspn(cp, " \t");
			cp[strcspn(cp, " \t")] = '\0';
			if (strcmp(cp, "chunked") != 0) {
				warnx("unknown transfer-encoding");
				goto err;
			}
			*chunked = 1;
		}
	}

	free(line);
	return 0;

err:
	free(line);
	return -1;
}

static ssize_t
http_read(FILE *fp, int chunked, size_t *chunksz, void *buf, size_t bufsz)
{
	const char	*errstr;
	char		*cp, *line = NULL;
	size_t		 r, linesize = 0;
	ssize_t		 ret = 0, linelen;

	if (!chunked) {
		r = fread(buf, 1, bufsz, fp);
		if (r == 0 && ferror(fp))
			return -1;
#if DEBUG_HTTP
		fwrite(buf, 1, r, stderr);
#endif
		return r;
	}

	while (bufsz > 0) {
		if (*chunksz == 0) {
		again:
			if ((linelen = getline(&line, &linesize, fp)) == -1) {
				if (ferror(fp)) {
					warn("%s: getline", __func__);
					ret = -1;
				}
				break;
			}

			if ((cp = strchr(line, '\r')) == NULL) {
				warnx("invalid HTTP chunk: missing CR");
				ret = -1;
				break;
			}
			*cp = '\0';

			if (*line == '\0')
				goto again; /* was the CRLF after the chunk */

			*chunksz = hexstrtonum(line, 0, INT_MAX, &errstr);
			if (errstr != NULL) {
				warnx("invalid HTTP chunk: size is %s (%s)",
				    errstr, line);
				ret = -1;
				break;
			}

			if (*chunksz == 0)
				break;
		}

		r = fread(buf, 1, MINIMUM(*chunksz, bufsz), fp);
		if (r == 0) {
			if (ferror(fp))
				ret = -1;
			break;
		}

#if DEBUG_HTTP
		if (tmp)
			fwrite(buf, 1, r, tmp);
		/* fwrite(buf, 1, r, stderr); */
#endif
		ret += r;
		buf += r;
		bufsz -= r;
		*chunksz -= r;
	}

	free(line);
	return ret;
}

static void
http_chunk(FILE *fp, const void *buf, size_t len)
{
	/* fprintf(stderr, "> %.*s", (int)len, (char *)buf); */

	fprintf(fp, "%zx\r\n", len);
	if (fwrite(buf, 1, len, fp) != len ||
	    fwrite("\r\n", 1, 2, fp) != 2)
		err(1, "%s fwrite", __func__);
}

static int
get_refs(int https, const char *host, const char *port, const char *path)
{
	char		 buf[HTTP_BUFSIZ];
	const char	*errstr, *sufx = "/info/refs";
	FILE		*fp;
	size_t		 skip, chunksz = 0;
	ssize_t		 r;
	int		 chunked;

	fp = http_open(https, "GET", host, port, path, sufx,
	    "service=git-upload-pack", NULL);
	if (fp == NULL)
		return -1;

	if (http_parse_reply(fp, &chunked, UPLOAD_PACK_ADV) == -1) {
		fclose(fp);
		return -1;
	}

	/* skip first pack; why git over http is like this? */
	r = http_read(fp, chunked, &chunksz, buf, 4);
	if (r <= 0) {
		fclose(fp);
		return -1;
	}
	buf[4] = '\0';
	skip = hexstrtonum(buf, 0, INT_MAX, &errstr);
	if (errstr != NULL) {
		warnx("pktlen is %s", errstr);
		fclose(fp);
		return -1;
	}

	/* TODO: validate it's # service=git-upload-pack\n */
	while (skip > 0) {
		r = http_read(fp, chunked, &chunksz, buf,
		    MINIMUM(skip, sizeof(buf)));
		if (r <= 0) {
			fclose(fp);
			return -1;
		}

		skip -= r;
	}

	for (;;) {
		r = http_read(fp, chunked, &chunksz, buf, sizeof(buf));
		if (r == -1) {
			fclose(fp);
			return -1;
		}

		if (r == 0)
			break;

		fwrite(buf, 1, r, stdout);
	}

	fflush(stdout);
	fclose(fp);
	return 0;
}

static int
upload_request(int https, const char *host, const char *port, const char *path,
    FILE *in)
{
	const char	*errstr;
	char		 buf[HTTP_BUFSIZ];
	FILE		*fp;
	ssize_t		 r;
	size_t		 chunksz = 0;
	long long	 t;
	int		 chunked;

	fp = http_open(https, "POST", host, port, path, "/git-upload-pack",
	    NULL, UPLOAD_PACK_REQ);
	if (fp == NULL)
		return -1;

	for (;;) {
		r = fread(buf, 1, 4, in);
		if (r != 4)
			goto err;

		buf[4] = '\0';
		t = hexstrtonum(buf, 0, sizeof(buf), &errstr);
		if (errstr != NULL) {
			warnx("pktline len is %s", errstr);
			goto err;
		}

		/* no idea why 0000 is not enough. */
		if (t == 0) {
			const char *x = "00000009done\n";
			http_chunk(fp, x, strlen(x));
			http_chunk(fp, NULL, 0);
			break;
		}

		if (t < 6) {
			warnx("pktline len is too small");
			goto err;
		}

		r = fread(buf + 4, 1, t - 4, in);
		if (r != t - 4)
			goto err;

		http_chunk(fp, buf, t);
	}

	if (http_parse_reply(fp, &chunked, UPLOAD_PACK_RES) == -1)
		goto err;

	for (;;) {
		r = http_read(fp, chunked, &chunksz, buf, sizeof(buf));
		if (r == -1) {
			fclose(fp);
			return -1;
		}

		if (r == 0)
			break;

		fwrite(buf, 1, r, stdout);
	}

	fclose(fp);
	return 0;

err:
	fclose(fp);
	return -1;
}

static __dead void
usage(void)
{
	fprintf(stderr, "usage: %s [-qv] proto host port path\n",
	     getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{
	struct pollfd	 pfd;
	const char	*host, *port, *path;
	int		 https = 0;
	int		 ch;
#if 0
	static int attached;
	while (!attached)
		sleep(1);
#endif

#if !DEBUG_HTTP || defined(PROFILE)
	if (pledge("stdio inet dns", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "qv")) != -1) {
		switch (ch) {
		case 'q':
			verbose = -1;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 4)
		usage();

	https = strcmp(argv[0], "https") == 0;

	host = argv[1];
	port = argv[2];
	path = argv[3];

	if (get_refs(https, host, port, path) == -1)
		errx(1, "failed to get refs");

#if DEBUG_HTTP
	tmp = fopen("/tmp/pck", "w");
#endif

	pfd.fd = 0;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, INFTIM) == -1)
		err(1, "poll");

	if ((ch = fgetc(stdin)) == EOF)
		return 0;

	ungetc(ch, stdin);
	if (upload_request(https, host, port, path, stdin) == -1) {
		fflush(tmp);
		errx(1, "failed to upload request");
	}

	return 0;
}
