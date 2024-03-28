/*
 * Copyright (c) 2024 Omar Polo <op@openbsd.org>
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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "got_opentemp.h"
#include "got_version.h"

#include "bufio.h"
#include "utf8d.h"

#define USERAGENT	 "got-notify-http/" GOT_VERSION_STR

static int		 http_timeout = 300;	/* 5 minutes in seconds */

__dead static void
usage(void)
{
	fprintf(stderr, "usage: %s [-c] -h host -p port path\n",
	    getprogname());
	exit(1);
}

static int
dial(const char *host, const char *port)
{
	struct addrinfo	 hints, *res, *res0;
	const char	*cause = NULL;
	int		 s, error, save_errno;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(host, port, &hints, &res0);
	if (error)
		errx(1, "failed to resolve %s:%s: %s", host, port,
		    gai_strerror(error));

	s = -1;
	for (res = res0; res; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (s == -1) {
			cause = "socket";
			continue;
		}

		if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "connect";
			save_errno = errno;
			close(s);
			errno = save_errno;
			s = -1;
			continue;
		}

		break;
	}

	freeaddrinfo(res0);
	if (s == -1)
		err(1, "%s", cause);
	return s;
}

static void
escape(FILE *fp, const uint8_t *s)
{
	uint32_t codepoint, state;
	const uint8_t *start = s;

	state = 0;
	for (; *s; ++s) {
		switch (decode(&state, &codepoint, *s)) {
		case UTF8_ACCEPT:
			switch (codepoint) {
			case '"':
			case '\\':
				fprintf(fp, "\\%c", *s);
				break;
			case '\b':
				fprintf(fp, "\\b");
				break;
			case '\f':
				fprintf(fp, "\\f");
				break;
			case '\n':
				fprintf(fp, "\\n");
				break;
			case '\r':
				fprintf(fp, "\\r");
				break;
			case '\t':
				fprintf(fp, "\\t");
				break;
			default:
				/* other control characters */
				if (codepoint < ' ' || codepoint == 0x7F) {
					fprintf(fp, "\\u%04x", codepoint);
					break;
				}
				fwrite(start, 1, s - start + 1, fp);
				break;
			}
			start = s + 1;
			break;

		case UTF8_REJECT:
			/* bad UTF-8 sequence; try to recover */
			fputs("\\uFFFD", fp);
			state = UTF8_ACCEPT;
			start = s + 1;
			break;
		}
        }
}

static void
json_field(FILE *fp, const char *key, const char *val, int comma)
{
	fprintf(fp, "\"%s\":\"", key);
	escape(fp, val);
	fprintf(fp, "\"%s", comma ? "," : "");
}

static int
jsonify_short(FILE *fp)
{
	char	*t, *date, *id, *author, *message;
	char	*line = NULL;
	size_t	 linesize = 0;
	ssize_t	 linelen;
	int	 needcomma = 0;

	fprintf(fp, "{\"notifications\":[");
	while ((linelen = getline(&line, &linesize, stdin)) != -1) {
		if (line[linelen - 1] == '\n')
			line[--linelen] = '\0';

		if (needcomma)
			fputc(',', fp);
		needcomma = 1;

		t = line;
		date = t;
		if ((t = strchr(t, ' ')) == NULL)
       			errx(1, "malformed line");
		*t++ = '\0';

		id = t;
		if ((t = strchr(t, ' ')) == NULL)
       			errx(1, "malformed line");
		*t++ = '\0';

		author = t;
		if ((t = strchr(t, ' ')) == NULL)
       			errx(1, "malformed line");
		*t++ = '\0';

		message = t;

		fprintf(fp, "{\"short\":true,");
		json_field(fp, "id", id, 1);
		json_field(fp, "author", author, 1);
		json_field(fp, "date", date, 1);
		json_field(fp, "message", message, 0);
		fprintf(fp, "}");
	}

	if (ferror(stdin))
		err(1, "getline");
	free(line);

	fprintf(fp, "]}");

	return 0;
}

static int
jsonify(FILE *fp)
{
	const char	*errstr;
	char		*l;
	char		*line = NULL;
	size_t		 linesize = 0;
	ssize_t		 linelen;
	int		 parent = 0;
	int		 msglen = 0, msgwrote = 0;
	int		 needcomma = 0;
	enum {
		P_COMMIT,
		P_FROM,
		P_VIA,
		P_DATE,
		P_PARENT,
		P_MSGLEN,
		P_MSG,
		P_DST,
		P_SUM,
	} phase = P_COMMIT;

	fprintf(fp, "{\"notifications\":[");
	while ((linelen = getline(&line, &linesize, stdin)) != -1) {
		if (line[linelen - 1] == '\n')
			line[--linelen] = '\0';

		l = line;
		switch (phase) {
		case P_COMMIT:
			if (*line == '\0')
				continue;

			if (strncmp(l, "commit ", 7) != 0)
				errx(1, "unexpected commit line: %s", line);
			l += 7;

			if (needcomma)
				fputc(',', fp);
			needcomma = 1;

			fprintf(fp, "{\"short\":false,");
			json_field(fp, "id", l, 1);

			phase = P_FROM;
			break;

		case P_FROM:
			if (strncmp(l, "from: ", 6) != 0)
				errx(1, "unexpected from line");
			l += 6;
			json_field(fp, "author", l, 1);
			phase = P_VIA;
			break;

		case P_VIA:
			/* optional */
			if (!strncmp(l, "via: ", 5)) {
				l += 5;
				json_field(fp, "via", l, 1);
				phase = P_DATE;
				break;
			}
			phase = P_DATE;
			/* fallthrough */

		case P_DATE:
			/* optional */
			if (!strncmp(l, "date: ", 6)) {
				l += 6;
				json_field(fp, "date", l, 1);
				phase = P_PARENT;
				break;
			}
			phase = P_PARENT;
			/* fallthough */

		case P_PARENT:
			/* optional - more than one */
			if (!strncmp(l, "parent ", 7)) {
				l += 7;
				l += strcspn(l, ":");
				l += strspn(l, " ");

				if (parent == 0) {
					parent = 1;
					fprintf(fp, "\"parents\":[");
				}

				fputc('"', fp);
				escape(fp, l);
				fputc('"', fp);

				break;
			}
			if (parent != 0) {
				fprintf(fp, "],");
				parent = 0;
			}
			phase = P_MSGLEN;
			/* fallthrough */

		case P_MSGLEN:
			if (strncmp(l, "messagelen: ", 12) != 0)
				errx(1, "unexpected messagelen line");
			l += 12;
			msglen = strtonum(l, 1, INT_MAX, &errstr);
			if (errstr)
				errx(1, "message len is %s: %s", errstr, l);

			fprintf(fp, "\"message\":\"");
			phase = P_MSG;
			break;

		case P_MSG:
			/*
			 * The commit message is indented with one extra
			 * space which is not accounted for in messagelen,
			 * but we also strip the trailing \n so that
			 * accounts for it.
			 *
			 * Since we read line-by-line and there is always
			 * a \n added at the end of the message,
			 * tolerate one byte less than advertised.
			 */
			if (*l == ' ') {
				escape(fp, l + 1); /* skip leading space */

				/* avoid pre-pending \n to the commit msg */
				msgwrote += linelen - 1;
				if (msgwrote != 0)
					escape(fp, "\n");
			}
			msglen -= linelen;
			if (msglen <= 1) {
				fprintf(fp, "\",");
				msgwrote = 0;
				phase = P_DST;
			}
			break;

		case P_DST:
			/* XXX: ignore the diffstat for now */
			if (*line == '\0') {
				fprintf(fp, "\"diffstat\":{},");
				phase = P_SUM;
				break;
			}
			break;

		case P_SUM:
			/* XXX: ignore the sum of changes for now */
			fprintf(fp, "\"changes\":{}}");
			/* restart the state machine */
			phase = P_COMMIT;
			break;

		default:
			errx(1, "unimplemented");
		}
	}
	if (ferror(stdin))
		err(1, "getline");
	if (phase != P_COMMIT)
		errx(1, "unexpected EOF");
	free(line);

	fprintf(fp, "]}");

	return 0;
}

static char *
basic_auth(const char *username, const char *password)
{
	char	*tmp;
	int	 len;

	len = asprintf(&tmp, "%s:%s", username, password);
	if (len == -1)
		err(1, "asprintf");

	/* XXX base64-ify */
	return tmp;
}

static inline int
bufio2poll(struct bufio *bio)
{
	int f, ret = 0;

	f = bufio_ev(bio);
	if (f & BUFIO_WANT_READ)
		ret |= POLLIN;
	if (f & BUFIO_WANT_WRITE)
		ret |= POLLOUT;
	return ret;
}

int
main(int argc, char **argv)
{
	FILE		*tmpfp;
	struct bufio	 bio;
	struct pollfd	 pfd;
	struct timespec	 timeout;
	const char	*username;
	const char	*password;
	const char	*timeoutstr;
	const char	*errstr;
	const char	*host = NULL, *port = NULL, *path = NULL;
	char		*auth, *line, *spc;
	size_t		 len;
	ssize_t		 r;
	off_t		 paylen;
	int		 tls = 0;
	int		 response_code = 0, done = 0;
	int		 ch, flags, ret, nonstd = 0;

#ifndef PROFILE
	if (pledge("stdio rpath tmppath dns inet", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "ch:p:")) != -1) {
		switch (ch) {
		case 'c':
			tls = 1;
			break;
		case 'h':
			host = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (host == NULL || argc != 1)
		usage();
	if (tls && port == NULL)
		port = "443";
	path = argv[0];

	username = getenv("GOT_NOTIFY_HTTP_USER");
	password = getenv("GOT_NOTIFY_HTTP_PASS");
	if ((username != NULL && password == NULL) ||
	    (username == NULL && password != NULL))
		errx(1, "username or password are not specified");
	if (username && *password == '\0')
		errx(1, "password can't be empty");

	/* used by the regression test suite */
	timeoutstr = getenv("GOT_NOTIFY_TIMEOUT");
	if (timeoutstr) {
		http_timeout = strtonum(timeoutstr, 0, 600, &errstr);
		if (errstr != NULL)
			errx(1, "timeout in seconds is %s: %s",
			    errstr, timeoutstr);
	}

	memset(&timeout, 0, sizeof(timeout));
	timeout.tv_sec = http_timeout;

	tmpfp = got_opentemp();
	if (tmpfp == NULL)
		err(1, "opentemp");

	/* detect the format of the input */
	ch = fgetc(stdin);
	if (ch == EOF)
		errx(1, "unexpected EOF");
	ungetc(ch, stdin);
	if (ch == 'c') {
		/* starts with "commit" so it's the long format */
		jsonify(tmpfp);
	} else {
		/* starts with the date so it's the short format */
		jsonify_short(tmpfp);
	}

	paylen = ftello(tmpfp);
	if (paylen == -1)
		err(1, "ftello");
	if (fseeko(tmpfp, 0, SEEK_SET) == -1)
		err(1, "fseeko");

#ifndef PROFILE
	/* drop tmppath */
	if (pledge("stdio rpath dns inet", NULL) == -1)
		err(1, "pledge");
#endif

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = dial(host, port);

	if ((flags = fcntl(pfd.fd, F_GETFL)) == -1)
		err(1, "fcntl(F_GETFL)");
	if (fcntl(pfd.fd, F_SETFL, flags | O_NONBLOCK) == -1)
		err(1, "fcntl(F_SETFL)");

	if (bufio_init(&bio) == -1)
		err(1, "bufio_init");
	bufio_set_fd(&bio, pfd.fd);
	if (tls && bufio_starttls(&bio, host, 0, NULL, 0, NULL, 0) == -1)
		err(1, "bufio_starttls");

#ifndef PROFILE
	/* drop rpath dns inet */
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");
#endif

	if ((!tls && strcmp(port, "80") != 0) ||
	    (tls && strcmp(port, "443")) != 0)
		nonstd = 1;

	ret = bufio_compose_fmt(&bio,
	    "POST %s HTTP/1.1\r\n"
	    "Host: %s%s%s\r\n"
	    "Content-Type: application/json\r\n"
	    "Content-Length: %lld\r\n"
	    "User-Agent: %s\r\n"
	    "Connection: close\r\n",
	    path, host,
	    nonstd ? ":" : "", nonstd ? port : "",
	    (long long)paylen, USERAGENT);
	if (ret == -1)
		err(1, "bufio_compose_fmt");

	if (username) {
		auth = basic_auth(username, password);
		ret = bufio_compose_fmt(&bio, "Authorization: basic %s\r\n",
		    auth);
		if (ret == -1)
			err(1, "bufio_compose_fmt");
		free(auth);
	}

	if (bufio_compose(&bio, "\r\n", 2) == -1)
		err(1, "bufio_compose");

	while (!done) {
		struct timespec	 elapsed, start, stop;
		char		 buf[BUFSIZ];

		pfd.events = bufio2poll(&bio);
		clock_gettime(CLOCK_MONOTONIC, &start);
		ret = ppoll(&pfd, 1, &timeout, NULL);
		if (ret == -1)
			err(1, "poll");
		clock_gettime(CLOCK_MONOTONIC, &stop);
		timespecsub(&stop, &start, &elapsed);
		timespecsub(&timeout, &elapsed, &timeout);
		if (ret == 0 || timeout.tv_sec <= 0)
			errx(1, "timeout");

		if (bio.wbuf.len > 0 && (pfd.revents & POLLOUT)) {
			if (bufio_write(&bio) == -1 && errno != EAGAIN)
				errx(1, "bufio_write: %s", bufio_io_err(&bio));
		}
		if (pfd.revents & POLLIN) {
			r = bufio_read(&bio);
			if (r == -1 && errno != EAGAIN)
				errx(1, "bufio_read: %s", bufio_io_err(&bio));
			if (r == 0)
				errx(1, "unexpected EOF");

			for (;;) {
				line = buf_getdelim(&bio.rbuf, "\r\n", &len);
				if (line == NULL)
					break;
				if (response_code && *line == '\0') {
					/*
					 * end of headers, don't bother
					 * reading the body, if there is.
					 */
					done = 1;
					break;
				}
				if (response_code) {
					buf_drain(&bio.rbuf, len);
					continue;
				}
				spc = strchr(line, ' ');
				if (spc == NULL)
					errx(1, "bad reply");
				*spc++ = '\0';
				if (strcasecmp(line, "HTTP/1.1") != 0)
					errx(1, "unexpected protocol: %s",
					    line);
				line = spc;

				spc = strchr(line, ' ');
				if (spc == NULL)
					errx(1, "bad reply");
				*spc++ = '\0';

				response_code = strtonum(line, 100, 599,
				    &errstr);
				if (errstr != NULL)
					errx(1, "response code is %s: %s",
					    errstr, line);

				buf_drain(&bio.rbuf, len);
			}
			if (done)
				break;
		}

		if (!feof(tmpfp) && bio.wbuf.len < sizeof(buf)) {
			len = fread(buf, 1, sizeof(buf), tmpfp);
			if (len == 0) {
				if (ferror(tmpfp))
					err(1, "fread");
				continue;
			}

			if (bufio_compose(&bio, buf, len) == -1)
				err(1, "buf_compose");
		}
	}

	if (response_code >= 200 && response_code < 300)
		return 0;
	errx(1, "request failed with code %d", response_code);
}