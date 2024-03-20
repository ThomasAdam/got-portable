/*
 * Copyright (c) 2024 Stefan Sperling <stsp@openbsd.org>
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

#include "got_compat.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <err.h>
#include <pwd.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>

#include "got_error.h"

#include "got_lib_poll.h"

int smtp_timeout = 60; /* in seconds */

__dead static void
usage(void)
{
	fprintf(stderr, "usage: %s [-f sender] [-r responder] "
	    "[-s subject] [-h hostname] [-p port] recipient\n", getprogname());
	exit(1);
}

static char *
set_default_fromaddr(void)
{
	struct passwd *pw = NULL;
	char *s;
	char hostname[255];

	pw = getpwuid(getuid());
	if (pw == NULL) {
		errx(1, "my UID %d was not found in password database",
		    getuid());
	}
	
	if (gethostname(hostname, sizeof(hostname)) == -1)
		err(1, "gethostname");

	if (asprintf(&s, "%s@%s", pw->pw_name, hostname) == -1)
		err(1, "asprintf");

	return s;
}

static int
read_smtp_code(int s, const char *code)
{
	const struct got_error *error;
	char buf[4];
	size_t n;

	error = got_poll_read_full_timeout(s, &n, buf, 3, 3, smtp_timeout);
	if (error)
		errx(1, "read: %s", error->msg);
	if (strncmp(buf, code, 3) != 0) {
		buf[3] = '\0';
		warnx("unexpected SMTP message code: %s", buf);
		return -1;
	}

	return 0;
}

static int
skip_to_crlf(int s)
{
	const struct got_error *error;
	char buf[1];
	size_t len;

	for (;;) {
		error = got_poll_read_full_timeout(s, &len, buf, 1, 1,
		    smtp_timeout);
		if (error)
			errx(1, "read: %s", error->msg);
		if (buf[0] == '\r') {
			error = got_poll_read_full(s, &len, buf, 1, 1);
			if (error)
				errx(1, "read: %s", error->msg);
			if (buf[0] == '\n')
				return 0;
		}
	}

	return -1;
}

static int
send_smtp_msg(int s, const char *fmt, ...)
{
	const struct got_error *error;
	char buf[512];
	int len;
	va_list ap;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (len < 0) {
		warn("vsnprintf");
		return -1;
	}
	if (len >= sizeof(buf)) {
		warnx("%s: buffer too small for message '%s...'",
		    __func__, buf);
		return -1;
	}

	error = got_poll_write_full(s, buf, len);
	if (error) {
		warnx("write: %s", error->msg);
		return -1;
	}

	return 0;
}

static char *
get_datestr(time_t *time, char *datebuf)
{
	struct tm mytm, *tm;
	char *p, *s;

	tm = gmtime_r(time, &mytm);
	if (tm == NULL)
		return NULL;
	s = asctime_r(tm, datebuf);
	if (s == NULL)
		return NULL;
	p = strchr(s, '\n');
	if (p)
		*p = '\0';
	return s;
}

static void
send_email(const char *myfromaddr, const char *fromaddr,
    const char *recipient, const char *replytoaddr,
    const char *subject, const char *hostname, const char *port)
{
	const struct got_error *error;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	struct addrinfo hints, *res = NULL;
	int s = -1, ret;
	time_t now;
	char datebuf[26];
	char *datestr;

	now = time(NULL);
	datestr = get_datestr(&now, datebuf);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(hostname, port, &hints, &res);
	if (ret)
		errx(1, "getaddrinfo: %s", gai_strerror(ret));

	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s == -1)
		err(1, "socket");

	if (connect(s, res->ai_addr, res->ai_addrlen) == -1)
		err(1, "connect %s:%s", hostname, port);

	if (read_smtp_code(s, "220"))
		errx(1, "unexpected SMTP greeting received");
	if (skip_to_crlf(s))
		errx(1, "invalid SMTP message received");

	if (send_smtp_msg(s, "HELO localhost\r\n"))
		errx(1, "could not send HELO");
	if (read_smtp_code(s, "250"))
		errx(1, "unexpected SMTP response received");
	if (skip_to_crlf(s))
		errx(1, "invalid SMTP message received");

	if (send_smtp_msg(s, "MAIL FROM:<%s>\r\n", myfromaddr))
		errx(1, "could not send MAIL FROM");
	if (read_smtp_code(s, "250"))
		errx(1, "unexpected SMTP response received");
	if (skip_to_crlf(s))
		errx(1, "invalid SMTP message received");

	if (send_smtp_msg(s, "RCPT TO:<%s>\r\n", recipient))
		errx(1, "could not send MAIL FROM");
	if (read_smtp_code(s, "250"))
		errx(1, "unexpected SMTP response received");
	if (skip_to_crlf(s))
		errx(1, "invalid SMTP message received");

	if (send_smtp_msg(s, "DATA\r\n"))
		errx(1, "could not send MAIL FROM");
	if (read_smtp_code(s, "354"))
		errx(1, "unexpected SMTP response received");
	if (skip_to_crlf(s))
		errx(1, "invalid SMTP message received");

	if (send_smtp_msg(s, "From: %s\r\n", fromaddr))
		errx(1, "could not send From header");
	if (send_smtp_msg(s, "To: %s\r\n", recipient))
		errx(1, "could not send To header");
	if (replytoaddr) {
		if (send_smtp_msg(s, "Reply-To: %s\r\n", replytoaddr))
			errx(1, "could not send Reply-To header");
	}
	if (send_smtp_msg(s, "Date: %s +0000 (UTC)\r\n", datestr))
		errx(1, "could not send Date header");

	if (send_smtp_msg(s, "Subject: %s\r\n", subject))
		errx(1, "could not send Subject header");

	if (send_smtp_msg(s, "\r\n"))
		errx(1, "could not send body delimiter");

	while ((linelen = getline(&line, &linesize, stdin)) != -1) {
		if (line[0] == '.') { /* dot stuffing */
			error = got_poll_write_full(s, ".", 1);
			if (error)
				errx(1, "write: %s", error->msg);
		}
		error = got_poll_write_full(s, line, linelen);
		if (error)
			errx(1, "write: %s", error->msg);
	}

	if (send_smtp_msg(s, "\r\n.\r\n"))
		errx(1, "could not send data terminator");
	if (read_smtp_code(s, "250"))
		errx(1, "unexpected SMTP response received");
	if (skip_to_crlf(s))
		errx(1, "invalid SMTP message received");

	if (send_smtp_msg(s, "QUIT\r\n"))
		errx(1, "could not send QUIT");

	if (read_smtp_code(s, "221"))
		errx(1, "unexpected SMTP response received");
	if (skip_to_crlf(s))
		errx(1, "invalid SMTP message received");

	close(s);
	free(line);
	if (res)
		freeaddrinfo(res);
}

int
main(int argc, char *argv[])
{
	char *default_fromaddr = NULL;
	const char *fromaddr = NULL, *recipient = NULL, *replytoaddr = NULL;
	const char *subject = "gotd notification";
	const char *hostname = "127.0.0.1";
	const char *port = "25";
	const char *errstr;
	char *timeoutstr;
	int ch;

	while ((ch = getopt(argc, argv, "f:r:s:h:p:")) != -1) {
		switch (ch) {
		case 'h':
			hostname = optarg;
			break;
		case 'f':
			fromaddr = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		case 'r':
			replytoaddr = optarg;
			break;
		case 's':
			subject = optarg;
			break;
		default:
			usage();
			/* NOTREACHED */
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	/* used by the regression test suite */
	timeoutstr = getenv("GOT_NOTIFY_EMAIL_TIMEOUT");
	if (timeoutstr) {
		smtp_timeout = strtonum(timeoutstr, 0, 600, &errstr); 
		if (errstr != NULL)
			errx(1, "timeout in seconds is %s: %s",
			    errstr, timeoutstr);
	}

#ifndef PROFILE
	if (pledge("stdio dns inet getpw", NULL) == -1)
		err(1, "pledge");
#endif
	default_fromaddr = set_default_fromaddr();

#ifndef PROFILE
	if (pledge("stdio dns inet", NULL) == -1)
		err(1, "pledge");
#endif

	recipient = argv[0];
	if (fromaddr == NULL)
		fromaddr = default_fromaddr;

	send_email(default_fromaddr, fromaddr, recipient, replytoaddr,
	    subject, hostname, port);

	free(default_fromaddr);
	return 0;
}
