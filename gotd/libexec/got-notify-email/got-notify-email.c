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

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "log.h"

#include "got_error.h"

#include "got_lib_poll.h"

#define SMTP_LINE_MAX	65535

static int smtp_timeout = 60; /* in seconds */
static char smtp_buf[SMTP_LINE_MAX];
static size_t smtp_buflen;

__dead static void
usage(void)
{
	fprintf(stderr, "usage: %s [-f sender] [-r responder] "
	    "[-s subject] [-h hostname] [-p port] recipient\n", getprogname());
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
		fatalx("failed to resolve %s:%s: %s", host, port,
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
		fatal("%s", cause);
	return s;
}

static char *
set_default_fromaddr(void)
{
	struct passwd *pw = NULL;
	char *s;
	char hostname[255];

	pw = getpwuid(getuid());
	if (pw == NULL) {
		fatalx("my UID %d was not found in password database",
		    getuid());
	}

	if (gethostname(hostname, sizeof(hostname)) == -1)
		fatal("gethostname");

	if (asprintf(&s, "%s@%s", pw->pw_name, hostname) == -1)
		fatal("asprintf");

	return s;
}

static int
read_smtp_code(int s, const char *code)
{
	const struct got_error *error;
	char	*endl;
	size_t	 linelen;
	ssize_t	 r;

	for (;;) {
		endl = memmem(smtp_buf, smtp_buflen, "\r\n", 2);
		if (endl != NULL)
			break;

		if (smtp_buflen == sizeof(smtp_buf))
			fatalx("line too long");

		error = got_poll_fd(s, POLLIN, smtp_timeout);
		if (error)
			fatalx("poll: %s", error->msg);

		r = read(s, smtp_buf + smtp_buflen,
		    sizeof(smtp_buf) - smtp_buflen);
		if (r == -1)
			fatal("read");
		if (r == 0)
			fatalx("unexpected EOF");
		smtp_buflen += r;
	}

	linelen = endl - smtp_buf;
	if (linelen < 3)
		fatalx("invalid SMTP response");

	if (strncmp(code, smtp_buf, 3) != 0) {
		smtp_buf[3] = '\0';
		log_warnx("unexpected SMTP message code: %s", smtp_buf);
		return -1;
	}

	/*
	 * Normally we would get just one reply, but the regress doesn't
	 * use a real SMTP server and queues all the replies upfront.
	 */
	linelen += 2;
	memmove(smtp_buf, smtp_buf + linelen, smtp_buflen - linelen);
	smtp_buflen -= linelen;

	return 0;
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
		log_warn("vsnprintf");
		return -1;
	}
	if (len >= sizeof(buf)) {
		log_warnx("%s: buffer too small for message '%s...'",
		    __func__, buf);
		return -1;
	}

	error = got_poll_write_full(s, buf, len);
	if (error) {
		log_warnx("write: %s", error->msg);
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

static const struct got_error *
print_date(int s, char *date, int shortfmt)
{
	const struct got_error	*error;
	struct tm		 tm;
	char			*t, datebuf[26];
	const char		*errstr;
	time_t			 ts;

	date[strcspn(date, " \n")] = '\0';

	ts = strtonum(date, INT64_MIN, INT64_MAX, &errstr);
	if (errstr)
		return got_error_set_errno(EINVAL, errstr);
	if (gmtime_r(&ts, &tm) == NULL)
		return got_error_set_errno(EINVAL, "gmtime_r");

	if (!shortfmt) {
		t = asctime_r(&tm, datebuf);
		if (t == NULL)
			return got_error_set_errno(EINVAL, "invalid timestamp");
		t[strcspn(t, "\n")] = '\0';
		error = got_poll_write_full(s, t, strlen(t));
		if (error)
			return error;
		return got_poll_write_full(s, " UTC\n", 5);
	}

	if (strftime(datebuf, sizeof(datebuf), "%F ", &tm) == 0)
		return got_error_set_errno(EINVAL, "invalid timestamp");
	return got_poll_write_full(s, datebuf, strlen(datebuf));
}

static void
send_email(int s, const char *myfromaddr, const char *fromaddr,
    const char *recipient, const char *replytoaddr,
    const char *subject)
{
	const struct got_error *error;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	time_t now;
	int firstline = 1, shortfmt = 0;
	char datebuf[26];
	char *datestr;

	now = time(NULL);
	datestr = get_datestr(&now, datebuf);

	if (read_smtp_code(s, "220"))
		fatalx("unexpected SMTP greeting received");

	if (send_smtp_msg(s, "HELO localhost\r\n"))
		fatalx("could not send HELO");
	if (read_smtp_code(s, "250"))
		fatalx("unexpected SMTP response received");

	if (send_smtp_msg(s, "MAIL FROM:<%s>\r\n", myfromaddr))
		fatalx("could not send MAIL FROM");
	if (read_smtp_code(s, "250"))
		fatalx("unexpected SMTP response received");

	if (send_smtp_msg(s, "RCPT TO:<%s>\r\n", recipient))
		fatalx("could not send MAIL FROM");
	if (read_smtp_code(s, "250"))
		fatalx("unexpected SMTP response received");

	if (send_smtp_msg(s, "DATA\r\n"))
		fatalx("could not send MAIL FROM");
	if (read_smtp_code(s, "354"))
		fatalx("unexpected SMTP response received");

	if (send_smtp_msg(s, "From: %s\r\n", fromaddr))
		fatalx("could not send From header");
	if (send_smtp_msg(s, "To: %s\r\n", recipient))
		fatalx("could not send To header");
	if (replytoaddr) {
		if (send_smtp_msg(s, "Reply-To: %s\r\n", replytoaddr))
			fatalx("could not send Reply-To header");
	}
	if (send_smtp_msg(s, "Date: %s +0000 (UTC)\r\n", datestr))
		fatalx("could not send Date header");

	if (send_smtp_msg(s, "Subject: %s\r\n", subject))
		fatalx("could not send Subject header");

	if (send_smtp_msg(s, "\r\n"))
		fatalx("could not send body delimiter");

	while ((linelen = getline(&line, &linesize, stdin)) != -1) {
		if (firstline && isdigit((unsigned char)line[0]))
			shortfmt = 1;
		firstline = 0;

		if (line[0] == '.') { /* dot stuffing */
			error = got_poll_write_full(s, ".", 1);
			if (error)
				fatalx("write: %s", error->msg);
		}

		if (shortfmt) {
			char *t;
			t = strchr(line, ' ');
			if (t != NULL) {
				*t++ = '\0';
				error = print_date(s, line, shortfmt);
				if (error)
					fatalx("write: %s", error->msg);
				error = got_poll_write_full(s, t, strlen(t));
				continue;
			}
		}

		if (!shortfmt && !strncmp(line, "date: ", 6)) {
			error = got_poll_write_full(s, line, 6);
			if (error)
				fatalx("write: %s", error->msg);
			error = print_date(s, line + 6, shortfmt);
			if (error)
				fatalx("write: %s", error->msg);
			continue;
		}

		error = got_poll_write_full(s, line, linelen);
		if (error)
			fatalx("write: %s", error->msg);
	}

	if (send_smtp_msg(s, "\r\n.\r\n"))
		fatalx("could not send data terminator");
	if (read_smtp_code(s, "250"))
		fatalx("unexpected SMTP response received");

	if (send_smtp_msg(s, "QUIT\r\n"))
		fatalx("could not send QUIT");

	if (read_smtp_code(s, "221"))
		fatalx("unexpected SMTP response received");

	close(s);
	free(line);
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
	int ch, s;

	log_init(0, LOG_DAEMON);
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
			fatalx("timeout in seconds is %s: %s",
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

	s = dial(hostname, port);

#ifndef PROFILE
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");
#endif

	send_email(s, default_fromaddr, fromaddr, recipient, replytoaddr,
	    subject);

	free(default_fromaddr);
	return 0;
}
