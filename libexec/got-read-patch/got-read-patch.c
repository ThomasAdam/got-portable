/*
 * Copyright 1986, Larry Wall
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following condition is met:
 * 1. Redistributions of source code must retain the above copyright notice,
 * this condition and the following disclaimer.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

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
#include "got_compat.h"

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <err.h>
#include <ctype.h>
#include <limits.h>
#include <paths.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"

#include "got_lib_delta.h"
#include "got_lib_hash.h"
#include "got_lib_object.h"
#include "got_lib_privsep.h"

struct imsgbuf ibuf;

static const struct got_error *
send_patch(const char *oldname, const char *newname, const char *commitid,
    const char *blob, const int xbit, int git)
{
	struct got_imsg_patch p;

	memset(&p, 0, sizeof(p));

	if (oldname != NULL)
		strlcpy(p.old, oldname, sizeof(p.old));

	if (newname != NULL)
		strlcpy(p.new, newname, sizeof(p.new));

	if (commitid != NULL)
		strlcpy(p.cid, commitid, sizeof(p.cid));

	if (blob != NULL)
		strlcpy(p.blob, blob, sizeof(p.blob));

	p.xbit = xbit;
	p.git = git;
	if (imsg_compose(&ibuf, GOT_IMSG_PATCH, 0, 0, -1, &p, sizeof(p)) == -1)
		return got_error_from_errno("imsg_compose GOT_IMSG_PATCH");
	return NULL;
}

static const struct got_error *
send_patch_done(void)
{
	if (imsg_compose(&ibuf, GOT_IMSG_PATCH_DONE, 0, 0, -1,
	    NULL, 0) == -1)
		return got_error_from_errno("imsg_compose GOT_IMSG_PATCH_EOF");
	return got_privsep_flush_imsg(&ibuf);
}

/* based on fetchname from usr.bin/patch/util.c */
static const struct got_error *
filename(const char *at, char **name)
{
	char	*tmp, *t;

	*name = NULL;
	if (*at == '\0')
		return NULL;

	while (isspace((unsigned char)*at))
		at++;

	/* files can be created or removed by diffing against /dev/null */
	if (!strncmp(at, _PATH_DEVNULL, sizeof(_PATH_DEVNULL) - 1))
		return NULL;

	tmp = strdup(at);
	if (tmp == NULL)
		return got_error_from_errno("strdup");
	if ((t = strchr(tmp, '\t')) != NULL)
		*t = '\0';
	if ((t = strchr(tmp, '\n')) != NULL)
		*t = '\0';

	*name = strdup(tmp);
	free(tmp);
	if (*name == NULL)
		return got_error_from_errno("strdup");
	return NULL;
}

static int
binary_deleted(const char *line)
{
	const char *prefix = "Binary files ";
	const char *suffix = " and /dev/null differ\n";
	size_t len, d;

	if (strncmp(line, prefix, strlen(prefix)) != 0)
		return 0;
	line += strlen(prefix);

	len = strlen(line);
	if (len <= strlen(suffix))
		return 0;
	d = len - strlen(suffix);
	return (strcmp(line + d, suffix) == 0);
}

static const struct got_error *
binaryfilename(const char *at, char **name)
{
	const char *suffix = " and /dev/null differ\n";
	size_t len, d;

	*name = NULL;

	len = strlen(at);
	if (len <= strlen(suffix))
		return NULL;

	d = len - strlen(suffix);
	if (strcmp(at + d, suffix) != 0)
		return NULL;

	*name = strndup(at, d);
	if (*name == NULL)
		return got_error_from_errno("strndup");
	return NULL;
}

static int
filexbit(const char *line)
{
	char *m;

	m = strchr(line, '(');
	if (m && !strncmp(m + 1, "mode ", 5))
		return strncmp(m + 6, "755", 3) == 0;

	return 0;
}

static const struct got_error *
blobid(const char *line, char **blob, int git)
{
	size_t len;

	*blob = NULL;

	len = strspn(line, "0123456789abcdefABCDEF");
	if ((*blob = strndup(line, len)) == NULL)
		return got_error_from_errno("strndup");

	if (git)
		return NULL;

	if (len != got_hash_digest_string_length(GOT_HASH_SHA1) - 1 &&
	    len != got_hash_digest_string_length(GOT_HASH_SHA256) - 1) {
		/* silently ignore invalid blob ids */
		free(*blob);
		*blob = NULL;
	}
	return NULL;
}

static const struct got_error *
patch_start(int *git, char **cid, FILE *fp)
{
	const struct got_error *err = NULL;
	char	*line = NULL;
	size_t	 linesize = 0;
	ssize_t	 linelen;

	*git = 0;

	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		if (!strncmp(line, "diff --git ", 11)) {
			*git = 1;
			free(*cid);
			*cid = NULL;
			break;
		} else if (!strncmp(line, "diff ", 5)) {
			*git = 0;
			free(*cid);
			*cid = NULL;
		} else if (!strncmp(line, "commit - ", 9)) {
			free(*cid);
			err = blobid(line + 9, cid, *git);
			if (err)
				break;
		} else if (!strncmp(line, "--- ", 4) ||
		    !strncmp(line, "+++ ", 4) ||
		    !strncmp(line, "blob - ", 7) ||
		    binary_deleted(line)) {
			/* rewind to previous line */
			if (fseeko(fp, -linelen, SEEK_CUR) == -1)
				err = got_error_from_errno("fseeko");
			break;
		}
	}

	free(line);
	if (ferror(fp) && err == NULL)
		err = got_error_from_errno("getline");
	if (feof(fp) && err == NULL)
		err = got_error(GOT_ERR_NO_PATCH);
	return err;
}

static const struct got_error *
find_diff(int *done, int *next, FILE *fp, int git, const char *commitid)
{
	const struct got_error *err = NULL;
	char	*old = NULL, *new = NULL;
	char	*blob = NULL;
	char	*line = NULL;
	size_t	 linesize = 0;
	ssize_t	 linelen;
	int	 create, delete_binary = 0, rename = 0, xbit = 0;

	*done = 0;
	*next = 0;
	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		/*
		 * Ignore the Index name like GNU and larry' patch,
		 * we don't have to follow POSIX.
		 */

		if (!strncmp(line, "--- ", 4)) {
			free(old);
			err = filename(line+4, &old);
		} else if (rename && !strncmp(line, "rename from ", 12)) {
			free(old);
			err = filename(line+12, &old);
		} else if (!strncmp(line, "+++ ", 4)) {
			free(new);
			err = filename(line+4, &new);
		} else if (!strncmp(line, "blob + ", 7) ||
		    !strncmp(line, "file + ", 7)) {
			xbit = filexbit(line);
		} else if (!git && !strncmp(line, "blob - ", 7)) {
			free(blob);
			err = blobid(line + 7, &blob, git);
		} else if (!strncmp(line, "Binary files ", 13)) {
			delete_binary = 1;
			free(old);
			err = binaryfilename(line + 13, &old);
		} else if (rename && !strncmp(line, "rename to ", 10)) {
			free(new);
			err = filename(line + 10, &new);
		} else if (git && !strncmp(line, "similarity index 100%", 21))
			rename = 1;
		else if (git && !strncmp(line, "new file mode 100", 17))
			xbit = strncmp(line + 17, "755", 3) == 0;
		else if (git && !strncmp(line, "index ", 6)) {
			free(blob);
			err = blobid(line + 6, &blob, git);
		} else if (!strncmp(line, "diff ", 5)) {
			/* rewind to previous line */
			if (fseeko(fp, -linelen, SEEK_CUR) == -1)
				err = got_error_from_errno("fseeko");
			*next = 1;
			break;
		}

		if (err)
			break;

		/*
		 * Git-style diffs with "similarity index 100%" don't
		 * have any hunks and ends with the "rename to foobar"
		 * line.
		 */
		if (rename && old != NULL && new != NULL) {
			*done = 1;
			err = send_patch(old, new, commitid,
			    blob, xbit, git);
			break;
		}

		/*
		 * Diffs that remove binary files have no hunks.
		 */
		if (delete_binary && old != NULL) {
			*done = 1;
			err = send_patch(old, new, commitid,
			    blob, xbit, git);
			break;
		}

		if (!strncmp(line, "@@ -", 4)) {
			create = !strncmp(line+4, "0,0", 3);
			if ((old == NULL && new == NULL) ||
			    (!create && old == NULL))
				err = got_error_fmt(GOT_ERR_PATCH_MALFORMED,
				    "%s", line);
			else
				err = send_patch(old, new, commitid,
				    blob, xbit, git);

			if (err)
				break;

			/* rewind to previous line */
			if (fseeko(fp, -linelen, SEEK_CUR) == -1)
				err = got_error_from_errno("fseeko");
			break;
		}
	}

	free(old);
	free(new);
	free(blob);
	free(line);
	if (ferror(fp) && err == NULL)
		err = got_error_from_errno("getline");
	if (feof(fp) && err == NULL)
		err = got_error(GOT_ERR_NO_PATCH);
	return err;
}

static const struct got_error *
strtolnum(char **str, int *n)
{
	char		*p, c;
	const char	*errstr;

	for (p = *str; isdigit((unsigned char)*p); ++p)
		/* nop */;

	c = *p;
	*p = '\0';

	*n = strtonum(*str, 0, INT_MAX, &errstr);
	if (errstr != NULL)
		return got_error_fmt(GOT_ERR_PATCH_MALFORMED,
		    "%s: %s", *str, errstr);

	*p = c;
	*str = p;
	return NULL;
}

static const struct got_error *
parse_hdr(char *s, int *done, struct got_imsg_patch_hunk *hdr)
{
	const struct got_error *err = NULL;
	char *s0 = s; 

	if (strncmp(s, "@@ -", 4)) {
		*done = 1;
		return NULL;
	}

	s += 4;
	if (!*s)
		return NULL;
	err = strtolnum(&s, &hdr->oldfrom);
	if (err)
		return err;
	if (*s == ',') {
		s++;
		err = strtolnum(&s, &hdr->oldlines);
		if (err)
			return err;
	} else
		hdr->oldlines = 1;

	if (*s == ' ')
		s++;

	if (*s != '+' || !*++s)
		return got_error_fmt(GOT_ERR_PATCH_MALFORMED, "%s", s0);
	err = strtolnum(&s, &hdr->newfrom);
	if (err)
		return err;
	if (*s == ',') {
		s++;
		err = strtolnum(&s, &hdr->newlines);
		if (err)
			return err;
	} else
		hdr->newlines = 1;

	if (*s == ' ')
		s++;

	if (*s != '@')
		return got_error_fmt(GOT_ERR_PATCH_MALFORMED, "%s", s0);

	if (hdr->oldfrom >= INT_MAX - hdr->oldlines ||
	    hdr->newfrom >= INT_MAX - hdr->newlines ||
	    /* not so sure about this one */
	    hdr->oldlines >= INT_MAX - hdr->newlines - 1 ||
	    (hdr->oldlines == 0 && hdr->newlines == 0))
		return got_error_fmt(GOT_ERR_PATCH_MALFORMED, "%s", s0);

	if (hdr->oldlines == 0) {
		/* larry says to "do append rather than insert"; I don't
		 * quite get it, but i trust him.
		 */
		hdr->oldfrom++;
	}

	if (imsg_compose(&ibuf, GOT_IMSG_PATCH_HUNK, 0, 0, -1,
	    hdr, sizeof(*hdr)) == -1)
		return got_error_from_errno(
		    "imsg_compose GOT_IMSG_PATCH_HUNK");
	return NULL;
}

static const struct got_error *
send_line(const char *line, size_t len)
{
	const struct got_error *err = NULL;
	struct iovec iov[2];
	int iovcnt = 0;

	memset(&iov, 0, sizeof(iov));

	if (*line != '+' && *line != '-' && *line != ' ' && *line != '\\') {
		iov[iovcnt].iov_base = (void *)" ";
		iov[iovcnt].iov_len = 1;
		iovcnt++;
	}

	iov[iovcnt].iov_base = (void *)line;
	iov[iovcnt].iov_len = len;
	iovcnt++;

	if (imsg_composev(&ibuf, GOT_IMSG_PATCH_LINE, 0, 0, -1,
	    iov, iovcnt) == -1)
		err = got_error_from_errno(
		    "imsg_compose GOT_IMSG_PATCH_LINE");

	return err;
}

static const struct got_error *
peek_special_line(FILE *fp)
{
	const struct got_error *err;
	int ch;

	ch = fgetc(fp);
	if (ch != EOF && ch != '\\') {
		ungetc(ch, fp);
		return NULL;
	}

	if (ch == '\\') {
		err = send_line("\\", 2);
		if (err)
			return err;
	}

	while (ch != EOF && ch != '\n')
		ch = fgetc(fp);

	if (ch != EOF || feof(fp))
		return NULL;
	return got_error(GOT_ERR_IO);
}

static const struct got_error *
parse_hunk(FILE *fp, int *done)
{
	const struct got_error *err = NULL;
	struct got_imsg_patch_hunk hdr;
	char	*line = NULL, ch;
	size_t	 linesize = 0;
	ssize_t	 linelen;
	int	 leftold, leftnew;

	linelen = getline(&line, &linesize, fp);
	if (linelen == -1) {
		*done = 1;
		goto done;
	}
	if (line[linelen - 1] == '\n')
		line[linelen - 1] = '\0';

	err = parse_hdr(line, done, &hdr);
	if (err)
		goto done;
	if (*done) {
		if (fseeko(fp, -linelen, SEEK_CUR) == -1)
			err = got_error_from_errno("fseeko");
		goto done;
	}

	leftold = hdr.oldlines;
	leftnew = hdr.newlines;

	while (leftold > 0 || leftnew > 0) {
		linelen = getline(&line, &linesize, fp);
		if (linelen == -1) {
			if (ferror(fp)) {
				err = got_error_from_errno("getline");
				goto done;
			}

			/* trailing newlines may be chopped */
			if (leftold < 3 && leftnew < 3) {
				*done = 1;
				break;
			}

			err = got_error(GOT_ERR_PATCH_TRUNCATED);
			goto done;
		}
		if (line[linelen - 1] == '\n')
			line[linelen - 1] = '\0';

		/* usr.bin/patch allows '=' as context char */
		if (*line == '=')
			*line = ' ';

		ch = *line;
		if (ch == '\t' || ch == '\0')
			ch = ' ';	/* the space got eaten */

		switch (ch) {
		case '-':
			leftold--;
			break;
		case ' ':
			leftold--;
			leftnew--;
			break;
		case '+':
			leftnew--;
			break;
		default:
			err = got_error_fmt(GOT_ERR_PATCH_MALFORMED,
			    "%s", line);
			goto done;
		}

		if (leftold < 0 || leftnew < 0) {
			err = got_error_fmt(GOT_ERR_PATCH_MALFORMED,
			    "%s", line);
			goto done;
		}

		err = send_line(line, linelen);
		if (err)
			goto done;

		if ((ch == '-' && leftold == 0) ||
		    (ch == '+' && leftnew == 0)) {
			err = peek_special_line(fp);
			if (err)
				goto done;
		}
	}

done:
	free(line);
	return err;
}

static const struct got_error *
read_patch(struct imsgbuf *ibuf, FILE *fp)
{
	const struct got_error *err = NULL;
	int git, patch_found = 0;
	char *cid = NULL;

	while ((err = patch_start(&git, &cid, fp)) == NULL) {
		int done, next;

		err = find_diff(&done, &next, fp, git, cid);
		if (err)
			goto done;
		if (next)
			continue;

		patch_found = 1;

		while (!done) {
			err = parse_hunk(fp, &done);
			if (err)
				goto done;
		}

		err = send_patch_done();
		if (err)
			goto done;
	}

done:
	free(cid);

	/* ignore trailing gibberish */
	if (err != NULL && err->code == GOT_ERR_NO_PATCH && patch_found)
		err = NULL;

	return err;
}

int
main(int argc, char **argv)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	FILE *fp = NULL;
	int fd = -1;
#if 0
	static int attached;
	while (!attached)
		sleep(1);
#endif

	if (imsgbuf_init(&ibuf, GOT_IMSG_FD_CHILD) == -1) {
		warn("imsgbuf_init");
		return 1;
	}
	imsgbuf_allow_fdpass(&ibuf);
#ifndef PROFILE
	/* revoke access to most system calls */
	if (pledge("stdio recvfd", NULL) == -1) {
		err = got_error_from_errno("pledge");
		got_privsep_send_error(&ibuf, err);
		imsgbuf_clear(&ibuf);
		return 1;
	}

	/* revoke fs access */
	if (landlock_no_fs() == -1) {
		err = got_error_from_errno("landlock_no_fs");
		got_privsep_send_error(&ibuf, err);
		return 1;
	}
	if (cap_enter() == -1) {
		err = got_error_from_errno("cap_enter");
		got_privsep_send_error(&ibuf, err);
		return 1;
	}
#endif

	err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
	if (err)
		goto done;
	if (imsg.hdr.type != GOT_IMSG_PATCH_FILE) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}
	fd = imsg_get_fd(&imsg);
	if (fd == -1) {
		err = got_error(GOT_ERR_PRIVSEP_NO_FD);
		goto done;
	}

	fp = fdopen(fd, "r");
	if (fp == NULL) {
		err = got_error_from_errno("fdopen");
		goto done;
	}
	fd = -1;

	err = read_patch(&ibuf, fp);
	if (err)
		goto done;
	if (imsg_compose(&ibuf, GOT_IMSG_PATCH_EOF, 0, 0, -1,
	    NULL, 0) == -1) {
		err = got_error_from_errno("imsg_compose GOT_IMSG_PATCH_EOF");
		goto done;
	}
	err = got_privsep_flush_imsg(&ibuf);
	imsg_free(&imsg);
done:
	if (err != NULL) {
		if (err->code != GOT_ERR_PRIVSEP_PIPE) {
			fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
			fflush(stderr);
		}
		got_privsep_send_error(&ibuf, err);
	}
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (fp != NULL && fclose(fp) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (close(GOT_IMSG_FD_CHILD) == -1 && err == NULL)
		err = got_error_from_errno("close");
	imsgbuf_clear(&ibuf);
	return err ? 1 : 0;
}
