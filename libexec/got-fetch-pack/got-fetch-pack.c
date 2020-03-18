/*
 * Copyright (c) 2019 Ori Bernstein <ori@openbsd.org>
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
#include <sys/stat.h>
#include <sys/syslimits.h>

#include <stdint.h>
#include <errno.h>
#include <imsg.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sha1.h>
#include <fcntl.h>
#include <zlib.h>
#include <err.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"
#include "got_version.h"

#include "got_lib_sha1.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_privsep.h"
#include "got_lib_pack.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#define GOT_PKTMAX	65536

struct got_object *indexed;
static int chattygit;
static char *fetchbranch;
static struct got_object_id zhash = {.sha1={0}};

static const struct got_error *
readn(ssize_t *off, int fd, void *buf, size_t n)
{
	ssize_t r;

	*off = 0;
	while (*off != n) {
		r = read(fd, buf + *off, n - *off);
		if (r == -1)
			return got_error_from_errno("read");
		if (r == 0)
			return NULL;
		*off += r;
	}
	return NULL;
}

static const struct got_error *
flushpkt(int fd)
{
	ssize_t w;

	if (chattygit)
		fprintf(stderr, "writepkt: 0000\n");

	 w = write(fd, "0000", 4);
	 if (w == -1)
		return got_error_from_errno("write");
	if (w != 4)
		return got_error(GOT_ERR_IO);
	return NULL;
}


static const struct got_error *
readpkt(int *outlen, int fd, char *buf, int nbuf)
{
	const struct got_error *err = NULL;
	char lenstr[5];
	long len;
	char *e;
	int n, i;
	ssize_t r;

	*outlen = 0;

	err = readn(&r, fd, lenstr, 4);
	if (err)
		return err;
	if (r != 4)
		return got_error(GOT_ERR_IO);

	lenstr[4] = '\0';
	for (i = 0; i < 4; i++) {
		if (!isxdigit(lenstr[i]))
			return got_error(GOT_ERR_BAD_PACKET);
	}
	errno = 0;
	len = strtol(lenstr, &e, 16);
	if (lenstr[0] == '\0' || *e != '\0')
		return got_error(GOT_ERR_BAD_PACKET);
	if (errno == ERANGE && (len == LONG_MAX || len == LONG_MIN))
		return got_error(GOT_ERR_BAD_PACKET);
	if (len > INT_MAX || len < INT_MIN)
		return got_error(GOT_ERR_BAD_PACKET);
	n = len;
	if (n == 0) {
		if (chattygit)
			fprintf(stderr, "readpkt: 0000\n");
		return NULL;
	}
	if (n <= 4)
		return got_error(GOT_ERR_BAD_PACKET);
	n  -= 4;
	if (n >= nbuf)
		return got_error(GOT_ERR_NO_SPACE);

	err = readn(&r, fd, buf, n);
	if (err)
		return err;
	if (r != n)
		return got_error(GOT_ERR_BAD_PACKET);
	buf[n] = 0;
	if (chattygit)
		fprintf(stderr, "readpkt: %s:\t%.*s\n", lenstr, nbuf, buf);

	*outlen = n;
	return NULL;
}

static const struct got_error *
writepkt(int fd, char *buf, int nbuf)
{
	char len[5];
	int i;
	ssize_t w;

	if (snprintf(len, sizeof(len), "%04x", nbuf + 4) >= sizeof(len))
		return got_error(GOT_ERR_NO_SPACE);
	w = write(fd, len, 4);
	if (w == -1)
		return got_error_from_errno("write");
	if (w != 4)
		return got_error(GOT_ERR_IO);
	w = write(fd, buf, nbuf);
	if (w == -1)
		return got_error_from_errno("write");
	if (w != nbuf)
		return got_error(GOT_ERR_IO);
	if (chattygit) {
		fprintf(stderr, "writepkt: %s:\t", len);
		fwrite(buf, 1, nbuf, stderr);
		for (i = 0; i < nbuf; i++) {
			if (isprint(buf[i]))
				fputc(buf[i], stderr);
		}
		fputc('\n', stderr);
	}
	return NULL;
}

static const struct got_error *
match_remote_ref(struct got_pathlist_head *have_refs, struct got_object_id *id,
    char *refname, char *id_str)
{
	struct got_pathlist_entry *pe;

	memset(id, 0, sizeof(*id));

	TAILQ_FOREACH(pe, have_refs, entry) {
		if (strcmp(pe->path, refname) == 0) {
			if (!got_parse_sha1_digest(id->sha1, id_str))
				return got_error(GOT_ERR_BAD_OBJ_ID_STR);
			break;
		}
	}
	return NULL;
}

static const struct got_error *
check_pack_hash(int fd, size_t sz, uint8_t *hcomp)
{
	const struct got_error *err = NULL;
	SHA1_CTX ctx;
	uint8_t hexpect[SHA1_DIGEST_LENGTH];
	char s1[SHA1_DIGEST_STRING_LENGTH + 1];
	char s2[SHA1_DIGEST_STRING_LENGTH + 1];
	uint8_t buf[32 * 1024];
	ssize_t n, r, nr;

	if (sz < sizeof(struct got_packfile_hdr) + SHA1_DIGEST_LENGTH)
		return got_error(GOT_ERR_BAD_PACKFILE);

	n = 0;
	SHA1Init(&ctx);
	while (n < sz - 20) {
		nr = sizeof(buf);
		if (sz - n - 20 < sizeof(buf))
			nr = sz - n - 20;
		err = readn(&r, fd, buf, nr);
		if (err)
			return err;
		if (r != nr)
			return got_error(GOT_ERR_BAD_PACKFILE);
		SHA1Update(&ctx, buf, nr);
		n += r;
	}
	SHA1Final(hcomp, &ctx);

	err = readn(&r, fd, hexpect, sizeof(hexpect));
	if (err)
		return err;
	if (r != sizeof(hexpect))
		return got_error(GOT_ERR_BAD_PACKFILE);
	if (memcmp(hcomp, hexpect, SHA1_DIGEST_LENGTH) != 0) {
		got_sha1_digest_to_str(hcomp, s1, sizeof(s1));
		got_sha1_digest_to_str(hexpect, s2, sizeof(s2));
		return got_error(GOT_ERR_BAD_PACKFILE);
	}
	return NULL;
}

static int
match_branch(char *br, char *pat)
{
	char name[128];

	if (strstr(pat, "refs/heads") == pat) {
		if (snprintf(name, sizeof(name), "%s", pat) >= sizeof(name))
			return -1;
	} else if (strstr(pat, "heads")) {
		if (snprintf(name, sizeof(name), "refs/%s", pat)
		    >= sizeof(name))
			return -1;
	} else {
		if (snprintf(name, sizeof(name), "refs/heads/%s", pat)
		    >= sizeof(name))
			return -1;
	}
	return strcmp(br, name) == 0;
}

static const struct got_error *
tokenize_refline(char **tokens, char *line, int len, int maxtokens)
{
	const struct got_error *err = NULL;
	char *p;
	size_t i, n = 0;

	for (i = 0; i < maxtokens; i++)
		tokens[i] = NULL;

	for (i = 0; n < len && i < maxtokens; i++) {
		while (isspace(*line)) {
			line++;
			n++;
		}
		p = line;
		while (*line != '\0' &&
		    (!isspace(*line) || i == maxtokens - 1)) {
			line++;
			n++;
		}
		tokens[i] = strndup(p, line - p);
		if (tokens[i] == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		/* Skip \0 field-delimiter at end of token. */
		while (line[0] == '\0' && n < len) {
			line++;
			n++;
		}
	}
	if (i <= 2)
		err = got_error(GOT_ERR_NOT_REF);
done:
	if (err) {
		int j;
		for (j = 0; j < i; j++)
			free(tokens[j]);
			tokens[j] = NULL;
	}
	return err;
}

static const struct got_error *
parse_refline(char **id_str, char **refname, char **server_capabilities,
    char *line, int len)
{
	const struct got_error *err = NULL;
	char *tokens[3];

	err = tokenize_refline(tokens, line, len, nitems(tokens));
	if (err)
		return err;

	if (tokens[0])
		*id_str = tokens[0];
	if (tokens[1])
		*refname = tokens[1];
	if (tokens[2])
		*server_capabilities = tokens[2];
	
	return NULL;
}

struct got_capability {
	const char *key;
	const char *value;
};
static const struct got_capability got_capabilities[] = {
	{ "ofs-delta", NULL },
	{ "agent", "got/" GOT_VERSION_STR },
};

static const struct got_error *
match_capability(char **my_capabilities, const char *capa,
    const struct got_capability *mycapa)
{
	char *equalsign;
	char *s;

	equalsign = strchr(capa, '=');
	if (equalsign) {
		if (strncmp(capa, mycapa->key, equalsign - capa) != 0)
			return NULL;
	} else {
		if (strcmp(capa, mycapa->key) != 0)
			return NULL;
	}

	if (asprintf(&s, "%s%s%s%s%s",
	    *my_capabilities != NULL ? *my_capabilities : "",
	    *my_capabilities != NULL ? " " : "",
	    mycapa->key,
	    mycapa->value != NULL ? "=" : "",
	    mycapa->value != NULL? mycapa->value : "") == -1)
		return got_error_from_errno("asprintf");

	free(*my_capabilities);
	*my_capabilities = s;
	return NULL;
}

static const struct got_error *
add_symref(struct got_pathlist_head *symrefs, char *capa)
{
	const struct got_error *err = NULL;
	char *colon, *name = NULL, *target = NULL;

	/* Need at least "A:B" */
	if (strlen(capa) < 3)
		return NULL;

	colon = strchr(capa, ':');
	if (colon == NULL)
		return NULL;

	*colon = '\0';
	name = strdup(capa);
	if (name == NULL)
		return got_error_from_errno("strdup");

	target = strdup(colon + 1);
	if (target == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	/* We can't validate the ref itself here. The main process will. */
	err = got_pathlist_append(symrefs, name, target);
done:
	if (err) {
		free(name);
		free(target);
	}
	return err;
}

static const struct got_error *
match_capabilities(char **my_capabilities, struct got_pathlist_head *symrefs,
    char *server_capabilities)
{
	const struct got_error *err = NULL;
	char *capa, *equalsign;
	int i;

	*my_capabilities = NULL;
	do {
		capa = strsep(&server_capabilities, " ");
		if (capa == NULL)
			return NULL;

		equalsign = strchr(capa, '=');
		if (equalsign != NULL &&
		    strncmp(capa, "symref", equalsign - capa) == 0) {
			err = add_symref(symrefs, equalsign + 1);
			if (err)
				break;
			continue;
		}

		for (i = 0; i < nitems(got_capabilities); i++) {
			err = match_capability(my_capabilities,
			    capa, &got_capabilities[i]);
			if (err)
				break;
		}
	} while (capa);

	return err;
}

static const struct got_error *
fetch_pack(int fd, int packfd, struct got_object_id *packid,
    struct got_pathlist_head *have_refs, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	char buf[GOT_PKTMAX];
	char hashstr[SHA1_DIGEST_STRING_LENGTH];
	struct got_object_id *have, *want;
	int is_firstpkt = 1, nref = 0, refsz = 16;
	int i, n, req;
	off_t packsz;
	char *id_str = NULL, *refname = NULL;
	char *server_capabilities = NULL, *my_capabilities = NULL;
	struct got_pathlist_head symrefs;
	struct got_pathlist_entry *pe;

	TAILQ_INIT(&symrefs);

	have = malloc(refsz * sizeof(have[0]));
	if (have == NULL)
		return got_error_from_errno("malloc");
	want = malloc(refsz * sizeof(want[0]));
	if (want == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}
	if (chattygit)
		fprintf(stderr, "starting fetch\n");
	while (1) {
		err = readpkt(&n, fd, buf, sizeof(buf));
		if (err)
			goto done;
		if (n == 0)
			break;
		if (n >= 4 && strncmp(buf, "ERR ", 4) == 0) {
			static char msg[1024];
			for (i = 0; i < n && i < sizeof(msg) - 1; i++) {
				if (!isprint(buf[i])) {
					err = got_error(GOT_ERR_FETCH_FAILED);
					goto done;
				}
				msg[i] = buf[i];
			}
			msg[i] = '\0';
			err = got_error_msg(GOT_ERR_FETCH_FAILED, msg);
			goto done;
		}
		err = parse_refline(&id_str, &refname, &server_capabilities,
		    buf, n);
		if (err)
			goto done;
		if (chattygit && server_capabilities[0] != '\0')
			fprintf(stderr, "server capabilities: %s\n",
			    server_capabilities);
		if (is_firstpkt) {
			err = match_capabilities(&my_capabilities, &symrefs,
			    server_capabilities);
			if (err)
				goto done;
			if (chattygit && my_capabilities)
				fprintf(stderr, "my matched capabilities: %s\n",
				    my_capabilities);
			err = got_privsep_send_fetch_symrefs(ibuf, &symrefs);
			if (err)
				goto done;
		}
		is_firstpkt = 0;
		if (strstr(refname, "^{}"))
			continue;
		if (fetchbranch && !match_branch(refname, fetchbranch))
			continue;
		if (refsz == nref + 1) {
			refsz *= 2;
			have = reallocarray(have, refsz, sizeof(have[0]));
			if (have == NULL) {
				err = got_error_from_errno("reallocarray");
				goto done;
			}
			want = reallocarray(want, refsz, sizeof(want[0]));
			if (want == NULL) {
				err = got_error_from_errno("reallocarray");
				goto done;
			}
		}
		if (!got_parse_sha1_digest(want[nref].sha1, id_str)) {
			err = got_error(GOT_ERR_BAD_OBJ_ID_STR);
			goto done;
		}

		err = match_remote_ref(have_refs, &have[nref], id_str, refname);
		if (err)
			goto done;

		err = got_privsep_send_fetch_progress(ibuf, &want[nref],
		    refname);
		if (err)
			goto done;
		if (chattygit)
			fprintf(stderr, "remote %s\n", refname);
		nref++;
	}

	req = 0;
	for (i = 0; i < nref; i++) {
		if (got_object_id_cmp(&have[i], &want[i]) == 0)
			continue;
		got_sha1_digest_to_str(want[i].sha1, hashstr, sizeof(hashstr));
		n = snprintf(buf, sizeof(buf), "want %s%s%s\n", hashstr,
		   i == 0 && my_capabilities ? " " : "",
		   i == 0 && my_capabilities ? my_capabilities : "");
		if (n >= sizeof(buf)) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
		err = writepkt(fd, buf, n);
		if (err)
			goto done;
		req = 1;
	}
	err = flushpkt(fd);
	if (err)
		goto done;
	for (i = 0; i < nref; i++) {
		if (got_object_id_cmp(&have[i], &zhash) == 0)
			continue;
		got_sha1_digest_to_str(want[i].sha1, hashstr, sizeof(hashstr));
		n = snprintf(buf, sizeof(buf), "have %s\n", hashstr);
		if (n >= sizeof(buf)) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
		err = writepkt(fd, buf, n + 1);
		if (err)
			goto done;
	}
	if (!req) {
		fprintf(stderr, "up to date\n");
		err = flushpkt(fd);
		if (err)
			goto done;
	}
	n = snprintf(buf, sizeof(buf), "done\n");
	err = writepkt(fd, buf, n);
	if (err)
		goto done;
	if (!req)
		return 0;

	err = readpkt(&n, fd, buf, sizeof(buf));
	if (err)
		goto done;
	buf[n] = 0;

	if (chattygit)
		fprintf(stderr, "fetching...\n");
	packsz = 0;
	while (1) {
		ssize_t r, w;
		err = readn(&r, fd, buf, sizeof buf);
		if (err)
			goto done;
		if (r == 0)
			break;
		w = write(packfd, buf, r);
		if (w == -1) {
			err = got_error_from_errno("write");
			goto done;
		}
		if (w != r) {
			err = got_error(GOT_ERR_IO);
			goto done;
		}
		packsz += r;
	}
	if (lseek(packfd, 0, SEEK_SET) == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}
	err = check_pack_hash(packfd, packsz, packid->sha1);
done:
	TAILQ_FOREACH(pe, &symrefs, entry) {
		free((void *)pe->path);
		free(pe->data);
	}
	got_pathlist_free(&symrefs);
	free(have);
	free(want);
	free(id_str);
	free(refname);
	free(server_capabilities);
	return err;
}


int
main(int argc, char **argv)
{
	const struct got_error *err = NULL;
	int fetchfd, packfd = -1;
	struct got_object_id packid;
	struct imsgbuf ibuf;
	struct imsg imsg;
	struct got_pathlist_head have_refs;
	struct got_imsg_fetch_have_refs *fetch_have_refs = NULL;
	size_t datalen;

	TAILQ_INIT(&have_refs);

	if (getenv("GOT_DEBUG") != NULL) {
		fprintf(stderr, "fetch-pack being chatty!\n");
		chattygit = 1;
	}

	imsg_init(&ibuf, GOT_IMSG_FD_CHILD);
#ifndef PROFILE
	/* revoke access to most system calls */
	if (pledge("stdio recvfd", NULL) == -1) {
		err = got_error_from_errno("pledge");
		got_privsep_send_error(&ibuf, err);
		return 1;
	}
#endif
	if ((err = got_privsep_recv_imsg(&imsg, &ibuf, 0)) != 0) {
		if (err->code == GOT_ERR_PRIVSEP_PIPE)
			err = NULL;
		goto done;
	}
	if (imsg.hdr.type == GOT_IMSG_STOP)
		goto done;
	if (imsg.hdr.type != GOT_IMSG_FETCH_REQUEST) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}
	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(struct got_imsg_fetch_have_refs)) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	fetch_have_refs = (struct got_imsg_fetch_have_refs *)imsg.data;
	if (datalen != sizeof(struct got_imsg_fetch_have_refs) +
	    sizeof(struct got_imsg_fetch_have_ref) *
	    fetch_have_refs->n_have_refs) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	if (fetch_have_refs->n_have_refs != 0) {
		/* TODO: Incremental fetch support */
		err = got_error(GOT_ERR_NOT_IMPL);
		goto done;
	}
	fetchfd = imsg.fd;

	if ((err = got_privsep_recv_imsg(&imsg, &ibuf, 0)) != 0) {
		if (err->code == GOT_ERR_PRIVSEP_PIPE)
			err = NULL;
		goto done;
	}
	if (imsg.hdr.type == GOT_IMSG_STOP)
		goto done;
	if (imsg.hdr.type != GOT_IMSG_TMPFD) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}
	if (imsg.hdr.len - IMSG_HEADER_SIZE != 0) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	packfd = imsg.fd;

	err = fetch_pack(fetchfd, packfd, &packid, &have_refs, &ibuf);
	if (err)
		goto done;
done:
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (err != NULL)
		got_privsep_send_error(&ibuf, err);
	else
		err = got_privsep_send_fetch_done(&ibuf, packid);
	if (err != NULL) {
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
		got_privsep_send_error(&ibuf, err);
	}

	exit(0);
}
