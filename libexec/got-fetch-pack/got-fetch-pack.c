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
#include "got_fetch.h"

#include "got_lib_sha1.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_privsep.h"
#include "got_lib_pack.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct got_object *indexed;
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

	 w = write(fd, "0000", 4);
	 if (w == -1)
		return got_error_from_errno("write");
	if (w != 4)
		return got_error(GOT_ERR_IO);
	return NULL;
}

/*
 * Packet header contains a 4-byte hexstring which specifies the length
 * of data which follows.
 */
static const struct got_error *
read_pkthdr(int *datalen, int fd)
{
	static const struct got_error *err = NULL;
	char lenstr[5];
	long len;
	char *e;
	int n, i;
	ssize_t r;

	*datalen = 0;

	err = readn(&r, fd, lenstr, 4);
	if (err)
		return err;
	if (r == 0) /* implicit "0000" */
		return NULL;
	if (r != 4)
		return got_error_msg(GOT_ERR_BAD_PACKET,
		    "wrong packet header length");

	lenstr[4] = '\0';
	for (i = 0; i < 4; i++) {
		if (!isxdigit(lenstr[i]))
			return got_error_msg(GOT_ERR_BAD_PACKET,
			    "packet length not specified in hex");
	}
	errno = 0;
	len = strtol(lenstr, &e, 16);
	if (lenstr[0] == '\0' || *e != '\0')
		return got_error(GOT_ERR_BAD_PACKET);
	if (errno == ERANGE && (len == LONG_MAX || len == LONG_MIN))
		return got_error_msg(GOT_ERR_BAD_PACKET, "bad packet length");
	if (len > INT_MAX || len < INT_MIN)
		return got_error_msg(GOT_ERR_BAD_PACKET, "bad packet length");
	n = len;
	if (n == 0)
		return NULL;
	if (n <= 4)
		return got_error_msg(GOT_ERR_BAD_PACKET, "packet too short");
	n  -= 4;

	*datalen = n;
	return NULL;
}

static const struct got_error *
readpkt(int *outlen, int fd, char *buf, int buflen)
{
	const struct got_error *err = NULL;
	int datalen;
	ssize_t n;

	err = read_pkthdr(&datalen, fd);
	if (err)
		return err;

	if (datalen > buflen)
		return got_error(GOT_ERR_NO_SPACE);

	err = readn(&n, fd, buf, datalen);
	if (err)
		return err;
	if (n != datalen)
		return got_error_msg(GOT_ERR_BAD_PACKET, "short packet");

	*outlen = n;
	return NULL;
}

static const struct got_error *
writepkt(int fd, char *buf, int nbuf)
{
	char len[5];
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
	return NULL;
}

static void
match_remote_ref(struct got_pathlist_head *have_refs,
    struct got_object_id *my_id, char *refname)
{
	struct got_pathlist_entry *pe;

	/* XXX zero-hash signifies we don't have this ref;
	 * we should use a flag instead */
	memset(my_id, 0, sizeof(*my_id));

	TAILQ_FOREACH(pe, have_refs, entry) {
		struct got_object_id *id = pe->data;
		if (strcmp(pe->path, refname) == 0) { 
			memcpy(my_id, id, sizeof(*my_id));
			break;
		}
	}
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

#define GOT_CAPA_AGENT			"agent"
#define GOT_CAPA_OFS_DELTA		"ofs-delta"
#define GOT_CAPA_SIDE_BAND_64K		"side-band-64k"

#define GOT_SIDEBAND_PACKFILE_DATA	1
#define GOT_SIDEBAND_PROGRESS_INFO	2
#define GOT_SIDEBAND_ERROR_INFO		3


struct got_capability {
	const char *key;
	const char *value;
};
static const struct got_capability got_capabilities[] = {
	{ GOT_CAPA_AGENT, "got/" GOT_VERSION_STR },
	{ GOT_CAPA_OFS_DELTA, NULL },
	{ GOT_CAPA_SIDE_BAND_64K, NULL },
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

	if (asprintf(&s, "%s %s%s%s",
	    *my_capabilities != NULL ? *my_capabilities : "",
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

	if (*my_capabilities == NULL) {
		*my_capabilities = strdup("");
		if (*my_capabilities == NULL)
			err = got_error_from_errno("strdup");
	}
	return err;
}

static const struct got_error *
fetch_progress(struct imsgbuf *ibuf, const char *buf, size_t len)
{
	int i;

	if (len == 0)
		return NULL;

	/*
	 * Truncate messages which exceed the maximum imsg payload size.
	 * Server may send up to 64k.
	 */
	if (len > MAX_IMSGSIZE - IMSG_HEADER_SIZE)
		len = MAX_IMSGSIZE - IMSG_HEADER_SIZE;

	/* Only allow printable ASCII. */
	for (i = 0; i < len; i++) {
		if (isprint((unsigned char)buf[i]) ||
		    isspace((unsigned char)buf[i]))
			continue;
		return got_error_msg(GOT_ERR_BAD_PACKET,
		    "non-printable progress message received from server");
	}

	return got_privsep_send_fetch_server_progress(ibuf, buf, len);
}

static const struct got_error *
fetch_error(const char *buf, size_t len)
{
	static char msg[1024];
	int i;

	for (i = 0; i < len && i < sizeof(msg) - 1; i++) {
		if (!isprint(buf[i]))
			return got_error_msg(GOT_ERR_BAD_PACKET,
			    "non-printable error message received from server");
		msg[i] = buf[i];
	}
	msg[i] = '\0';
	return got_error_msg(GOT_ERR_FETCH_FAILED, msg);
}

static const struct got_error *
fetch_pack(int fd, int packfd, struct got_object_id *packid,
    struct got_pathlist_head *have_refs, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	char buf[GOT_FETCH_PKTMAX];
	char hashstr[SHA1_DIGEST_STRING_LENGTH];
	struct got_object_id *have, *want;
	int is_firstpkt = 1, nref = 0, refsz = 16;
	int i, n, nwant = 0, nhave = 0, acked = 0;
	off_t packsz = 0, last_reported_packsz = 0;
	char *id_str = NULL, *refname = NULL;
	char *server_capabilities = NULL, *my_capabilities = NULL;
	struct got_pathlist_head symrefs;
	struct got_pathlist_entry *pe;
	int sent_my_capabilites = 0, have_sidebands = 0;

	TAILQ_INIT(&symrefs);

	have = malloc(refsz * sizeof(have[0]));
	if (have == NULL)
		return got_error_from_errno("malloc");
	want = malloc(refsz * sizeof(want[0]));
	if (want == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}
	while (1) {
		err = readpkt(&n, fd, buf, sizeof(buf));
		if (err)
			goto done;
		if (n == 0)
			break;
		if (n >= 4 && strncmp(buf, "ERR ", 4) == 0) {
			err = fetch_error(&buf[4], n - 4);
			goto done;
		}
		err = parse_refline(&id_str, &refname, &server_capabilities,
		    buf, n);
		if (err)
			goto done;
		if (is_firstpkt) {
			err = match_capabilities(&my_capabilities, &symrefs,
			    server_capabilities);
			if (err)
				goto done;
			err = got_privsep_send_fetch_symrefs(ibuf, &symrefs);
			if (err)
				goto done;
			is_firstpkt = 0;
			continue;
		}
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
		match_remote_ref(have_refs, &have[nref], refname);
		err = got_privsep_send_fetch_ref(ibuf, &want[nref],
		    refname);
		if (err)
			goto done;
		nref++;
	}

	for (i = 0; i < nref; i++) {
		if (got_object_id_cmp(&have[i], &want[i]) == 0)
			continue;
		got_sha1_digest_to_str(want[i].sha1, hashstr, sizeof(hashstr));
		n = snprintf(buf, sizeof(buf), "want %s%s\n", hashstr,
		   sent_my_capabilites ? "" : my_capabilities);
		if (n >= sizeof(buf)) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
		err = writepkt(fd, buf, n);
		if (err)
			goto done;
		nwant++;
	}
	err = flushpkt(fd);
	if (err)
		goto done;

	if (nwant == 0)
		goto done;

	for (i = 0; i < nref; i++) {
		if (got_object_id_cmp(&have[i], &zhash) == 0)
			continue;
		got_sha1_digest_to_str(have[i].sha1, hashstr, sizeof(hashstr));
		n = snprintf(buf, sizeof(buf), "have %s\n", hashstr);
		if (n >= sizeof(buf)) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
		err = writepkt(fd, buf, n + 1);
		if (err)
			goto done;
		nhave++;
	}

	while (nhave > 0 && !acked) {
		struct got_object_id common_id;

		/* The server should ACK the object IDs we need. */
		err = readpkt(&n, fd, buf, sizeof(buf));
		if (err)
			goto done;
		if (n >= 4 && strncmp(buf, "ERR ", 4) == 0) {
			err = fetch_error(&buf[4], n - 4);
			goto done;
		}
		if (n >= 4 && strncmp(buf, "NAK\n", 4) == 0) {
			/* Server has not located our objects yet. */
			continue;
		}
		if (n < 4 + SHA1_DIGEST_STRING_LENGTH ||
		    strncmp(buf, "ACK ", 4) != 0) {
			err = got_error_msg(GOT_ERR_BAD_PACKET,
			    "unexpected message from server");
			goto done;
		}
		if (!got_parse_sha1_digest(common_id.sha1, buf + 4)) {
			err = got_error_msg(GOT_ERR_BAD_PACKET,
			    "bad object ID in ACK packet from server");
			goto done;
		}
		acked++;
	}

	n = snprintf(buf, sizeof(buf), "done\n");
	err = writepkt(fd, buf, n);
	if (err)
		goto done;

	if (nhave == 0) {
		err = readpkt(&n, fd, buf, sizeof(buf));
		if (err)
			goto done;
		if (n != 4 || strncmp(buf, "NAK\n", n) != 0) {
			err = got_error_msg(GOT_ERR_BAD_PACKET,
			    "unexpected message from server");
			goto done;
		}
	}

	if (my_capabilities != NULL &&
	    strstr(my_capabilities, GOT_CAPA_SIDE_BAND_64K) != NULL)
		have_sidebands = 1;

	while (1) {
		ssize_t r = 0, w;
		int datalen = -1;

		if (have_sidebands) {
			err = read_pkthdr(&datalen, fd);
			if (err)
				goto done;
			if (datalen <= 0)
				break;

			/* Read sideband channel ID (one byte). */
			r = read(fd, buf, 1);
			if (r == -1) {
				err = got_error_from_errno("read");
				goto done;
			}
			if (r != 1) {
				err = got_error_msg(GOT_ERR_BAD_PACKET,
				    "short packet");
				goto done;
			}
			if (datalen > sizeof(buf) - 5) {
				err = got_error_msg(GOT_ERR_BAD_PACKET,
				    "bad packet length");
				goto done;
			}
			datalen--; /* sideband ID has been read */
			if (buf[0] == GOT_SIDEBAND_PACKFILE_DATA) {
				/* Read packfile data. */
				err = readn(&r, fd, buf, datalen);
				if (err)
					goto done;
				if (r != datalen) {
					err = got_error_msg(GOT_ERR_BAD_PACKET,
					    "packet too short");
					goto done;
				}
			} else if (buf[0] == GOT_SIDEBAND_PROGRESS_INFO) {
				err = readn(&r, fd, buf, datalen);
				if (err)
					goto done;
				if (r != datalen) {
					err = got_error_msg(GOT_ERR_BAD_PACKET,
					    "packet too short");
					goto done;
				}
				err = fetch_progress(ibuf, buf, r);
				if (err)
					goto done;
				continue;
			} else if (buf[0] == GOT_SIDEBAND_ERROR_INFO) {
				err = readn(&r, fd, buf, datalen);
				if (err)
					goto done;
				if (r != datalen) {
					err = got_error_msg(GOT_ERR_BAD_PACKET,
					    "packet too short");
					goto done;
				}
				err = fetch_error(buf, r);
				goto done;
			} else {
				err = got_error_msg(GOT_ERR_BAD_PACKET,
				    "unknown side-band received from server");
				goto done;
			}
		} else {
			/* No sideband channel. Every byte is packfile data. */
			err = readn(&r, fd, buf, sizeof buf);
			if (err)
				goto done;
			if (r <= 0)
				break;
		}

		/* Write packfile data to temporary pack file. */
		w = write(packfd, buf, r);
		if (w == -1) {
			err = got_error_from_errno("write");
			goto done;
		}
		if (w != r) {
			err = got_error(GOT_ERR_IO);
			goto done;
		}
		packsz += w;

		/* Don't send too many progress privsep messages. */
		if (packsz > last_reported_packsz + 1024) {
			err = got_privsep_send_fetch_download_progress(ibuf,
			    packsz);
			if (err)
				goto done;
			last_reported_packsz = packsz;
		}
	}
	err = got_privsep_send_fetch_download_progress(ibuf, packsz);
	if (err)
		goto done;
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
	int fetchfd, packfd = -1, i;
	struct got_object_id packid;
	struct imsgbuf ibuf;
	struct imsg imsg;
	struct got_pathlist_head have_refs;
	struct got_pathlist_entry *pe;
	struct got_imsg_fetch_have_refs *fetch_have_refs = NULL;
	struct got_imsg_fetch_have_ref *href = NULL;
	size_t datalen;
#if 0
	static int attached;
	while (!attached)
		sleep (1);
#endif

	TAILQ_INIT(&have_refs);

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
	if (datalen < sizeof(struct got_imsg_fetch_have_refs) +
	    sizeof(struct got_imsg_fetch_have_ref) *
	    fetch_have_refs->n_have_refs) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	href = (struct got_imsg_fetch_have_ref *)(
	    (uint8_t *)fetch_have_refs + sizeof(fetch_have_refs->n_have_refs));
	for (i = 0; i < fetch_have_refs->n_have_refs; i++) {
		struct got_object_id *id;
		char *refname;

		if (datalen < sizeof(*href) + href->name_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
		datalen -= sizeof(*href) + href->name_len;
		refname = strndup((uint8_t *)href + sizeof(href->id) +
		    sizeof(href->name_len), href->name_len);
		if (refname == NULL) {
			err = got_error_from_errno("strndump");
			goto done;
		}
		id = malloc(sizeof(*id));
		if (id == NULL) {
			free(refname);
			err = got_error_from_errno("malloc");
			goto done;
		}
		memcpy(id->sha1, href->id, SHA1_DIGEST_LENGTH);
		err = got_pathlist_append(&have_refs, refname, id);
		if (err) {
			free(refname);
			free(id);
			goto done;
		}
		href = (struct got_imsg_fetch_have_ref *)(
		    (uint8_t *)href + sizeof(*href) + href->name_len);
		}
	fetchfd = imsg.fd;

	if ((err = got_privsep_recv_imsg(&imsg, &ibuf, 0)) != 0) {
		if (err->code == GOT_ERR_PRIVSEP_PIPE)
			err = NULL;
		goto done;
	}
	if (imsg.hdr.type == GOT_IMSG_STOP)
		goto done;
	if (imsg.hdr.type != GOT_IMSG_FETCH_OUTFD) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}
	if (imsg.hdr.len - IMSG_HEADER_SIZE != 0) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	packfd = imsg.fd;

	err = fetch_pack(fetchfd, packfd, &packid, &have_refs, &ibuf);
done:
	TAILQ_FOREACH(pe, &have_refs, entry) {
		free((char *)pe->path);
		free(pe->data);
	}
	got_pathlist_free(&have_refs);
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
