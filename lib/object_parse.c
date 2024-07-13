/*
 * Copyright (c) 2018, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <zlib.h>
#include <ctype.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_opentemp.h"
#include "got_path.h"

#include "got_lib_hash.h"
#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_object_qid.h"
#include "got_lib_object_cache.h"
#include "got_lib_pack.h"
#include "got_lib_repository.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

const struct got_error *
got_object_type_label(const char **label, int obj_type)
{
	const struct got_error *err = NULL;

	switch (obj_type) {
	case GOT_OBJ_TYPE_BLOB:
		*label = GOT_OBJ_LABEL_BLOB;
		break;
	case GOT_OBJ_TYPE_TREE:
		*label = GOT_OBJ_LABEL_TREE;
		break;
	case GOT_OBJ_TYPE_COMMIT:
		*label = GOT_OBJ_LABEL_COMMIT;
		break;
	case GOT_OBJ_TYPE_TAG:
		*label = GOT_OBJ_LABEL_TAG;
		break;
	default:
		*label = NULL;
		err = got_error(GOT_ERR_OBJ_TYPE);
		break;
	}

	return err;
}

void
got_object_close(struct got_object *obj)
{
	if (obj->refcnt > 0) {
		obj->refcnt--;
		if (obj->refcnt > 0)
			return;
	}

	if (obj->flags & GOT_OBJ_FLAG_DELTIFIED) {
		struct got_delta *delta;
		while (!STAILQ_EMPTY(&obj->deltas.entries)) {
			delta = STAILQ_FIRST(&obj->deltas.entries);
			STAILQ_REMOVE_HEAD(&obj->deltas.entries, entry);
			free(delta);
		}
	}
	free(obj);
}

const struct got_error *
got_object_raw_close(struct got_raw_object *obj)
{
	const struct got_error *err = NULL;

	if (obj->refcnt > 0) {
		obj->refcnt--;
		if (obj->refcnt > 0)
			return NULL;
	}

	if (obj->close_cb)
		obj->close_cb(obj);

	if (obj->f == NULL) {
		if (obj->fd != -1) {
			if (munmap(obj->data, obj->hdrlen + obj->size) == -1)
				err = got_error_from_errno("munmap");
			if (close(obj->fd) == -1 && err == NULL)
				err = got_error_from_errno("close");
		} else
			free(obj->data);
	} else {
		if (fclose(obj->f) == EOF && err == NULL)
			err = got_error_from_errno("fclose");
	}
	free(obj);
	return err;
}

const struct got_error *
got_object_parse_header(struct got_object **obj, char *buf, size_t len)
{
	const char *obj_labels[] = {
		GOT_OBJ_LABEL_COMMIT,
		GOT_OBJ_LABEL_TREE,
		GOT_OBJ_LABEL_BLOB,
		GOT_OBJ_LABEL_TAG,
	};
	const int obj_types[] = {
		GOT_OBJ_TYPE_COMMIT,
		GOT_OBJ_TYPE_TREE,
		GOT_OBJ_TYPE_BLOB,
		GOT_OBJ_TYPE_TAG,
	};
	int type = 0;
	size_t size = 0;
	size_t i;
	char *end;

	*obj = NULL;

	end = memchr(buf, '\0', len);
	if (end == NULL)
		return got_error(GOT_ERR_BAD_OBJ_HDR);

	for (i = 0; i < nitems(obj_labels); i++) {
		const char *label = obj_labels[i];
		size_t label_len = strlen(label);
		const char *errstr;

		if (len <= label_len || buf + label_len >= end ||
		    strncmp(buf, label, label_len) != 0)
			continue;

		type = obj_types[i];
		size = strtonum(buf + label_len, 0, LONG_MAX, &errstr);
		if (errstr != NULL)
			return got_error(GOT_ERR_BAD_OBJ_HDR);
		break;
	}

	if (type == 0)
		return got_error(GOT_ERR_BAD_OBJ_HDR);

	*obj = calloc(1, sizeof(**obj));
	if (*obj == NULL)
		return got_error_from_errno("calloc");
	(*obj)->type = type;
	(*obj)->hdrlen = end - buf + 1;
	(*obj)->size = size;
	return NULL;
}

const struct got_error *
got_object_read_header(struct got_object **obj, int fd)
{
	const struct got_error *err;
	struct got_inflate_buf zb;
	uint8_t *buf;
	const size_t zbsize = 64;
	size_t outlen, totlen;
	int nbuf = 1;

	*obj = NULL;

	buf = malloc(zbsize);
	if (buf == NULL)
		return got_error_from_errno("malloc");
	buf[0] = '\0';

	err = got_inflate_init(&zb, buf, zbsize, NULL);
	if (err)
		return err;

	totlen = 0;
	do {
		err = got_inflate_read_fd(&zb, fd, &outlen, NULL);
		if (err)
			goto done;
		if (outlen == 0)
			break;
		totlen += outlen;
		if (memchr(zb.outbuf, '\0', outlen) == NULL) {
			uint8_t *newbuf;
			nbuf++;
			newbuf = recallocarray(buf, nbuf - 1, nbuf, zbsize);
			if (newbuf == NULL) {
				err = got_error_from_errno("recallocarray");
				goto done;
			}
			buf = newbuf;
			zb.outbuf = newbuf + totlen;
			zb.outlen = (nbuf * zbsize) - totlen;
		}
	} while (memchr(zb.outbuf, '\0', outlen) == NULL);

	err = got_object_parse_header(obj, buf, totlen);
done:
	free(buf);
	got_inflate_end(&zb);
	return err;
}

const struct got_error *
got_object_read_raw(uint8_t **outbuf, off_t *size, size_t *hdrlen,
    size_t max_in_mem_size, int outfd, struct got_object_id *expected_id,
    int infd)
{
	const struct got_error *err = NULL;
	struct got_object *obj;
	struct got_inflate_checksum csum;
	struct got_object_id id;
	struct got_hash ctx;
	size_t len, consumed;
	FILE *f = NULL;

	*outbuf = NULL;
	*size = 0;
	*hdrlen = 0;

	got_hash_init(&ctx, GOT_HASH_SHA1);
	memset(&csum, 0, sizeof(csum));
	csum.output_ctx = &ctx;

	if (lseek(infd, SEEK_SET, 0) == -1)
		return got_error_from_errno("lseek");

	err = got_object_read_header(&obj, infd);
	if (err)
		return err;

	if (lseek(infd, SEEK_SET, 0) == -1)
		return got_error_from_errno("lseek");

	if (obj->size + obj->hdrlen <= max_in_mem_size) {
		err = got_inflate_to_mem_fd(outbuf, &len, &consumed, &csum,
		    obj->size + obj->hdrlen, infd);
	} else {
		int fd;
		/*
		 * XXX This uses an extra file descriptor for no good reason.
		 * We should have got_inflate_fd_to_fd().
		 */
		fd = dup(infd);
		if (fd == -1)
			return got_error_from_errno("dup");
		f = fdopen(fd, "r");
		if (f == NULL) {
			err = got_error_from_errno("fdopen");
			close(fd);
			goto done;
		}
		err = got_inflate_to_fd(&len, f, &csum, outfd);
	}
	if (err)
		goto done;

	if (len < obj->hdrlen || len != obj->hdrlen + obj->size) {
		err = got_error(GOT_ERR_BAD_OBJ_HDR);
		goto done;
	}

	got_hash_final_object_id(&ctx, &id);
	if (got_object_id_cmp(expected_id, &id) != 0) {
		err = got_error_checksum(expected_id);
		goto done;
	}

	*size = obj->size;
	*hdrlen = obj->hdrlen;
done:
	got_object_close(obj);
	if (f && fclose(f) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}

struct got_commit_object *
got_object_commit_alloc_partial(void)
{
	struct got_commit_object *commit;

	commit = calloc(1, sizeof(*commit));
	if (commit == NULL)
		return NULL;
	commit->tree_id = malloc(sizeof(*commit->tree_id));
	if (commit->tree_id == NULL) {
		free(commit);
		return NULL;
	}

	STAILQ_INIT(&commit->parent_ids);

	return commit;
}

const struct got_error *
got_object_commit_add_parent(struct got_commit_object *commit,
    const char *id_str, enum got_hash_algorithm algo)
{
	const struct got_error *err = NULL;
	struct got_object_qid *qid;

	err = got_object_qid_alloc_partial(&qid);
	if (err)
		return err;

	if (!got_parse_object_id(&qid->id, id_str, algo)) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		got_object_qid_free(qid);
		return err;
	}

	STAILQ_INSERT_TAIL(&commit->parent_ids, qid, entry);
	commit->nparents++;

	return NULL;
}

static const struct got_error *
parse_gmtoff(time_t *gmtoff, const char *tzstr)
{
	int sign = 1;
	const char *p = tzstr;
	time_t h, m;

	*gmtoff = 0;

	if (*p == '-')
		sign = -1;
	else if (*p != '+')
		return got_error(GOT_ERR_BAD_OBJ_DATA);
	p++;
	if (!isdigit((unsigned char)*p) &&
	    !isdigit((unsigned char)*(p + 1)))
		return got_error(GOT_ERR_BAD_OBJ_DATA);
	h = (((*p - '0') * 10) + (*(p + 1) - '0'));

	p += 2;
	if (!isdigit((unsigned char)*p) &&
	    !isdigit((unsigned char)*(p + 1)))
		return got_error(GOT_ERR_BAD_OBJ_DATA);
	m = ((*p - '0') * 10) + (*(p + 1) - '0');

	*gmtoff = (h * 60 * 60 + m * 60) * sign;
	return NULL;
}

static const struct got_error *
parse_commit_time(time_t *time, time_t *gmtoff, char *committer)
{
	const struct got_error *err = NULL;
	const char *errstr;
	char *space, *tzstr;

	/* Parse and strip off trailing timezone indicator string. */
	space = strrchr(committer, ' ');
	if (space == NULL)
		return got_error(GOT_ERR_BAD_OBJ_DATA);
	tzstr = strdup(space + 1);
	if (tzstr == NULL)
		return got_error_from_errno("strdup");
	err = parse_gmtoff(gmtoff, tzstr);
	free(tzstr);
	if (err) {
		if (err->code != GOT_ERR_BAD_OBJ_DATA)
			return err;
		/* Old versions of Git omitted the timestamp. */
		*time = 0;
		*gmtoff = 0;
		return NULL;
	}
	*space = '\0';

	/* Timestamp is separated from committer name + email by space. */
	space = strrchr(committer, ' ');
	if (space == NULL)
		return got_error(GOT_ERR_BAD_OBJ_DATA);

	/* Timestamp parsed here is expressed as UNIX timestamp (UTC). */
	*time = strtonum(space + 1, 0, INT64_MAX, &errstr);
	if (errstr)
		return got_error(GOT_ERR_BAD_OBJ_DATA);

	/* Strip off parsed time information, leaving just author and email. */
	*space = '\0';

	return NULL;
}

void
got_object_commit_close(struct got_commit_object *commit)
{
	if (commit->refcnt > 0) {
		commit->refcnt--;
		if (commit->refcnt > 0)
			return;
	}

	got_object_id_queue_free(&commit->parent_ids);
	free(commit->tree_id);
	free(commit->author);
	free(commit->committer);
	free(commit->logmsg);
	free(commit);
}

struct got_object_id *
got_object_commit_get_tree_id(struct got_commit_object *commit)
{
	return commit->tree_id;
}

int
got_object_commit_get_nparents(struct got_commit_object *commit)
{
	return commit->nparents;
}

const struct got_object_id_queue *
got_object_commit_get_parent_ids(struct got_commit_object *commit)
{
	return &commit->parent_ids;
}

const char *
got_object_commit_get_author(struct got_commit_object *commit)
{
	return commit->author;
}

time_t
got_object_commit_get_author_time(struct got_commit_object *commit)
{
	return commit->author_time;
}

time_t got_object_commit_get_author_gmtoff(struct got_commit_object *commit)
{
	return commit->author_gmtoff;
}

const char *
got_object_commit_get_committer(struct got_commit_object *commit)
{
	return commit->committer;
}

time_t
got_object_commit_get_committer_time(struct got_commit_object *commit)
{
	return commit->committer_time;
}

time_t
got_object_commit_get_committer_gmtoff(struct got_commit_object *commit)
{
	return commit->committer_gmtoff;
}

const struct got_error *
got_object_commit_get_logmsg(char **logmsg, struct got_commit_object *commit)
{
	const struct got_error *err = NULL;
	const char *src;
	char *dst;
	size_t len;

	len = strlen(commit->logmsg);
	*logmsg = malloc(len + 2); /* leave room for a trailing \n and \0 */
	if (*logmsg == NULL)
		return got_error_from_errno("malloc");

	/*
	 * Strip out unusual headers. Headers are separated from the commit
	 * message body by a single empty line.
	 */
	src = commit->logmsg;
	dst = *logmsg;
	while (*src != '\0' && *src != '\n') {
		int copy_header = 1, eol = 0;
		if (strncmp(src, GOT_COMMIT_LABEL_TREE,
		    strlen(GOT_COMMIT_LABEL_TREE)) != 0 &&
		    strncmp(src, GOT_COMMIT_LABEL_AUTHOR,
		    strlen(GOT_COMMIT_LABEL_AUTHOR)) != 0 &&
		    strncmp(src, GOT_COMMIT_LABEL_PARENT,
		    strlen(GOT_COMMIT_LABEL_PARENT)) != 0 &&
		    strncmp(src, GOT_COMMIT_LABEL_COMMITTER,
		    strlen(GOT_COMMIT_LABEL_COMMITTER)) != 0)
			copy_header = 0;

		while (*src != '\0' && !eol) {
			if (copy_header) {
				*dst = *src;
				dst++;
			}
			if (*src == '\n')
				eol = 1;
			src++;
		}
	}
	*dst = '\0';

	if (strlcat(*logmsg, src, len + 1) >= len + 1) {
		err = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}

	/* Trim redundant trailing whitespace. */
	len = strlen(*logmsg);
	while (len > 1 && isspace((unsigned char)(*logmsg)[len - 2]) &&
	    isspace((unsigned char)(*logmsg)[len - 1])) {
		(*logmsg)[len - 1] = '\0';
		len--;
	}

	/* Append a trailing newline if missing. */
	if (len > 0 && (*logmsg)[len - 1] != '\n') {
		(*logmsg)[len] = '\n';
		(*logmsg)[len + 1] = '\0';
	}
done:
	if (err) {
		free(*logmsg);
		*logmsg = NULL;
	}
	return err;
}

const char *
got_object_commit_get_logmsg_raw(struct got_commit_object *commit)
{
	return commit->logmsg;
}

const struct got_error *
got_object_parse_commit(struct got_commit_object **commit, char *buf,
    size_t len, enum got_hash_algorithm algo)
{
	const struct got_error *err = NULL;
	char *s = buf;
	size_t label_len, digest_string_len;
	ssize_t remain = (ssize_t)len;

	digest_string_len = got_hash_digest_string_length(algo);

	if (remain == 0)
		return got_error(GOT_ERR_BAD_OBJ_DATA);

	*commit = got_object_commit_alloc_partial();
	if (*commit == NULL)
		return got_error_from_errno("got_object_commit_alloc_partial");

	label_len = strlen(GOT_COMMIT_LABEL_TREE);
	if (strncmp(s, GOT_COMMIT_LABEL_TREE, label_len) == 0) {
		remain -= label_len;
		if (remain < digest_string_len) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s += label_len;
		if (!got_parse_object_id((*commit)->tree_id, s, algo)) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		remain -= digest_string_len;
		s += digest_string_len;
	} else {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	label_len = strlen(GOT_COMMIT_LABEL_PARENT);
	while (strncmp(s, GOT_COMMIT_LABEL_PARENT, label_len) == 0) {
		remain -= label_len;
		if (remain < digest_string_len) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s += label_len;
		err = got_object_commit_add_parent(*commit, s, algo);
		if (err)
			goto done;

		remain -= digest_string_len;
		s += digest_string_len;
	}

	label_len = strlen(GOT_COMMIT_LABEL_AUTHOR);
	if (strncmp(s, GOT_COMMIT_LABEL_AUTHOR, label_len) == 0) {
		char *p;
		size_t slen;

		remain -= label_len;
		if (remain <= 0) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s += label_len;
		p = memchr(s, '\n', remain);
		if (p == NULL) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		*p = '\0';
		slen = strlen(s);
		err = parse_commit_time(&(*commit)->author_time,
		    &(*commit)->author_gmtoff, s);
		if (err)
			goto done;
		(*commit)->author = strdup(s);
		if ((*commit)->author == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
		s += slen + 1;
		remain -= slen + 1;
	}

	label_len = strlen(GOT_COMMIT_LABEL_COMMITTER);
	if (strncmp(s, GOT_COMMIT_LABEL_COMMITTER, label_len) == 0) {
		char *p;
		size_t slen;

		remain -= label_len;
		if (remain <= 0) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s += label_len;
		p = memchr(s, '\n', remain);
		if (p == NULL) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		*p = '\0';
		slen = strlen(s);
		err = parse_commit_time(&(*commit)->committer_time,
		    &(*commit)->committer_gmtoff, s);
		if (err)
			goto done;
		(*commit)->committer = strdup(s);
		if ((*commit)->committer == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
		s += slen + 1;
		remain -= slen + 1;
	}

	(*commit)->logmsg = strndup(s, remain);
	if ((*commit)->logmsg == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
done:
	if (err) {
		got_object_commit_close(*commit);
		*commit = NULL;
	}
	return err;
}

const struct got_error *
got_object_read_commit(struct got_commit_object **commit, int fd,
    struct got_object_id *expected_id, size_t expected_size)
{
	struct got_object *obj = NULL;
	const struct got_error *err = NULL;
	size_t len;
	uint8_t *p;
	struct got_inflate_checksum csum;
	struct got_hash ctx;
	struct got_object_id id;

	got_hash_init(&ctx, GOT_HASH_SHA1);
	memset(&csum, 0, sizeof(csum));
	csum.output_ctx = &ctx;

	err = got_inflate_to_mem_fd(&p, &len, NULL, &csum, expected_size, fd);
	if (err)
		return err;

	got_hash_final_object_id(&ctx, &id);
	if (got_object_id_cmp(expected_id, &id) != 0) {
		err = got_error_checksum(expected_id);
		goto done;
	}

	err = got_object_parse_header(&obj, p, len);
	if (err)
		goto done;

	if (len < obj->hdrlen + obj->size) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	if (obj->type != GOT_OBJ_TYPE_COMMIT) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	/* Skip object header. */
	len -= obj->hdrlen;
	err = got_object_parse_commit(commit, p + obj->hdrlen, len,
	    GOT_HASH_SHA1);
done:
	free(p);
	if (obj)
		got_object_close(obj);
	return err;
}

void
got_object_tree_close(struct got_tree_object *tree)
{
	if (tree->refcnt > 0) {
		tree->refcnt--;
		if (tree->refcnt > 0)
			return;
	}

	free(tree->entries);
	free(tree);
}

const struct got_error *
got_object_parse_tree_entry(struct got_parsed_tree_entry *pte, size_t *elen,
    char *buf, size_t maxlen, size_t idlen, enum got_hash_algorithm algo)
{
	char *p, *space;

	*elen = 0;

	*elen = strnlen(buf, maxlen) + 1;
	if (*elen > maxlen)
		return got_error(GOT_ERR_BAD_OBJ_DATA);

	space = memchr(buf, ' ', *elen);
	if (space == NULL || space <= buf)
		return got_error(GOT_ERR_BAD_OBJ_DATA);

	pte->mode = 0;
	p = buf;
	while (p < space) {
		if (*p < '0' || *p > '7')
			return got_error(GOT_ERR_BAD_OBJ_DATA);
		pte->mode <<= 3;
		pte->mode |= *p - '0';
		p++;
	}

	if (*elen > maxlen || maxlen - *elen < idlen)
		return got_error(GOT_ERR_BAD_OBJ_DATA);

	pte->name = space + 1;
	pte->namelen = strlen(pte->name);
	buf += *elen;
	pte->id = buf;
	pte->idlen = idlen;
	pte->algo = algo;
	*elen += idlen;
	return NULL;
}

static int
pte_cmp(const void *pa, const void *pb)
{
	const struct got_parsed_tree_entry *a = pa, *b = pb;

	return got_path_cmp(a->name, b->name, a->namelen, b->namelen);
}

const struct got_error *
got_object_parse_tree(struct got_parsed_tree_entry **entries, size_t *nentries,
    size_t *nentries_alloc, uint8_t *buf, size_t len,
    enum got_hash_algorithm algo)
{
	const struct got_error *err = NULL;
	size_t digest_len, remain = len;
	const size_t nalloc = 16;
	struct got_parsed_tree_entry *pte;
	int i;

	digest_len = got_hash_digest_length(algo);

	*nentries = 0;
	if (remain == 0)
		return NULL; /* tree is empty */

	while (remain > 0) {
		size_t elen;

		if (*nentries >= *nentries_alloc) {
			pte = recallocarray(*entries, *nentries_alloc,
			    *nentries_alloc + nalloc, sizeof(**entries));
			if (pte == NULL) {
				err = got_error_from_errno("recallocarray");
				goto done;
			}
			*entries = pte;
			*nentries_alloc += nalloc;
		}

		pte = &(*entries)[*nentries];
		err = got_object_parse_tree_entry(pte, &elen, buf, remain,
		    digest_len, algo);
		if (err)
			goto done;
		buf += elen;
		remain -= elen;
		(*nentries)++;
	}

	if (remain != 0) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	if (*nentries > 1) {
		mergesort(*entries, *nentries, sizeof(**entries), pte_cmp);

		for (i = 0; i < *nentries - 1; i++) {
			struct got_parsed_tree_entry *prev = &(*entries)[i];
			pte = &(*entries)[i + 1];
			if (got_path_cmp(prev->name, pte->name,
			    prev->namelen, pte->namelen) == 0) {
				err = got_error(GOT_ERR_TREE_DUP_ENTRY);
				break;
			}
		}
	}
done:
	if (err)
		*nentries = 0;
	return err;
}

const struct got_error *
got_object_read_tree(struct got_parsed_tree_entry **entries, size_t *nentries,
    size_t *nentries_alloc, uint8_t **p, int fd,
    struct got_object_id *expected_id)
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL;
	size_t len;
	struct got_inflate_checksum csum;
	struct got_hash ctx;
	struct got_object_id id;

	got_hash_init(&ctx, GOT_HASH_SHA1);
	memset(&csum, 0, sizeof(csum));
	csum.output_ctx = &ctx;

	err = got_inflate_to_mem_fd(p, &len, NULL, &csum, 0, fd);
	if (err)
		return err;

	got_hash_final_object_id(&ctx, &id);
	if (got_object_id_cmp(expected_id, &id) != 0) {
		err = got_error_checksum(expected_id);
		goto done;
	}

	err = got_object_parse_header(&obj, *p, len);
	if (err)
		goto done;

	if (len < obj->hdrlen + obj->size) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	/* Skip object header. */
	len -= obj->hdrlen;
	err = got_object_parse_tree(entries, nentries, nentries_alloc,
	    *p + obj->hdrlen, len, GOT_HASH_SHA1);
done:
	if (obj)
		got_object_close(obj);
	return err;
}

void
got_object_tag_close(struct got_tag_object *tag)
{
	if (tag->refcnt > 0) {
		tag->refcnt--;
		if (tag->refcnt > 0)
			return;
	}

	free(tag->tag);
	free(tag->tagger);
	free(tag->tagmsg);
	free(tag);
}

const struct got_error *
got_object_parse_tag(struct got_tag_object **tag, uint8_t *buf, size_t len,
    enum got_hash_algorithm algo)
{
	const struct got_error *err = NULL;
	size_t remain = len;
	char *s = buf;
	size_t label_len, digest_string_len;

	digest_string_len = got_hash_digest_string_length(algo);

	if (remain == 0)
		return got_error(GOT_ERR_BAD_OBJ_DATA);

	*tag = calloc(1, sizeof(**tag));
	if (*tag == NULL)
		return got_error_from_errno("calloc");

	label_len = strlen(GOT_TAG_LABEL_OBJECT);
	if (strncmp(s, GOT_TAG_LABEL_OBJECT, label_len) == 0) {
		remain -= label_len;
		if (remain < digest_string_len) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s += label_len;
		if (!got_parse_object_id(&(*tag)->id, s, algo)) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		remain -= digest_string_len;
		s += digest_string_len;
	} else {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	if (remain <= 0) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	label_len = strlen(GOT_TAG_LABEL_TYPE);
	if (strncmp(s, GOT_TAG_LABEL_TYPE, label_len) == 0) {
		remain -= label_len;
		if (remain <= 0) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s += label_len;
		if (strncmp(s, GOT_OBJ_LABEL_COMMIT,
		    strlen(GOT_OBJ_LABEL_COMMIT)) == 0) {
			(*tag)->obj_type = GOT_OBJ_TYPE_COMMIT;
			label_len = strlen(GOT_OBJ_LABEL_COMMIT);
			s += label_len;
			remain -= label_len;
		} else if (strncmp(s, GOT_OBJ_LABEL_TREE,
		    strlen(GOT_OBJ_LABEL_TREE)) == 0) {
			(*tag)->obj_type = GOT_OBJ_TYPE_TREE;
			label_len = strlen(GOT_OBJ_LABEL_TREE);
			s += label_len;
			remain -= label_len;
		} else if (strncmp(s, GOT_OBJ_LABEL_BLOB,
		    strlen(GOT_OBJ_LABEL_BLOB)) == 0) {
			(*tag)->obj_type = GOT_OBJ_TYPE_BLOB;
			label_len = strlen(GOT_OBJ_LABEL_BLOB);
			s += label_len;
			remain -= label_len;
		} else if (strncmp(s, GOT_OBJ_LABEL_TAG,
		    strlen(GOT_OBJ_LABEL_TAG)) == 0) {
			(*tag)->obj_type = GOT_OBJ_TYPE_TAG;
			label_len = strlen(GOT_OBJ_LABEL_TAG);
			s += label_len;
			remain -= label_len;
		} else {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}

		if (remain <= 0 || *s != '\n') {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s++;
		remain--;
		if (remain <= 0) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
	} else {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	label_len = strlen(GOT_TAG_LABEL_TAG);
	if (strncmp(s, GOT_TAG_LABEL_TAG, label_len) == 0) {
		char *p;
		size_t slen;
		remain -= label_len;
		if (remain <= 0) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s += label_len;
		p = memchr(s, '\n', remain);
		if (p == NULL) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		*p = '\0';
		slen = strlen(s);
		(*tag)->tag = strndup(s, slen);
		if ((*tag)->tag == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		s += slen + 1;
		remain -= slen + 1;
		if (remain <= 0) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
	} else {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	label_len = strlen(GOT_TAG_LABEL_TAGGER);
	if (strncmp(s, GOT_TAG_LABEL_TAGGER, label_len) == 0) {
		char *p;
		size_t slen;

		remain -= label_len;
		if (remain <= 0) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s += label_len;
		p = memchr(s, '\n', remain);
		if (p == NULL) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		*p = '\0';
		slen = strlen(s);
		err = parse_commit_time(&(*tag)->tagger_time,
		    &(*tag)->tagger_gmtoff, s);
		if (err)
			goto done;
		(*tag)->tagger = strdup(s);
		if ((*tag)->tagger == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
		s += slen + 1;
		remain -= slen + 1;
		if (remain < 0) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
	} else {
		/* Some old tags in the Linux git repo have no tagger. */
		(*tag)->tagger = strdup("");
		if ((*tag)->tagger == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}

	(*tag)->tagmsg = strndup(s, remain);
	if ((*tag)->tagmsg == NULL) {
		err = got_error_from_errno("strndup");
		goto done;
	}
done:
	if (err) {
		got_object_tag_close(*tag);
		*tag = NULL;
	}
	return err;
}

const struct got_error *
got_object_read_tag(struct got_tag_object **tag, int fd,
    struct got_object_id *expected_id, size_t expected_size)
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL;
	size_t len;
	uint8_t *p;
	struct got_inflate_checksum csum;
	struct got_hash ctx;
	struct got_object_id id;

	got_hash_init(&ctx, GOT_HASH_SHA1);
	memset(&csum, 0, sizeof(csum));
	csum.output_ctx = &ctx;

	err = got_inflate_to_mem_fd(&p, &len, NULL, &csum,
	    expected_size, fd);
	if (err)
		return err;

	got_hash_final_object_id(&ctx, &id);
	if (got_object_id_cmp(expected_id, &id) != 0) {
		err = got_error_checksum(expected_id);
		goto done;
	}

	err = got_object_parse_header(&obj, p, len);
	if (err)
		goto done;

	if (len < obj->hdrlen + obj->size) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	/* Skip object header. */
	len -= obj->hdrlen;
	err = got_object_parse_tag(tag, p + obj->hdrlen, len,
	    GOT_HASH_SHA1);
done:
	free(p);
	if (obj)
		got_object_close(obj);
	return err;
}
