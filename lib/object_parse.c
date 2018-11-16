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
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/syslimits.h>
#include <sys/wait.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sha1.h>
#include <zlib.h>
#include <ctype.h>
#include <limits.h>
#include <imsg.h>
#include <time.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_opentemp.h"

#include "got_lib_sha1.h"
#include "got_lib_delta.h"
#include "got_lib_privsep.h"
#include "got_lib_pack.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_cache.h"
#include "got_lib_repository.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

#define GOT_COMMIT_TAG_TREE		"tree "
#define GOT_COMMIT_TAG_PARENT		"parent "
#define GOT_COMMIT_TAG_AUTHOR		"author "
#define GOT_COMMIT_TAG_COMMITTER	"committer "

int
got_object_id_cmp(const struct got_object_id *id1,
    const struct got_object_id *id2)
{
	return memcmp(id1->sha1, id2->sha1, SHA1_DIGEST_LENGTH);
}

const struct got_error *
got_object_qid_alloc_partial(struct got_object_qid **qid)
{
	const struct got_error *err = NULL;

	*qid = malloc(sizeof(**qid));
	if (*qid == NULL)
		return got_error_from_errno();

	(*qid)->id = malloc(sizeof(*((*qid)->id)));
	if ((*qid)->id == NULL) {
		err = got_error_from_errno();
		got_object_qid_free(*qid);
		*qid = NULL;
		return err;
	}

	return NULL;
}

const struct got_error *
got_object_id_str(char **outbuf, struct got_object_id *id)
{
	static const size_t len = SHA1_DIGEST_STRING_LENGTH;

	*outbuf = malloc(len);
	if (*outbuf == NULL)
		return got_error_from_errno();

	if (got_sha1_digest_to_str(id->sha1, *outbuf, len) == NULL) {
		free(*outbuf);
		*outbuf = NULL;
		return got_error(GOT_ERR_BAD_OBJ_ID_STR);
	}

	return NULL;
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
		while (!SIMPLEQ_EMPTY(&obj->deltas.entries)) {
			delta = SIMPLEQ_FIRST(&obj->deltas.entries);
			SIMPLEQ_REMOVE_HEAD(&obj->deltas.entries, entry);
			got_delta_close(delta);
		}
	}
	if (obj->flags & GOT_OBJ_FLAG_PACKED)
		free(obj->path_packfile);
	free(obj);
}

void
got_object_qid_free(struct got_object_qid *qid)
{
	free(qid->id);
	free(qid);
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

	SIMPLEQ_INIT(&commit->parent_ids);

	return commit;
}

const struct got_error *
got_object_commit_add_parent(struct got_commit_object *commit,
    const char *id_str)
{
	const struct got_error *err = NULL;
	struct got_object_qid *qid;

	err = got_object_qid_alloc_partial(&qid);
	if (err)
		return err;

	if (!got_parse_sha1_digest(qid->id->sha1, id_str)) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		free(qid->id);
		free(qid);
		return err;
	}

	SIMPLEQ_INSERT_TAIL(&commit->parent_ids, qid, entry);
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
	if (!isdigit(*p) && !isdigit(*(p + 1)))
		return got_error(GOT_ERR_BAD_OBJ_DATA);
	h = (((*p - '0') * 10) + (*(p + 1) - '0'));

	p += 2;
	if (!isdigit(*p) && !isdigit(*(p + 1)))
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
		return got_error_from_errno();
	err = parse_gmtoff(gmtoff, tzstr);
	free(tzstr);
	if (err)
		return err;
	*space = '\0';

	/* Timestamp is separated from committer name + email by space. */
	space = strrchr(committer, ' ');
	if (space == NULL)
		return got_error(GOT_ERR_BAD_OBJ_DATA);

	/* Timestamp parsed here is expressed in comitter's local time. */
	*time = strtonum(space + 1, 0, INT64_MAX, &errstr);
	if (errstr)
		return got_error(GOT_ERR_BAD_OBJ_DATA);

	/* Express the time stamp in UTC. */
	*time -= *gmtoff;

	/* Strip off parsed time information, leaving just author and email. */
	*space = '\0';

	return NULL;
}

void
got_object_commit_close(struct got_commit_object *commit)
{
	struct got_object_qid *qid;

	if (commit->refcnt > 0) {
		commit->refcnt--;
		if (commit->refcnt > 0)
			return;
	}

	while (!SIMPLEQ_EMPTY(&commit->parent_ids)) {
		qid = SIMPLEQ_FIRST(&commit->parent_ids);
		SIMPLEQ_REMOVE_HEAD(&commit->parent_ids, entry);
		got_object_qid_free(qid);
	}

	free(commit->tree_id);
	free(commit->author);
	free(commit->committer);
	free(commit->logmsg);
	free(commit);
}

const struct got_error *
got_object_parse_commit(struct got_commit_object **commit, char *buf, size_t len)
{
	const struct got_error *err = NULL;
	char *s = buf;
	size_t tlen;
	ssize_t remain = (ssize_t)len;
 
	*commit = got_object_commit_alloc_partial();
	if (*commit == NULL)
		return got_error_from_errno();

	tlen = strlen(GOT_COMMIT_TAG_TREE);
	if (strncmp(s, GOT_COMMIT_TAG_TREE, tlen) == 0) {
		remain -= tlen;
		if (remain < SHA1_DIGEST_STRING_LENGTH) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s += tlen;
		if (!got_parse_sha1_digest((*commit)->tree_id->sha1, s)) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		remain -= SHA1_DIGEST_STRING_LENGTH;
		s += SHA1_DIGEST_STRING_LENGTH;
	} else {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	tlen = strlen(GOT_COMMIT_TAG_PARENT);
	while (strncmp(s, GOT_COMMIT_TAG_PARENT, tlen) == 0) {
		remain -= tlen;
		if (remain < SHA1_DIGEST_STRING_LENGTH) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s += tlen;
		err = got_object_commit_add_parent(*commit, s);
		if (err)
			goto done;

		remain -= SHA1_DIGEST_STRING_LENGTH;
		s += SHA1_DIGEST_STRING_LENGTH;
	}

	tlen = strlen(GOT_COMMIT_TAG_AUTHOR);
	if (strncmp(s, GOT_COMMIT_TAG_AUTHOR, tlen) == 0) {
		char *p;
		size_t slen;

		remain -= tlen;
		if (remain <= 0) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s += tlen;
		p = strchr(s, '\n');
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
			err = got_error_from_errno();
			goto done;
		}
		s += slen + 1;
		remain -= slen + 1;
	}

	tlen = strlen(GOT_COMMIT_TAG_COMMITTER);
	if (strncmp(s, GOT_COMMIT_TAG_COMMITTER, tlen) == 0) {
		char *p;
		size_t slen;

		remain -= tlen;
		if (remain <= 0) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s += tlen;
		p = strchr(s, '\n');
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
			err = got_error_from_errno();
			goto done;
		}
		s += slen + 1;
		remain -= slen + 1;
	}

	(*commit)->logmsg = strndup(s, remain);
	if ((*commit)->logmsg == NULL) {
		err = got_error_from_errno();
		goto done;
	}
done:
	if (err) {
		got_object_commit_close(*commit);
		*commit = NULL;
	}
	return err;
}

void
got_object_tree_entry_close(struct got_tree_entry *te)
{
	free(te->id);
	free(te->name);
	free(te);
}

void
got_object_tree_close(struct got_tree_object *tree)
{
	struct got_tree_entry *te;

	if (tree->refcnt > 0) {
		tree->refcnt--;
		if (tree->refcnt > 0)
			return;
	}

	while (!SIMPLEQ_EMPTY(&tree->entries.head)) {
		te = SIMPLEQ_FIRST(&tree->entries.head);
		SIMPLEQ_REMOVE_HEAD(&tree->entries.head, entry);
		got_object_tree_entry_close(te);
	}

	free(tree);
}

struct got_tree_entry *
got_alloc_tree_entry_partial(void)
{
	struct got_tree_entry *te;

	te = malloc(sizeof(*te));
	if (te == NULL)
		return NULL;

	te->id = malloc(sizeof(*te->id));
	if (te->id == NULL) {
		free(te);
		te = NULL;
	}
	return te;
}

static const struct got_error *
parse_tree_entry(struct got_tree_entry **te, size_t *elen, char *buf,
    size_t maxlen)
{
	char *p = buf, *space;
	const struct got_error *err = NULL;

	*te = got_alloc_tree_entry_partial();
	if (*te == NULL)
		return got_error_from_errno();

	*elen = strlen(buf) + 1;
	if (*elen > maxlen) {
		free(*te);
		*te = NULL;
		return got_error(GOT_ERR_BAD_OBJ_DATA);
	}

	space = strchr(buf, ' ');
	if (space == NULL) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		free(*te);
		*te = NULL;
		return err;
	}
	(*te)->mode = 0;
	while (*p != ' ') {
		if (*p < '0' && *p > '7') {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		(*te)->mode <<= 3;
		(*te)->mode |= *p - '0';
		p++;
	}

	(*te)->name = strdup(space + 1);
	if (*elen > maxlen || maxlen - *elen < SHA1_DIGEST_LENGTH) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}
	buf += *elen;
	memcpy((*te)->id->sha1, buf, SHA1_DIGEST_LENGTH);
	*elen += SHA1_DIGEST_LENGTH;
done:
	if (err) {
		got_object_tree_entry_close(*te);
		*te = NULL;
	}
	return err;
}

const struct got_error *
got_object_parse_tree(struct got_tree_object **tree, uint8_t *buf, size_t len)
{
	const struct got_error *err;
	size_t remain = len;

	*tree = calloc(1, sizeof(**tree));
	if (*tree == NULL)
		return got_error_from_errno();

	SIMPLEQ_INIT(&(*tree)->entries.head);

	while (remain > 0) {
		struct got_tree_entry *te;
		size_t elen;

		err = parse_tree_entry(&te, &elen, buf, remain);
		if (err)
			return err;
		(*tree)->entries.nentries++;
		SIMPLEQ_INSERT_TAIL(&(*tree)->entries.head, te, entry);
		buf += elen;
		remain -= elen;
	}

	if (remain != 0) {
		got_object_tree_close(*tree);
		return got_error(GOT_ERR_BAD_OBJ_DATA);
	}

	return NULL;
}

const struct got_error *
got_read_file_to_mem(uint8_t **outbuf, size_t *outlen, FILE *f)
{
	const struct got_error *err = NULL;
	static const size_t blocksize = 512;
	size_t n, total, remain;
	uint8_t *buf;

	*outbuf = NULL;
	*outlen = 0;

	buf = malloc(blocksize);
	if (buf == NULL)
		return got_error_from_errno();

	remain = blocksize;
	total = 0;
	while (1) {
		if (remain == 0) {
			uint8_t *newbuf;
			newbuf = reallocarray(buf, 1, total + blocksize);
			if (newbuf == NULL) {
				err = got_error_from_errno();
				goto done;
			}
			buf = newbuf;
			remain += blocksize;
		}
		n = fread(buf + total, 1, remain, f);
		if (n == 0) {
			if (ferror(f)) {
				err = got_ferror(f, GOT_ERR_IO);
				goto done;
			}
			break; /* EOF */
		}
		remain -= n;
		total += n;
	};

done:
	if (err == NULL) {
		*outbuf = buf;
		*outlen = total;
	} else
		free(buf);
	return err;
}
