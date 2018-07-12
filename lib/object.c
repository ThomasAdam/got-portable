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
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
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

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_opentemp.h"

#include "got_lib_sha1.h"
#include "got_lib_delta.h"
#include "got_lib_pack.h"
#include "got_lib_path.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_privsep.h"
#include "got_lib_repository.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

#define GOT_OBJ_TAG_COMMIT	"commit"
#define GOT_OBJ_TAG_TREE	"tree"
#define GOT_OBJ_TAG_BLOB	"blob"

#define GOT_COMMIT_TAG_TREE		"tree "
#define GOT_COMMIT_TAG_PARENT		"parent "
#define GOT_COMMIT_TAG_AUTHOR		"author "
#define GOT_COMMIT_TAG_COMMITTER	"committer "

const struct got_error *
got_object_id_str(char **outbuf, struct got_object_id *id)
{
	static const size_t len = SHA1_DIGEST_STRING_LENGTH;

	*outbuf = calloc(1, len);
	if (*outbuf == NULL)
		return got_error_from_errno();

	if (got_sha1_digest_to_str(id->sha1, *outbuf, len) == NULL) {
		free(*outbuf);
		*outbuf = NULL;
		return got_error(GOT_ERR_BAD_OBJ_ID_STR);
	}

	return NULL;
}

int
got_object_id_cmp(struct got_object_id *id1, struct got_object_id *id2)
{
	return memcmp(id1->sha1, id2->sha1, SHA1_DIGEST_LENGTH);
}

struct got_object_id *
got_object_id_dup(struct got_object_id *id1)
{
	struct got_object_id *id2;

	id2 = malloc(sizeof(*id2));
	if (id2 == NULL)
		return NULL;
	memcpy(id2, id1, sizeof(*id2));
	return id2;
}

struct got_object_id *
got_object_get_id(struct got_object *obj)
{
	return got_object_id_dup(&obj->id);
}

const struct got_error *
got_object_get_id_str(char **outbuf, struct got_object *obj)
{
	return got_object_id_str(outbuf, &obj->id);
}

int
got_object_get_type(struct got_object *obj)
{
	switch (obj->type) {
	case GOT_OBJ_TYPE_COMMIT:
	case GOT_OBJ_TYPE_TREE:
	case GOT_OBJ_TYPE_BLOB:
	case GOT_OBJ_TYPE_TAG:
		return obj->type;
	default:
		abort();
		break;
	}

	/* not reached */
	return 0;
}

static const struct got_error *
parse_object_header(struct got_object **obj, char *buf, size_t len)
{
	const char *obj_tags[] = {
		GOT_OBJ_TAG_COMMIT,
		GOT_OBJ_TAG_TREE,
		GOT_OBJ_TAG_BLOB
	};
	const int obj_types[] = {
		GOT_OBJ_TYPE_COMMIT,
		GOT_OBJ_TYPE_TREE,
		GOT_OBJ_TYPE_BLOB,
	};
	int type = 0;
	size_t size = 0, hdrlen = 0;
	int i;
	char *p = strchr(buf, '\0');

	if (p == NULL)
		return got_error(GOT_ERR_BAD_OBJ_HDR);

	hdrlen = strlen(buf) + 1 /* '\0' */;

	for (i = 0; i < nitems(obj_tags); i++) {
		const char *tag = obj_tags[i];
		size_t tlen = strlen(tag);
		const char *errstr;

		if (strncmp(buf, tag, tlen) != 0)
			continue;

		type = obj_types[i];
		if (len <= tlen)
			return got_error(GOT_ERR_BAD_OBJ_HDR);
		size = strtonum(buf + tlen, 0, LONG_MAX, &errstr);
		if (errstr != NULL)
			return got_error(GOT_ERR_BAD_OBJ_HDR);
		break;
	}

	if (type == 0)
		return got_error(GOT_ERR_BAD_OBJ_HDR);

	*obj = calloc(1, sizeof(**obj));
	if (*obj == NULL)
		return got_error_from_errno();
	(*obj)->type = type;
	(*obj)->hdrlen = hdrlen;
	(*obj)->size = size;
	return NULL;
}

static const struct got_error *
read_object_header(struct got_object **obj, int fd)
{
	const struct got_error *err;
	struct got_zstream_buf zb;
	char *buf;
	const size_t zbsize = 64;
	size_t outlen, totlen;
	int i;

	buf = calloc(zbsize, sizeof(char));
	if (buf == NULL)
		return got_error_from_errno();

	err = got_inflate_init(&zb, NULL, zbsize);
	if (err)
		return err;

	i = 0;
	totlen = 0;
	do {
		err = got_inflate_read_fd(&zb, fd, &outlen);
		if (err)
			goto done;
		if (strchr(zb.outbuf, '\0') == NULL) {
			buf = recallocarray(buf, 1 + i, 2 + i, zbsize);
			if (buf == NULL) {
				err = got_error_from_errno();
				goto done;
			}
		}
		memcpy(buf + totlen, zb.outbuf, outlen);
		totlen += outlen;
		i++;
	} while (strchr(zb.outbuf, '\0') == NULL);

	err = parse_object_header(obj, buf, totlen);
done:
	got_inflate_end(&zb);
	return err;
}

static void
read_object_header_privsep_child(int obj_fd, int imsg_fds[2])
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL;
	struct imsgbuf ibuf;
	int status = 0;

	setproctitle("read object header");
	close(imsg_fds[0]);
	imsg_init(&ibuf, imsg_fds[1]);

	/* revoke access to most system calls */
	if (pledge("stdio", NULL) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	err = read_object_header(&obj, obj_fd);
	if (err)
		goto done;

	err = got_privsep_send_obj(&ibuf, obj, 0);
done:
	if (obj)
		got_object_close(obj);
	if (err) {
		got_privsep_send_error(&ibuf, err);
		status = 1;
	}
	close(obj_fd);
	imsg_clear(&ibuf);
	close(imsg_fds[1]);
	_exit(status);
}

static const struct got_error *
wait_for_child(pid_t pid)
{
	int child_status;

	waitpid(pid, &child_status, 0);

	if (!WIFEXITED(child_status))
		return got_error(GOT_ERR_PRIVSEP_DIED);

	if (WEXITSTATUS(child_status) != 0)
		return got_error(GOT_ERR_PRIVSEP_EXIT);

	return NULL;
}

static const struct got_error *
read_object_header_privsep(struct got_object **obj, int fd)
{
	struct imsgbuf parent_ibuf;
	int imsg_fds[2];
	const struct got_error *err = NULL, *err_child = NULL;
	pid_t pid;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds) == -1)
		return got_error_from_errno();

	pid = fork();
	if (pid == -1)
		return got_error_from_errno();
	else if (pid == 0) {
		read_object_header_privsep_child(fd, imsg_fds);
		/* not reached */
	}

	close(imsg_fds[1]);
	imsg_init(&parent_ibuf, imsg_fds[0]);
	err = got_privsep_recv_obj(obj, &parent_ibuf);
	imsg_clear(&parent_ibuf);
	err_child = wait_for_child(pid);
	close(imsg_fds[0]);
	return err ? err : err_child;
}

static const struct got_error *
object_path(char **path, struct got_object_id *id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *hex;
	char *path_objects = got_repo_get_path_objects(repo);

	*path = NULL;

	if (path_objects == NULL)
		return got_error_from_errno();

	err = got_object_id_str(&hex, id);
	if (err)
		return err;

	if (asprintf(path, "%s/%.2x/%s", path_objects,
	    id->sha1[0], hex + 2) == -1)
		err = got_error_from_errno();

	free(hex);
	free(path_objects);
	return err;
}

static const struct got_error *
open_loose_object(int *fd, struct got_object *obj, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path;

	err = object_path(&path, &obj->id, repo);
	if (err)
		return err;
	*fd = open(path, O_RDONLY | O_NOFOLLOW, GOT_DEFAULT_FILE_MODE);
	if (*fd == -1) {
		err = got_error_from_errno();
		goto done;
	}
done:
	free(path);
	return err;
}

const struct got_error *
got_object_open(struct got_object **obj, struct got_repository *repo,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;
	char *path;
	int fd;

	*obj = got_repo_get_cached_object(repo, id);
	if (*obj != NULL) {
		(*obj)->refcnt++;
		return NULL;
	}

	err = object_path(&path, id, repo);
	if (err)
		return err;

	fd = open(path, O_RDONLY | O_NOFOLLOW, GOT_DEFAULT_FILE_MODE);
	if (fd == -1) {
		if (errno != ENOENT) {
			err = got_error_from_errno();
			goto done;
		}
		err = got_packfile_open_object(obj, id, repo);
		if (err)
			goto done;
		if (*obj == NULL)
			err = got_error(GOT_ERR_NO_OBJ);
	} else {
		err = read_object_header_privsep(obj, fd);
		if (err)
			goto done;
		memcpy((*obj)->id.sha1, id->sha1, SHA1_DIGEST_LENGTH);
	}

	if (err == NULL) {
		(*obj)->refcnt++;
		err = got_repo_cache_object(repo, id, *obj);
	}
done:
	free(path);
	if (fd != -1)
		close(fd);
	return err;

}

const struct got_error *
got_object_open_by_id_str(struct got_object **obj, struct got_repository *repo,
    const char *id_str)
{
	struct got_object_id id;

	if (!got_parse_sha1_digest(id.sha1, id_str))
		return got_error(GOT_ERR_BAD_OBJ_ID_STR);

	return got_object_open(obj, repo, &id);
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

struct got_commit_object *
got_object_commit_alloc_partial(void)
{
	struct got_commit_object *commit;

	commit = calloc(1, sizeof(*commit));
	if (commit == NULL)
		return NULL;
	commit->tree_id = calloc(1, sizeof(*commit->tree_id));
	if (commit->tree_id == NULL) {
		free(commit);
		return NULL;
	}

	SIMPLEQ_INIT(&commit->parent_ids);

	return commit;
}

const struct got_error *
got_object_open_as_commit(struct got_commit_object **commit,
    struct got_repository *repo, struct got_object_id *id)
{
	const struct got_error *err;
	struct got_object *obj;

	*commit = NULL;

	err = got_object_open(&obj, repo, id);
	if (err)
		return err;
	if (got_object_get_type(obj) != GOT_OBJ_TYPE_COMMIT) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_commit_open(commit, repo, obj);
done:
	got_object_close(obj);
	return err;
}

const struct got_error *
got_object_qid_alloc(struct got_object_qid **qid, struct got_object_id *id)
{
	const struct got_error *err = NULL;

	*qid = calloc(1, sizeof(**qid));
	if (*qid == NULL)
		return got_error_from_errno();

	(*qid)->id = got_object_id_dup(id);
	if ((*qid)->id == NULL) {
		err = got_error_from_errno();
		free(*qid);
		*qid = NULL;
		return err;
	}

	return NULL;
}

void
got_object_qid_free(struct got_object_qid *qid)
{
	free(qid->id);
	free(qid);
}

const struct got_error *
got_object_commit_add_parent(struct got_commit_object *commit,
    const char *id_str)
{
	const struct got_error *err = NULL;
	struct got_object_qid *qid;

	qid = calloc(1, sizeof(*qid));
	if (qid == NULL)
		return got_error_from_errno();

	qid->id = calloc(1, sizeof(*qid->id));
	if (qid->id == NULL) {
		err = got_error_from_errno();
		free(qid);
		return err;
	}

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
parse_commit_time(struct tm *tm, char *committer)
{
	const struct got_error *err = NULL;
	const char *errstr;
	char *space, *tzstr;
	time_t gmtoff;
	time_t time;

	/* Parse and strip off trailing timezone indicator string. */
	space = strrchr(committer, ' ');
	if (space == NULL)
		return got_error(GOT_ERR_BAD_OBJ_DATA);
	tzstr = strdup(space + 1);
	if (tzstr == NULL)
		return got_error_from_errno();
	err = parse_gmtoff(&gmtoff, tzstr);
	free(tzstr);
	if (err)
		return err;
	*space = '\0';

	/* Timestamp is separated from committer name + email by space. */
	space = strrchr(committer, ' ');
	if (space == NULL)
		return got_error(GOT_ERR_BAD_OBJ_DATA);

	/* Timestamp parsed here is expressed in comitter's local time. */
	time = strtonum(space + 1, 0, INT64_MAX, &errstr);
	if (errstr)
		return got_error(GOT_ERR_BAD_OBJ_DATA);

	/* Express the time stamp in UTC. */
	memset(tm, 0, sizeof(*tm));
	time -= gmtoff;
	if (localtime_r(&time, tm) == NULL)
		return got_error_from_errno();
	tm->tm_gmtoff = gmtoff;

	/* Strip off parsed time information, leaving just author and email. */
	*space = '\0';

	return NULL;
}

static const struct got_error *
parse_commit_object(struct got_commit_object **commit, char *buf, size_t len)
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
		err = parse_commit_time(&(*commit)->tm_author, s);
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
		err = parse_commit_time(&(*commit)->tm_committer, s);
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

static void
tree_entry_close(struct got_tree_entry *te)
{
	free(te->id);
	free(te->name);
	free(te);
}

struct got_tree_entry *
got_alloc_tree_entry_partial(void)
{
	struct got_tree_entry *te;

	te = calloc(1, sizeof(*te));
	if (te == NULL)
		return NULL;

	te->id = calloc(1, sizeof(*te->id));
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
	buf += strlen(buf) + 1;
	memcpy((*te)->id->sha1, buf, SHA1_DIGEST_LENGTH);
	*elen += SHA1_DIGEST_LENGTH;
done:
	if (err) {
		tree_entry_close(*te);
		*te = NULL;
	}
	return err;
}

static const struct got_error *
parse_tree_object(struct got_tree_object **tree, uint8_t *buf, size_t len)
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

static const struct got_error *
read_to_mem(uint8_t **outbuf, size_t *outlen, FILE *f)
{
	const struct got_error *err = NULL;
	static const size_t blocksize = 512;
	size_t n, total, remain;
	uint8_t *buf;

	*outbuf = NULL;
	*outlen = 0;

	buf = calloc(1, blocksize);
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

static const struct got_error *
read_commit_object(struct got_commit_object **commit, struct got_object *obj,
    FILE *f)
{
	const struct got_error *err = NULL;
	size_t len;
	uint8_t *p;

	if (obj->flags & GOT_OBJ_FLAG_PACKED)
		err = read_to_mem(&p, &len, f);
	else
		err = got_inflate_to_mem(&p, &len, f);
	if (err)
		return err;

	if (len < obj->hdrlen + obj->size) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	/* Skip object header. */
	len -= obj->hdrlen;
	err = parse_commit_object(commit, p + obj->hdrlen, len);
	free(p);
done:
	return err;
}

static void
read_commit_object_privsep_child(struct got_object *obj, int obj_fd,
    int imsg_fds[2])
{
	const struct got_error *err = NULL;
	struct got_commit_object *commit = NULL;
	struct imsgbuf ibuf;
	FILE *f = NULL;
	int status = 0;

	setproctitle("read commit object");
	close(imsg_fds[0]);
	imsg_init(&ibuf, imsg_fds[1]);

	/* revoke access to most system calls */
	if (pledge("stdio", NULL) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	f = fdopen(obj_fd, "rb");
	if (f == NULL) {
		err = got_error_from_errno();
		close(obj_fd);
		goto done;
	}

	err = read_commit_object(&commit, obj, f);
	if (err)
		goto done;

	err = got_privsep_send_commit(&ibuf, commit);
done:
	if (commit)
		got_object_commit_close(commit);
	if (err) {
		got_privsep_send_error(&ibuf, err);
		status = 1;
	}
	if (f)
		fclose(f);
	imsg_clear(&ibuf);
	close(imsg_fds[1]);
	_exit(status);
}

static const struct got_error *
read_commit_object_privsep(struct got_commit_object **commit,
    struct got_repository *repo, struct got_object *obj, int fd)
{
	const struct got_error *err = NULL, *err_child = NULL;
	struct imsgbuf parent_ibuf;
	int imsg_fds[2];
	pid_t pid;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds) == -1)
		return got_error_from_errno();

	pid = fork();
	if (pid == -1)
		return got_error_from_errno();
	else if (pid == 0) {
		read_commit_object_privsep_child(obj, fd, imsg_fds);
		/* not reached */
	}

	close(imsg_fds[1]);
	imsg_init(&parent_ibuf, imsg_fds[0]);
	err = got_privsep_recv_commit(commit, &parent_ibuf);
	imsg_clear(&parent_ibuf);
	err_child = wait_for_child(pid);
	close(imsg_fds[0]);
	return err ? err : err_child;
}

const struct got_error *
got_object_commit_open(struct got_commit_object **commit,
    struct got_repository *repo, struct got_object *obj)
{
	const struct got_error *err = NULL;

	*commit = got_repo_get_cached_commit(repo, &obj->id);
	if (*commit != NULL) {
		(*commit)->refcnt++;
		return NULL;
	}

	if (obj->type != GOT_OBJ_TYPE_COMMIT)
		return got_error(GOT_ERR_OBJ_TYPE);

	if (obj->flags & GOT_OBJ_FLAG_PACKED) {
		uint8_t *buf;
		size_t len;
		err = got_packfile_extract_object_to_mem(&buf, &len, obj, repo);
		if (err)
			return err;
		obj->size = len;
		err = parse_commit_object(commit, buf, len);
		free(buf);
	} else {
		int fd;
		err = open_loose_object(&fd, obj, repo);
		if (err)
			return err;
		err = read_commit_object_privsep(commit, repo, obj, fd);
		close(fd);
	}

	if (err == NULL) {
		(*commit)->refcnt++;
		err = got_repo_cache_commit(repo, &obj->id, *commit);
	}

	return err;
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
		free(qid->id);
		free(qid);
	}

	free(commit->tree_id);
	free(commit->author);
	free(commit->committer);
	free(commit->logmsg);
	free(commit);
}

static const struct got_error *
read_tree_object(struct got_tree_object **tree, struct got_object *obj, FILE *f)
{
	const struct got_error *err = NULL;
	size_t len;
	uint8_t *p;

	if (obj->flags & GOT_OBJ_FLAG_PACKED)
		err = read_to_mem(&p, &len, f);
	else
		err = got_inflate_to_mem(&p, &len, f);
	if (err)
		return err;

	if (len < obj->hdrlen + obj->size) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	/* Skip object header. */
	len -= obj->hdrlen;
	err = parse_tree_object(tree, p + obj->hdrlen, len);
	free(p);
done:
	return err;
}

static void
read_tree_object_privsep_child(struct got_object *obj, int obj_fd,
    int imsg_fds[2])
{
	const struct got_error *err = NULL;
	struct got_tree_object *tree = NULL;
	struct imsgbuf ibuf;
	FILE *f = NULL;
	int status = 0;

	setproctitle("read tree object");
	close(imsg_fds[0]);
	imsg_init(&ibuf, imsg_fds[1]);

	/* revoke access to most system calls */
	if (pledge("stdio", NULL) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	f = fdopen(obj_fd, "rb");
	if (f == NULL) {
		err = got_error_from_errno();
		close(obj_fd);
		goto done;
	}

	err = read_tree_object(&tree, obj, f);
	if (err)
		goto done;

	err = got_privsep_send_tree(&ibuf, tree);
done:
	if (tree)
		got_object_tree_close(tree);
	if (err) {
		got_privsep_send_error(&ibuf, err);
		status = 1;
	}
	if (f)
		fclose(f);
	imsg_clear(&ibuf);
	close(imsg_fds[1]);
	_exit(status);
}

static const struct got_error *
read_tree_object_privsep(struct got_tree_object **tree, struct got_object *obj,
    int fd)
{
	const struct got_error *err = NULL, *err_child = NULL;
	struct imsgbuf parent_ibuf;
	int imsg_fds[2];
	pid_t pid;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds) == -1)
		return got_error_from_errno();

	pid = fork();
	if (pid == -1)
		return got_error_from_errno();
	else if (pid == 0) {
		read_tree_object_privsep_child(obj, fd, imsg_fds);
		/* not reached */
	}

	close(imsg_fds[1]);
	imsg_init(&parent_ibuf, imsg_fds[0]);
	err = got_privsep_recv_tree(tree, &parent_ibuf);
	imsg_clear(&parent_ibuf);
	err_child = wait_for_child(pid);
	close(imsg_fds[0]);
	return err ? err : err_child;
}

const struct got_error *
got_object_tree_open(struct got_tree_object **tree,
    struct got_repository *repo, struct got_object *obj)
{
	const struct got_error *err = NULL;

	*tree = got_repo_get_cached_tree(repo, &obj->id);
	if (*tree != NULL) {
		(*tree)->refcnt++;
		return NULL;
	}

	if (obj->type != GOT_OBJ_TYPE_TREE)
		return got_error(GOT_ERR_OBJ_TYPE);

	if (obj->flags & GOT_OBJ_FLAG_PACKED) {
		uint8_t *buf;
		size_t len;
		err = got_packfile_extract_object_to_mem(&buf, &len, obj, repo);
		if (err)
			return err;
		obj->size = len;
		err = parse_tree_object(tree, buf, len);
		free(buf);
	} else {
		int fd;
		err = open_loose_object(&fd, obj, repo);
		if (err)
			return err;
		err = read_tree_object_privsep(tree, obj, fd);
		close(fd);
	}

	if (err == NULL) {
		(*tree)->refcnt++;
		err = got_repo_cache_tree(repo, &obj->id, *tree);
	}

	return err;
}

const struct got_error *
got_object_open_as_tree(struct got_tree_object **tree,
    struct got_repository *repo, struct got_object_id *id)
{
	const struct got_error *err;
	struct got_object *obj;

	*tree = NULL;

	err = got_object_open(&obj, repo, id);
	if (err)
		return err;
	if (got_object_get_type(obj) != GOT_OBJ_TYPE_TREE) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_tree_open(tree, repo, obj);
done:
	got_object_close(obj);
	return err;
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
		tree_entry_close(te);
	}

	free(tree);
}

const struct got_tree_entries *
got_object_tree_get_entries(struct got_tree_object *tree)
{
	return &tree->entries;
}

static const struct got_error *
read_blob_object_privsep_child(int outfd, int infd, int imsg_fds[2])
{
	const struct got_error *err = NULL;
	struct imsgbuf ibuf;
	int status = 0;
	size_t size;
	FILE *infile = NULL;

	setproctitle("read blob object");
	close(imsg_fds[0]);
	imsg_init(&ibuf, imsg_fds[1]);

	/* revoke access to most system calls */
	if (pledge("stdio", NULL) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	infile = fdopen(infd, "rb");
	if (infile == NULL) {
		err = got_error_from_errno();
		close(infd);
		goto done;
	}
	err = got_inflate_to_fd(&size, infile, outfd);
	fclose(infile);
	if (err)
		goto done;

	err = got_privsep_send_blob(&ibuf, size);
done:
	if (err) {
		got_privsep_send_error(&ibuf, err);
		status = 1;
	}
	close(outfd);
	imsg_clear(&ibuf);
	close(imsg_fds[1]);
	_exit(status);
}

static const struct got_error *
read_blob_object_privsep(size_t *size, int outfd, int infd)
{
	struct imsgbuf parent_ibuf;
	int imsg_fds[2];
	const struct got_error *err = NULL, *err_child = NULL;
	pid_t pid;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds) == -1)
		return got_error_from_errno();

	pid = fork();
	if (pid == -1)
		return got_error_from_errno();
	else if (pid == 0) {
		read_blob_object_privsep_child(outfd, infd, imsg_fds);
		/* not reached */
	}

	close(imsg_fds[1]);
	imsg_init(&parent_ibuf, imsg_fds[0]);
	err = got_privsep_recv_blob(size, &parent_ibuf);
	imsg_clear(&parent_ibuf);
	err_child = wait_for_child(pid);
	close(imsg_fds[0]);
	if (lseek(outfd, SEEK_SET, 0) == -1)
		err = got_error_from_errno();
	return err ? err : err_child;
}

const struct got_error *
got_object_blob_open(struct got_blob_object **blob,
    struct got_repository *repo, struct got_object *obj, size_t blocksize)
{
	const struct got_error *err = NULL;

	if (obj->type != GOT_OBJ_TYPE_BLOB)
		return got_error(GOT_ERR_OBJ_TYPE);

	if (blocksize < obj->hdrlen)
		return got_error(GOT_ERR_NO_SPACE);

	*blob = calloc(1, sizeof(**blob));
	if (*blob == NULL)
		return got_error_from_errno();

	(*blob)->read_buf = calloc(1, blocksize);
	if ((*blob)->read_buf == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	if (obj->flags & GOT_OBJ_FLAG_PACKED) {
		err = got_packfile_extract_object(&((*blob)->f), obj, repo);
		if (err)
			goto done;
	} else {
		int infd, outfd;
		size_t size;
		struct stat sb;

		err = open_loose_object(&infd, obj, repo);
		if (err)
			goto done;


		outfd = got_opentempfd();
		if (outfd == -1) {
			err = got_error_from_errno();
			close(infd);
			goto done;
		}

		err = read_blob_object_privsep(&size, outfd, infd);
		close(infd);
		if (err)
			goto done;

		if (size != obj->hdrlen + obj->size) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			close(outfd);
			goto done;
		}

		if (fstat(outfd, &sb) == -1) {
			err = got_error_from_errno();
			close(outfd);
			goto done;
		}

		if (sb.st_size != size) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			close(outfd);
			goto done;
		}

		(*blob)->f = fdopen(outfd, "rb");
		if ((*blob)->f == NULL) {
			err = got_error_from_errno();
			close(outfd);
			goto done;
		}
	}

	(*blob)->hdrlen = obj->hdrlen;
	(*blob)->blocksize = blocksize;
	memcpy(&(*blob)->id.sha1, obj->id.sha1, SHA1_DIGEST_LENGTH);

done:
	if (err && *blob) {
		if ((*blob)->f)
			fclose((*blob)->f);
		free((*blob)->read_buf);
		free(*blob);
		*blob = NULL;
	}
	return err;
}

const struct got_error *
got_object_open_as_blob(struct got_blob_object **blob,
    struct got_repository *repo, struct got_object_id *id,
    size_t blocksize)
{
	const struct got_error *err;
	struct got_object *obj;

	*blob = NULL;

	err = got_object_open(&obj, repo, id);
	if (err)
		return err;
	if (got_object_get_type(obj) != GOT_OBJ_TYPE_BLOB) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_blob_open(blob, repo, obj, blocksize);
done:
	got_object_close(obj);
	return err;
}

void
got_object_blob_close(struct got_blob_object *blob)
{
	free(blob->read_buf);
	fclose(blob->f);
	free(blob);
}

char *
got_object_blob_id_str(struct got_blob_object *blob, char *buf, size_t size)
{
	return got_sha1_digest_to_str(blob->id.sha1, buf, size);
}

size_t
got_object_blob_get_hdrlen(struct got_blob_object *blob)
{
	return blob->hdrlen;
}

const uint8_t *
got_object_blob_get_read_buf(struct got_blob_object *blob)
{
	return blob->read_buf;
}

const struct got_error *
got_object_blob_read_block(size_t *outlenp, struct got_blob_object *blob)
{
	size_t n;

	n = fread(blob->read_buf, 1, blob->blocksize, blob->f);
	if (n == 0 && ferror(blob->f))
		return got_ferror(blob->f, GOT_ERR_IO);
	*outlenp = n;
	return NULL;
}

const struct got_error *
got_object_blob_dump_to_file(size_t *total_len, size_t *nlines,
    FILE *outfile, struct got_blob_object *blob)
{
	const struct got_error *err = NULL;
	size_t len, hdrlen;
	const uint8_t *buf;
	int i;

	if (total_len)
		*total_len = 0;
	if (nlines)
		*nlines = 0;

	hdrlen = got_object_blob_get_hdrlen(blob);
	do {
		err = got_object_blob_read_block(&len, blob);
		if (err)
			return err;
		if (len == 0)
			break;
		if (total_len)
			*total_len += len;
		buf = got_object_blob_get_read_buf(blob);
		if (nlines) {
			for (i = 0; i < len; i++) {
				if (buf[i] == '\n')
					(*nlines)++;
			}
		}
		/* Skip blob object header first time around. */
		fwrite(buf + hdrlen, len - hdrlen, 1, outfile);
		hdrlen = 0;
	} while (len != 0);

	fflush(outfile);
	rewind(outfile);

	return NULL;
}

static struct got_tree_entry *
find_entry_by_name(struct got_tree_object *tree, const char *name)
{
	struct got_tree_entry *te;

	SIMPLEQ_FOREACH(te, &tree->entries.head, entry) {
		if (strcmp(te->name, name) == 0)
			return te;
	}
	return NULL;
}

const struct got_error *
got_object_open_by_path(struct got_object **obj, struct got_repository *repo,
    struct got_object_id *commit_id, const char *path)
{
	const struct got_error *err = NULL;
	struct got_commit_object *commit = NULL;
	struct got_tree_object *tree = NULL;
	struct got_tree_entry *te = NULL;
	char *seg, *s, *s0 = NULL;
	size_t len = strlen(path);

	*obj = NULL;

	/* We are expecting an absolute in-repository path. */
	if (path[0] != '/')
		return got_error(GOT_ERR_NOT_ABSPATH);

	err = got_object_open_as_commit(&commit, repo, commit_id);
	if (err)
		goto done;

	/* Handle opening of root of commit's tree. */
	if (path[1] == '\0') {
		err = got_object_open(obj, repo, commit->tree_id);
		if (err)
			goto done;
		return NULL;
	}

	err = got_object_open_as_tree(&tree, repo, commit->tree_id);
	if (err)
		goto done;

	s0 = strdup(path);
	if (s0 == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	err = got_canonpath(path, s0, len + 1);
	if (err)
		goto done;

	s = s0;
	s++; /* skip leading '/' */
	len--;
	seg = s;
	while (len > 0) {
		struct got_tree_object *next_tree;

		if (*s != '/') {
			s++;
			len--;
			if (*s)
				continue;
		}

		/* end of path segment */
		*s = '\0';

		te = find_entry_by_name(tree, seg);
		if (te == NULL) {
			err = got_error(GOT_ERR_NO_OBJ);
			goto done;
		}

		if (len == 0)
			break;

		seg = s + 1;
		s++;
		len--;
		if (*s) {
			err = got_object_open_as_tree(&next_tree, repo,
			    te->id);
			te = NULL;
			if (err)
				goto done;
			got_object_tree_close(tree);
			tree = next_tree;
		}
	}

	if (te) {
		err = got_object_open(obj, repo, te->id);
		if (err)
			goto done;
	} else
		err = got_error(GOT_ERR_NO_OBJ);
done:
	free(s0);
	if (commit)
		got_object_commit_close(commit);
	if (tree)
		got_object_tree_close(tree);
	return err;
}
