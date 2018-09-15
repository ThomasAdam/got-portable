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

static const struct got_error *
request_object(struct got_object **obj, struct got_repository *repo, int fd)
{
	const struct got_error *err = NULL;
	struct imsgbuf *ibuf;

	ibuf = repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_OBJECT].ibuf;

	err = got_privsep_send_obj_req(ibuf, fd, NULL);
	if (err)
		return err;

	return got_privsep_recv_obj(obj, ibuf);
}

static void
exec_privsep_child(int imsg_fds[2], const char *path, const char *repo_path)
{
	close(imsg_fds[0]);

	if (dup2(imsg_fds[1], GOT_IMSG_FD_CHILD) == -1) {
		fprintf(stderr, "%s: %s\n", getprogname(),
		    strerror(errno));
		_exit(1);
	}
	if (closefrom(GOT_IMSG_FD_CHILD + 1) == -1) {
		fprintf(stderr, "%s: %s\n", getprogname(),
		    strerror(errno));
		_exit(1);
	}

	if (execl(path, path, repo_path, (char *)NULL) == -1) {
		fprintf(stderr, "%s: %s: %s\n", getprogname(), path,
		    strerror(errno));
		_exit(1);
	}
}

const struct got_error *
got_object_read_header_privsep(struct got_object **obj,
    struct got_repository *repo, int obj_fd)
{
	int imsg_fds[2];
	pid_t pid;
	struct imsgbuf *ibuf;

	if (repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_OBJECT].imsg_fd != -1)
		return request_object(obj, repo, obj_fd);

	ibuf = calloc(1, sizeof(*ibuf));
	if (ibuf == NULL)
		return got_error_from_errno();

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds) == -1)
		return got_error_from_errno();

	pid = fork();
	if (pid == -1)
		return got_error_from_errno();
	else if (pid == 0) {
		exec_privsep_child(imsg_fds, GOT_PATH_PROG_READ_OBJECT,
		    repo->path);
		/* not reached */
	}

	close(imsg_fds[1]);
	repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_OBJECT].imsg_fd =
	    imsg_fds[0];
	repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_OBJECT].pid = pid;
	imsg_init(ibuf, imsg_fds[0]);
	repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_OBJECT].ibuf = ibuf;

	return request_object(obj, repo, obj_fd);
}

static const struct got_error *
request_packed_object(struct got_object **obj, struct got_pack *pack, int idx,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct imsgbuf *ibuf = pack->privsep_child->ibuf;

	err = got_privsep_send_packed_obj_req(ibuf, idx);
	if (err)
		return err;

	err = got_privsep_recv_obj(obj, ibuf);
	if (err)
		return err;

	(*obj)->path_packfile = strdup(pack->path_packfile);
	if ((*obj)->path_packfile == NULL) {
		err = got_error_from_errno();
		return err;
	}
	memcpy(&(*obj)->id, id, sizeof((*obj)->id));

	return NULL;
}

const struct got_error *
got_object_packed_read_privsep(struct got_object **obj,
    struct got_repository *repo, struct got_pack *pack,
    struct got_packidx *packidx, int idx, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	int imsg_fds[2];
	pid_t pid;
	struct imsgbuf *ibuf;

	if (pack->privsep_child)
		return request_packed_object(obj, pack, idx, id);

	ibuf = calloc(1, sizeof(*ibuf));
	if (ibuf == NULL)
		return got_error_from_errno();

	pack->privsep_child = calloc(1, sizeof(*pack->privsep_child));
	if (pack->privsep_child == NULL) {
		err = got_error_from_errno();
		free(ibuf);
		return err;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	pid = fork();
	if (pid == -1) {
		err = got_error_from_errno();
		goto done;
	} else if (pid == 0) {
		exec_privsep_child(imsg_fds, GOT_PATH_PROG_READ_PACK,
		    pack->path_packfile);
		/* not reached */
	}

	close(imsg_fds[1]);
	pack->privsep_child->imsg_fd = imsg_fds[0];
	pack->privsep_child->pid = pid;
	imsg_init(ibuf, imsg_fds[0]);
	pack->privsep_child->ibuf = ibuf;

	err = got_privsep_init_pack_child(ibuf, pack, packidx);
	if (err) {
		const struct got_error *child_err;
		err = got_privsep_send_stop(pack->privsep_child->imsg_fd);
		child_err = got_privsep_wait_for_child(
		    pack->privsep_child->pid);
		if (child_err && err == NULL)
			err = child_err;
		free(ibuf);
		free(pack->privsep_child);
		pack->privsep_child = NULL;
		return err;
	}

done:
	if (err) {
		free(ibuf);
		free(pack->privsep_child);
		pack->privsep_child = NULL;
	} else
		err = request_packed_object(obj, pack, idx, id);
	return err;
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
got_object_commit_add_parent(struct got_commit_object *commit,
    const char *id_str)
{
	const struct got_error *err = NULL;
	struct got_object_qid *qid;

	qid = malloc(sizeof(*qid));
	if (qid == NULL)
		return got_error_from_errno();

	qid->id = malloc(sizeof(*qid->id));
	if (qid->id == NULL) {
		err = got_error_from_errno();
		got_object_qid_free(qid);
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

static const struct got_error *
request_commit(struct got_commit_object **commit, struct got_repository *repo,
    struct got_object *obj, int fd)
{
	const struct got_error *err = NULL;
	struct imsgbuf *ibuf;

	ibuf = repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_COMMIT].ibuf;

	err = got_privsep_send_obj_req(ibuf, fd, obj);
	if (err)
		return err;

	return got_privsep_recv_commit(commit, ibuf);
}

const struct got_error *
got_object_read_packed_commit_privsep(struct got_commit_object **commit,
    struct got_object *obj, struct got_pack *pack)
{
	const struct got_error *err = NULL;

	err = got_privsep_send_obj_req(pack->privsep_child->ibuf, -1, obj);
	if (err)
		return err;

	return got_privsep_recv_commit(commit, pack->privsep_child->ibuf);
}

const struct got_error *
got_object_read_commit_privsep(struct got_commit_object **commit,
    struct got_object *obj, int obj_fd, struct got_repository *repo)
{
	int imsg_fds[2];
	pid_t pid;
	struct imsgbuf *ibuf;

	if (repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_COMMIT].imsg_fd != -1)
		return request_commit(commit, repo, obj, obj_fd);

	ibuf = calloc(1, sizeof(*ibuf));
	if (ibuf == NULL)
		return got_error_from_errno();

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds) == -1)
		return got_error_from_errno();

	pid = fork();
	if (pid == -1)
		return got_error_from_errno();
	else if (pid == 0) {
		exec_privsep_child(imsg_fds, GOT_PATH_PROG_READ_COMMIT,
		    repo->path);
		/* not reached */
	}

	close(imsg_fds[1]);
	repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_COMMIT].imsg_fd =
	    imsg_fds[0];
	repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_COMMIT].pid = pid;
	imsg_init(ibuf, imsg_fds[0]);
	repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_COMMIT].ibuf = ibuf;

	return request_commit(commit, repo, obj, obj_fd);
}

static const struct got_error *
request_tree(struct got_tree_object **tree, struct got_repository *repo,
    struct got_object *obj, int fd)
{
	const struct got_error *err = NULL;
	struct imsgbuf *ibuf;

	ibuf = repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_TREE].ibuf;

	err = got_privsep_send_obj_req(ibuf, fd, obj);
	if (err)
		return err;

	return got_privsep_recv_tree(tree, ibuf);
}

const struct got_error *
got_object_read_tree_privsep(struct got_tree_object **tree,
    struct got_object *obj, int obj_fd, struct got_repository *repo)
{
	int imsg_fds[2];
	pid_t pid;
	struct imsgbuf *ibuf;

	if (repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_TREE].imsg_fd != -1)
		return request_tree(tree, repo, obj, obj_fd);

	ibuf = calloc(1, sizeof(*ibuf));
	if (ibuf == NULL)
		return got_error_from_errno();

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds) == -1)
		return got_error_from_errno();

	pid = fork();
	if (pid == -1)
		return got_error_from_errno();
	else if (pid == 0) {
		exec_privsep_child(imsg_fds, GOT_PATH_PROG_READ_TREE,
		    repo->path);
		/* not reached */
	}

	close(imsg_fds[1]);

	repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_TREE].imsg_fd =
	    imsg_fds[0];
	repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_TREE].pid = pid;
	imsg_init(ibuf, imsg_fds[0]);
	repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_TREE].ibuf = ibuf;


	return request_tree(tree, repo, obj, obj_fd);
}

const struct got_error *
got_object_read_packed_tree_privsep(struct got_tree_object **tree,
    struct got_object *obj, struct got_pack *pack)
{
	const struct got_error *err = NULL;

	err = got_privsep_send_obj_req(pack->privsep_child->ibuf, -1, obj);
	if (err)
		return err;

	return got_privsep_recv_tree(tree, pack->privsep_child->ibuf);
}

static const struct got_error *
request_blob(size_t *size, int outfd, int infd, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	int outfd_child;

	outfd_child = dup(outfd);
	if (outfd_child == -1)
		return got_error_from_errno();

	err = got_privsep_send_blob_req(ibuf, infd);
	if (err)
		return err;

	err = got_privsep_send_blob_outfd(ibuf, outfd_child);
	if (err) {
		close(outfd_child);
		return err;
	}

	err = got_privsep_recv_blob(size, ibuf);
	if (err)
		return err;

	if (lseek(outfd, SEEK_SET, 0) == -1)
		return got_error_from_errno();

	return err;
}

const struct got_error *
got_object_read_blob_privsep(size_t *size, int outfd, int infd,
    struct got_repository *repo)
{
	int imsg_fds[2];
	pid_t pid;
	struct imsgbuf *ibuf;

	if (repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_BLOB].imsg_fd != -1) {
		ibuf = repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_BLOB].ibuf;
		return request_blob(size, outfd, infd, ibuf);
	}

	ibuf = calloc(1, sizeof(*ibuf));
	if (ibuf == NULL)
		return got_error_from_errno();

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds) == -1)
		return got_error_from_errno();

	pid = fork();
	if (pid == -1)
		return got_error_from_errno();
	else if (pid == 0) {
		exec_privsep_child(imsg_fds, GOT_PATH_PROG_READ_BLOB,
		    repo->path);
		/* not reached */
	}

	close(imsg_fds[1]);
	repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_BLOB].imsg_fd =
	    imsg_fds[0];
	repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_BLOB].pid = pid;
	imsg_init(ibuf, imsg_fds[0]);
	repo->privsep_children[GOT_REPO_PRIVSEP_CHILD_BLOB].ibuf = ibuf;

	return request_blob(size, outfd, infd, ibuf);
}
