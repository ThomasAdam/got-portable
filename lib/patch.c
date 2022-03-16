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
 *
 * Apply patches.
 *
 * Things that are still missing:
 *     + "No final newline" handling
 *
 * Things that we may want to support:
 *     + support indented patches?
 *     + support other kinds of patches?
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <imsg.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"
#include "got_reference.h"
#include "got_cancel.h"
#include "got_worktree.h"
#include "got_opentemp.h"
#include "got_patch.h"

#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_privsep.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct got_patch_hunk {
	STAILQ_ENTRY(got_patch_hunk) entries;
	long	old_from;
	long	old_lines;
	long	new_from;
	long	new_lines;
	size_t	len;
	size_t	cap;
	char	**lines;
};

struct got_patch {
	char	*old;
	char	*new;
	STAILQ_HEAD(, got_patch_hunk) head;
};

struct patch_args {
	got_patch_progress_cb progress_cb;
	void	*progress_arg;
};

static const struct got_error *
send_patch(struct imsgbuf *ibuf, int fd)
{
	const struct got_error *err = NULL;

	if (imsg_compose(ibuf, GOT_IMSG_PATCH_FILE, 0, 0, fd,
	    NULL, 0) == -1) {
		err = got_error_from_errno(
		    "imsg_compose GOT_IMSG_PATCH_FILE");
		close(fd);
		return err;
	}

	if (imsg_flush(ibuf) == -1) {
		err = got_error_from_errno("imsg_flush");
		imsg_clear(ibuf);
	}

	return err;
}

static void
patch_free(struct got_patch *p)
{
	struct got_patch_hunk *h;
	size_t i;

	while (!STAILQ_EMPTY(&p->head)) {
		h = STAILQ_FIRST(&p->head);
		STAILQ_REMOVE_HEAD(&p->head, entries);

		for (i = 0; i < h->len; ++i)
			free(h->lines[i]);
		free(h->lines);
		free(h);
	}

	free(p->new);
	free(p->old);
}

static const struct got_error *
pushline(struct got_patch_hunk *h, const char *line)
{
	void 	*t;
	size_t	 newcap;

	if (h->len == h->cap) {
		if ((newcap = h->cap * 1.5) == 0)
			newcap = 16;
		t = recallocarray(h->lines, h->cap, newcap,
		    sizeof(h->lines[0]));
		if (t == NULL)
			return got_error_from_errno("recallocarray");
		h->lines = t;
		h->cap = newcap;
	}

	if ((t = strdup(line)) == NULL)
		return got_error_from_errno("strdup");

	h->lines[h->len++] = t;
	return NULL;
}

static const struct got_error *
recv_patch(struct imsgbuf *ibuf, int *done, struct got_patch *p)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_patch_hunk hdr;
	struct got_imsg_patch patch;
	struct got_patch_hunk *h = NULL;
	size_t datalen;

	memset(p, 0, sizeof(*p));
	STAILQ_INIT(&p->head);

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;
	if (imsg.hdr.type == GOT_IMSG_PATCH_EOF) {
		*done = 1;
		goto done;
	}
	if (imsg.hdr.type != GOT_IMSG_PATCH) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}
	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(patch)) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	memcpy(&patch, imsg.data, sizeof(patch));
	if (*patch.old != '\0' && (p->old = strdup(patch.old)) == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}
	if (*patch.new != '\0' && (p->new = strdup(patch.new)) == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}
	if (p->old == NULL && p->new == NULL) {
		err = got_error(GOT_ERR_PATCH_MALFORMED);
		goto done;
	}

	imsg_free(&imsg);

	for (;;) {
		char *t;

		err = got_privsep_recv_imsg(&imsg, ibuf, 0);
		if (err)
			return err;

		switch (imsg.hdr.type) {
		case GOT_IMSG_PATCH_DONE:
			goto done;
		case GOT_IMSG_PATCH_HUNK:
			datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
			if (datalen != sizeof(hdr)) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				goto done;
			}
			memcpy(&hdr, imsg.data, sizeof(hdr));
			if ((h = calloc(1, sizeof(*h))) == NULL) {
				err = got_error_from_errno("calloc");
				goto done;
			}
			h->old_from = hdr.oldfrom;
			h->old_lines = hdr.oldlines;
			h->new_from = hdr.newfrom;
			h->new_lines = hdr.newlines;
			STAILQ_INSERT_TAIL(&p->head, h, entries);
			break;
		case GOT_IMSG_PATCH_LINE:
			if (h == NULL) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				goto done;
			}
			datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
			t = imsg.data;
			/* at least one char plus newline */
			if (datalen < 2 || t[datalen-1] != '\0') {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				goto done;
			}
			if (*t != ' ' && *t != '-' && *t != '+') {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				goto done;
			}
			err = pushline(h, t);
			if (err)
				goto done;
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			goto done;
		}

		imsg_free(&imsg);
	}

done:
	imsg_free(&imsg);
	return err;
}

/*
 * Copy data from orig starting at copypos until pos into tmp.
 * If pos is -1, copy until EOF.
 */
static const struct got_error *
copy(FILE *tmp, FILE *orig, off_t copypos, off_t pos)
{
	char buf[BUFSIZ];
	size_t len, r, w;

	if (fseek(orig, copypos, SEEK_SET) == -1)
		return got_error_from_errno("fseek");

	while (pos == -1 || copypos < pos) {
		len = sizeof(buf);
		if (pos > 0)
			len = MIN(len, (size_t)pos - copypos);
		r = fread(buf, 1, len, orig);
		if (r != len && ferror(orig))
			return got_error_from_errno("fread");
		w = fwrite(buf, 1, r, tmp);
		if (w != r)
			return got_error_from_errno("fwrite");
		copypos += len;
		if (r != len && feof(orig)) {
			if (pos == -1)
				return NULL;
			return got_error(GOT_ERR_PATCH_DONT_APPLY);
		}
	}
	return NULL;
}

static const struct got_error *
locate_hunk(FILE *orig, struct got_patch_hunk *h, off_t *pos, long *lineno)
{
	const struct got_error *err = NULL;
	char *line = NULL;
	char mode = *h->lines[0];
	size_t linesize = 0;
	ssize_t linelen;
	off_t match = -1;
	long match_lineno = -1;

	for (;;) {
		linelen = getline(&line, &linesize, orig);
		if (linelen == -1) {
			if (ferror(orig))
				err = got_error_from_errno("getline");
			else if (match == -1)
				err = got_error(GOT_ERR_PATCH_DONT_APPLY);
			break;
		}
		(*lineno)++;

		if ((mode == ' ' && !strcmp(h->lines[0]+1, line)) ||
		    (mode == '-' && !strcmp(h->lines[0]+1, line)) ||
		    (mode == '+' && *lineno == h->old_from)) {
			match = ftello(orig);
			if (match == -1) {
				err = got_error_from_errno("ftello");
				break;
			}
			match -= linelen;
			match_lineno = (*lineno)-1;
		}

		if (*lineno >= h->old_from && match != -1)
			break;
	}

	if (err == NULL) {
		*pos = match;
		*lineno = match_lineno;
		if (fseek(orig, match, SEEK_SET) == -1)
			err = got_error_from_errno("fseek");
	}

	free(line);
	return err;
}

static const struct got_error *
test_hunk(FILE *orig, struct got_patch_hunk *h)
{
	const struct got_error *err = NULL;
	char *line = NULL;
	size_t linesize = 0, i = 0;
	ssize_t linelen;

	for (i = 0; i < h->len; ++i) {
		switch (*h->lines[i]) {
		case '+':
			continue;
		case ' ':
		case '-':
			linelen = getline(&line, &linesize, orig);
			if (linelen == -1) {
				if (ferror(orig))
					err = got_error_from_errno("getline");
				else
					err = got_error(
					    GOT_ERR_PATCH_DONT_APPLY);
				goto done;
			}
			if (strcmp(h->lines[i]+1, line)) {
				err = got_error(GOT_ERR_PATCH_DONT_APPLY);
				goto done;
			}
			break;
		}
	}

done:
	free(line);
	return err;
}

static const struct got_error *
apply_hunk(FILE *tmp, struct got_patch_hunk *h, long *lineno)
{
	size_t i = 0;

	for (i = 0; i < h->len; ++i) {
		switch (*h->lines[i]) {
		case ' ':
			if (fprintf(tmp, "%s", h->lines[i]+1) < 0)
				return got_error_from_errno("fprintf");
			/* fallthrough */
		case '-':
			(*lineno)++;
			break;
		case '+':
			if (fprintf(tmp, "%s", h->lines[i]+1) < 0)
				return got_error_from_errno("fprintf");
			break;
		}
	}
	return NULL;
}

static const struct got_error *
patch_file(struct got_patch *p, const char *path, FILE *tmp, int nop,
    mode_t *mode)
{
	const struct got_error *err = NULL;
	struct got_patch_hunk *h;
	struct stat sb;
	size_t i;
	long lineno = 0;
	FILE *orig;
	off_t copypos, pos;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;

	if (p->old == NULL) {				/* create */
		h = STAILQ_FIRST(&p->head);
		if (h == NULL || STAILQ_NEXT(h, entries) != NULL)
			return got_error(GOT_ERR_PATCH_MALFORMED);
		if (nop)
			return NULL;
		for (i = 0; i < h->len; ++i) {
			if (fprintf(tmp, "%s", h->lines[i]+1) < 0)
				return got_error_from_errno("fprintf");
		}
		return err;
	}

	if ((orig = fopen(path, "r")) == NULL) {
		err = got_error_from_errno2("fopen", path);
		goto done;
	}

	if (fstat(fileno(orig), &sb) == -1) {
		err = got_error_from_errno("fstat");
		goto done;
	}
	*mode = sb.st_mode;

	copypos = 0;
	STAILQ_FOREACH(h, &p->head, entries) {
		if (h->lines == NULL)
			break;

	tryagain:
		err = locate_hunk(orig, h, &pos, &lineno);
		if (err != NULL)
			goto done;
		if (!nop)
			err = copy(tmp, orig, copypos, pos);
		if (err != NULL)
			goto done;
		copypos = pos;

		err = test_hunk(orig, h);
		if (err != NULL && err->code == GOT_ERR_PATCH_DONT_APPLY) {
			/*
			 * try to apply the hunk again starting the search
			 * after the previous partial match.
			 */
			if (fseek(orig, pos, SEEK_SET) == -1) {
				err = got_error_from_errno("fseek");
				goto done;
			}
			linelen = getline(&line, &linesize, orig);
			if (linelen == -1) {
				err = got_error_from_errno("getline");
				goto done;
			}
			lineno++;
			goto tryagain;
		}
		if (err != NULL)
			goto done;

		if (!nop)
			err = apply_hunk(tmp, h, &lineno);
		if (err != NULL)
			goto done;
		
		copypos = ftello(orig);
		if (copypos == -1) {
			err = got_error_from_errno("ftello");
			goto done;
		}
	}

	if (p->new == NULL && sb.st_size != copypos)
		err = got_error(GOT_ERR_PATCH_DONT_APPLY);
	else if (!nop && !feof(orig))
		err = copy(tmp, orig, copypos, -1);

done:
	if (orig != NULL)
		fclose(orig);
	return err;
}

static const struct got_error *
build_pathlist(const char *p, char **path, struct got_pathlist_head *head,
    struct got_worktree *worktree)
{
	const struct got_error *err;
	struct got_pathlist_entry *pe;

	err = got_worktree_resolve_path(path, worktree, p);
	if (err == NULL)
		err = got_pathlist_insert(&pe, head, *path, NULL);
	return err;
}

static const struct got_error *
can_rm(void *arg, unsigned char status, unsigned char staged_status,
    const char *path, struct got_object_id *blob_id,
    struct got_object_id *staged_blob_id, struct got_object_id *commit_id,
    int dirfd, const char *de_name)
{
	if (status == GOT_STATUS_NONEXISTENT)
		return got_error_set_errno(ENOENT, path);
	if (status != GOT_STATUS_NO_CHANGE &&
	    status != GOT_STATUS_ADD &&
	    status != GOT_STATUS_MODIFY &&
	    status != GOT_STATUS_MODE_CHANGE)
		return got_error_path(path, GOT_ERR_FILE_STATUS);
	if (staged_status == GOT_STATUS_DELETE)
		return got_error_path(path, GOT_ERR_FILE_STATUS);
	return NULL;
}

static const struct got_error *
can_add(void *arg, unsigned char status, unsigned char staged_status,
    const char *path, struct got_object_id *blob_id,
    struct got_object_id *staged_blob_id, struct got_object_id *commit_id,
    int dirfd, const char *de_name)
{
	if (status != GOT_STATUS_NONEXISTENT)
		return got_error_path(path, GOT_ERR_FILE_STATUS);
	return NULL;
}

static const struct got_error *
can_edit(void *arg, unsigned char status, unsigned char staged_status,
    const char *path, struct got_object_id *blob_id,
    struct got_object_id *staged_blob_id, struct got_object_id *commit_id,
    int dirfd, const char *de_name)
{
	if (status == GOT_STATUS_NONEXISTENT)
		return got_error_set_errno(ENOENT, path);
	if (status != GOT_STATUS_NO_CHANGE &&
	    status != GOT_STATUS_ADD &&
	    status != GOT_STATUS_MODIFY)
		return got_error_path(path, GOT_ERR_FILE_STATUS);
	if (staged_status == GOT_STATUS_DELETE)
		return got_error_path(path, GOT_ERR_FILE_STATUS);
	return NULL;
}

static const struct got_error *
check_file_status(struct got_patch *p, int file_renamed,
    struct got_worktree *worktree, struct got_repository *repo,
    struct got_pathlist_head *old, struct got_pathlist_head *new,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	static const struct got_error *err;

	if (p->old != NULL && p->new == NULL)
		return got_worktree_status(worktree, old, repo, 0,
		    can_rm, NULL, cancel_cb, cancel_arg);
	else if (file_renamed) {
		err = got_worktree_status(worktree, old, repo, 0,
		    can_rm, NULL, cancel_cb, cancel_arg);
		if (err)
			return err;
		return got_worktree_status(worktree, new, repo, 0,
		    can_add, NULL, cancel_cb, cancel_arg);
	} else if (p->old == NULL)
		return got_worktree_status(worktree, new, repo, 0,
		    can_add, NULL, cancel_cb, cancel_arg);
	else
		return got_worktree_status(worktree, new, repo, 0,
		    can_edit, NULL, cancel_cb, cancel_arg);
}

static const struct got_error *
patch_delete(void *arg, unsigned char status, unsigned char staged_status,
    const char *path)
{
	struct patch_args *pa = arg;

	return pa->progress_cb(pa->progress_arg, path, NULL, status);
}

static const struct got_error *
patch_add(void *arg, unsigned char status, const char *path)
{
	struct patch_args *pa = arg;

	return pa->progress_cb(pa->progress_arg, NULL, path, status);
}

static const struct got_error *
apply_patch(struct got_worktree *worktree, struct got_repository *repo,
    struct got_patch *p, int nop, struct patch_args *pa,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_pathlist_head oldpaths, newpaths;
	int file_renamed = 0;
	char *oldpath = NULL, *newpath = NULL, *parent = NULL;
	char *tmppath = NULL, *template = NULL;
	FILE *tmp = NULL;
	mode_t mode = GOT_DEFAULT_FILE_MODE;

	TAILQ_INIT(&oldpaths);
	TAILQ_INIT(&newpaths);

	err = build_pathlist(p->old != NULL ? p->old : p->new, &oldpath,
	    &oldpaths, worktree);
	if (err)
		goto done;

	err = build_pathlist(p->new != NULL ? p->new : p->old, &newpath,
	    &newpaths, worktree);
	if (err)
		goto done;

	if (p->old != NULL && p->new != NULL && strcmp(p->old, p->new))
		file_renamed = 1;

	err = check_file_status(p, file_renamed, worktree, repo, &oldpaths,
	    &newpaths, cancel_cb, cancel_arg);
	if (err)
		goto done;

	if (p->old != NULL && p->new == NULL) {
		/*
		 * special case: delete a file.  don't try to match
		 * the lines but just schedule the removal.
		 */
		err = got_worktree_schedule_delete(worktree, &oldpaths,
		    0, NULL, delete_cb, delete_arg, repo, 0, 0);
		goto done;
	}

	if (asprintf(&template, "%s/got-patch",
	    got_worktree_get_root_path(worktree)) == -1) {
		err = got_error_from_errno(template);
		goto done;
	}

	if (!nop)
		err = got_opentemp_named(&tmppath, &tmp, template);
	if (err)
		goto done;
	err = patch_file(p, oldpath, tmp, nop, &mode);
	if (err)
		goto done;

	if (nop)
		goto done;

	if (p->old != NULL && p->new == NULL) {
		err = got_worktree_schedule_delete(worktree, &oldpaths,
		    0, NULL, patch_delete, pa, repo, 0, 0);
		goto done;
	}

	if (fchmod(fileno(tmp), mode) == -1) {
		err = got_error_from_errno2("chmod", newpath);
		goto done;
	}

	if (rename(tmppath, newpath) == -1) {
		if (errno != ENOENT) {
			err = got_error_from_errno3("rename", tmppath,
			    newpath);
			goto done;
		}

		err = got_path_dirname(&parent, newpath);
		if (err != NULL)
			goto done;
		err = got_path_mkdir(parent);
		if (err != NULL)
			goto done;
		if (rename(tmppath, newpath) == -1) {
			err = got_error_from_errno3("rename", tmppath,
			    newpath);
			goto done;
		}
	}

	if (file_renamed) {
		err = got_worktree_schedule_delete(worktree, &oldpaths,
		    0, NULL, patch_delete, pa, repo, 0, 0);
		if (err == NULL)
			err = got_worktree_schedule_add(worktree, &newpaths,
			    patch_add, pa, repo, 1);
	} else if (p->old == NULL)
		err = got_worktree_schedule_add(worktree, &newpaths,
		    patch_add, pa, repo, 1);
	else
		err = pa->progress_cb(pa->progress_arg, oldpath, newpath,
		    GOT_STATUS_MODIFY);

done:
	if (err != NULL && newpath != NULL && (file_renamed || p->old == NULL))
		unlink(newpath);
	free(parent);
	free(template);
	if (tmppath != NULL)
		unlink(tmppath);
	free(tmppath);
	got_pathlist_free(&oldpaths);
	got_pathlist_free(&newpaths);
	free(oldpath);
	free(newpath);
	return err;
}

const struct got_error *
got_patch(int fd, struct got_worktree *worktree, struct got_repository *repo,
    int nop, got_patch_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct patch_args pa;
	struct imsgbuf *ibuf;
	int imsg_fds[2] = {-1, -1};
	int done = 0;
	pid_t pid;

	pa.progress_cb = progress_cb;
	pa.progress_arg = progress_arg;

	ibuf = calloc(1, sizeof(*ibuf));
	if (ibuf == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds) == -1) {
		err = got_error_from_errno("socketpair");
		goto done;
	}

	pid = fork();
	if (pid == -1) {
		err = got_error_from_errno("fork");
		goto done;
	} else if (pid == 0) {
		got_privsep_exec_child(imsg_fds, GOT_PATH_PROG_READ_PATCH,
		    NULL);
		/* not reached */
	}

	if (close(imsg_fds[1]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	imsg_fds[1] = -1;
	imsg_init(ibuf, imsg_fds[0]);

	err = send_patch(ibuf, fd);
	fd = -1;
	if (err)
		goto done;

	while (!done && err == NULL) {
		struct got_patch p;

		err = recv_patch(ibuf, &done, &p);
		if (err || done)
			break;

		err = apply_patch(worktree, repo, &p, nop, &pa,
		    cancel_cb, cancel_arg);
		patch_free(&p);
		if (err)
			break;
	}

done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (ibuf != NULL)
		imsg_clear(ibuf);
	if (imsg_fds[0] != -1 && close(imsg_fds[0]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (imsg_fds[1] != -1 && close(imsg_fds[1]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err;
}
