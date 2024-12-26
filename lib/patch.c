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
 * Things that we may want to support:
 *     + support indented patches?
 *     + support other kinds of patches?
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <sha1.h>
#include <sha2.h>
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
#include "got_repository.h"
#include "got_opentemp.h"
#include "got_patch.h"
#include "got_diff.h"

#include "got_lib_delta.h"
#include "got_lib_diff.h"
#include "got_lib_hash.h"
#include "got_lib_object.h"
#include "got_lib_privsep.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

struct got_patch_line {
	char	 mode;
	char	*line;
	size_t	 len;
};

struct got_patch_hunk {
	STAILQ_ENTRY(got_patch_hunk) entries;
	const struct got_error *err;
	int	ws_mangled;
	int	offset;
	int	old_nonl;
	int	new_nonl;
	int	old_from;
	int	old_lines;
	int	new_from;
	int	new_lines;
	size_t	len;
	size_t	cap;
	struct got_patch_line *lines;
};

STAILQ_HEAD(got_patch_hunk_head, got_patch_hunk);
struct got_patch {
	int	 xbit;
	char	*old;
	char	*new;
	char	 cid[GOT_HASH_DIGEST_STRING_MAXLEN];
	char	 blob[GOT_HASH_DIGEST_STRING_MAXLEN];
	struct got_patch_hunk_head head;
};

struct patch_args {
	got_patch_progress_cb progress_cb;
	void	*progress_arg;
	struct got_patch_hunk_head *head;
};

static mode_t
apply_umask(mode_t mode)
{
	mode_t um;

	um = umask(000);
	umask(um);
	return mode & ~um;
}

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

	return got_privsep_flush_imsg(ibuf);
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
			free(h->lines[i].line);
		free(h->lines);
		free(h);
	}

	free(p->new);
	free(p->old);

	memset(p, 0, sizeof(*p));
	STAILQ_INIT(&p->head);
}

static const struct got_error *
pushline(struct got_patch_hunk *h, const char *line, size_t len)
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

	if ((t = malloc(len - 1)) == NULL)
		return got_error_from_errno("malloc");
	memcpy(t, line + 1, len - 1);	/* skip the line type */

	h->lines[h->len].mode = *line;
	h->lines[h->len].line = t;
	h->lines[h->len].len = len - 2;	/* line type and trailing NUL */
	h->len++;
	return NULL;
}

static const struct got_error *
recv_patch(struct imsgbuf *ibuf, int *done, struct got_patch *p, int strip)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_patch_hunk hdr;
	struct got_imsg_patch patch;
	struct got_patch_hunk *h = NULL;
	size_t datalen;
	int lastmode = -1;

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

	if (patch.old[sizeof(patch.old)-1] != '\0' ||
	    patch.new[sizeof(patch.new)-1] != '\0' ||
	    patch.cid[sizeof(patch.cid)-1] != '\0' ||
	    patch.blob[sizeof(patch.blob)-1] != '\0') {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}

	if (*patch.cid != '\0')
		strlcpy(p->cid, patch.cid, sizeof(p->cid));

	if (*patch.blob != '\0')
		strlcpy(p->blob, patch.blob, sizeof(p->blob));

	p->xbit = patch.xbit;

	/* automatically set strip=1 for git-style diffs */
	if (strip == -1 && patch.git &&
	    (*patch.old == '\0' || !strncmp(patch.old, "a/", 2)) &&
	    (*patch.new == '\0' || !strncmp(patch.new, "b/", 2)))
		strip = 1;

	/* prefer the new name if not /dev/null for not git-style diffs */
	if (!patch.git && *patch.new != '\0' && *patch.old != '\0') {
		err = got_path_strip(&p->old, patch.new, strip);
		if (err)
			goto done;
	} else if (*patch.old != '\0') {
		err = got_path_strip(&p->old, patch.old, strip);
		if (err)
			goto done;
	}

	if (*patch.new != '\0') {
		err = got_path_strip(&p->new, patch.new, strip);
		if (err)
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
		if (err) {
			patch_free(p);
			return err;
		}

		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
		switch (imsg.hdr.type) {
		case GOT_IMSG_PATCH_DONE:
			if (h != NULL && h->len == 0)
				err = got_error(GOT_ERR_PATCH_MALFORMED);
			goto done;
		case GOT_IMSG_PATCH_HUNK:
			if (h != NULL &&
			    (h->len == 0 || h->old_nonl || h->new_nonl)) {
				err = got_error(GOT_ERR_PATCH_MALFORMED);
				goto done;
			}
			lastmode = -1;
			if (datalen != sizeof(hdr)) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				goto done;
			}
			memcpy(&hdr, imsg.data, sizeof(hdr));
			if (hdr.oldfrom < 0 || hdr.newfrom < 0) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				goto done;
			}
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
			t = imsg.data;
			/* at least one char */
			if (datalen < 2 || t[datalen-1] != '\0') {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				goto done;
			}
			if (*t != ' ' && *t != '-' && *t != '+' &&
			    *t != '\\') {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				goto done;
			}

			if (*t != '\\')
				err = pushline(h, t, datalen);
			else if (lastmode == '-')
				h->old_nonl = 1;
			else if (lastmode == '+')
				h->new_nonl = 1;
			else
				err = got_error(GOT_ERR_PATCH_MALFORMED);

			if (err)
				goto done;

			lastmode = *t;
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			goto done;
		}

		imsg_free(&imsg);
	}

done:
	if (err)
		patch_free(p);

	imsg_free(&imsg);
	return err;
}

static void
reverse_patch(struct got_patch *p)
{
	struct got_patch_hunk *h;
	size_t i;
	int tmp;

	STAILQ_FOREACH(h, &p->head, entries) {
		tmp = h->old_from;
		h->old_from = h->new_from;
		h->new_from = tmp;

		tmp = h->old_lines;
		h->old_lines = h->new_lines;
		h->new_lines = tmp;

		tmp = h->old_nonl;
		h->old_nonl = h->new_nonl;
		h->new_nonl = tmp;

		for (i = 0; i < h->len; ++i) {
			if (h->lines[i].mode == '+')
				h->lines[i].mode = '-';
			else if (h->lines[i].mode == '-')
				h->lines[i].mode = '+';
		}
	}
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

	if (fseeko(orig, copypos, SEEK_SET) == -1)
		return got_error_from_errno("fseeko");

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
			return got_error(GOT_ERR_HUNK_FAILED);
		}
	}
	return NULL;
}

static int lines_eq(struct got_patch_line *, const char *, size_t, int *);

static const struct got_error *
locate_hunk(FILE *orig, struct got_patch_hunk *h, off_t *pos, int *lineno)
{
	const struct got_error *err = NULL;
	struct got_patch_line *l = &h->lines[0];
	char *line = NULL;
	char mode = l->mode;
	size_t linesize = 0;
	ssize_t linelen;
	off_t match = -1;
	int mangled = 0, match_lineno = -1;

	for (;;) {
		(*lineno)++;
		linelen = getline(&line, &linesize, orig);
		if (linelen == -1) {
			if (ferror(orig))
				err = got_error_from_errno("getline");
			/* An EOF is fine iff the target file is empty. */
			if (feof(orig) && match == -1 && h->old_lines != 0)
				err = got_error(GOT_ERR_HUNK_FAILED);
			match = 0;
			match_lineno = (*lineno)-1;
			break;
		}

		if ((mode == ' ' && lines_eq(l, line, linelen, &mangled)) ||
		    (mode == '-' && lines_eq(l, line, linelen, &mangled)) ||
		    (mode == '+' && *lineno == h->old_from)) {
			match = ftello(orig);
			if (match == -1) {
				err = got_error_from_errno("ftello");
				break;
			}
			match -= linelen;
			match_lineno = (*lineno)-1;
		}

		if (*lineno >= h->old_from && match != -1) {
			if (mangled)
				h->ws_mangled = 1;
			break;
		}
	}

	if (err == NULL) {
		*pos = match;
		*lineno = match_lineno;
		if (fseeko(orig, match, SEEK_SET) == -1)
			err = got_error_from_errno("fseeko");
	}

	free(line);
	return err;
}

static int
lines_eq(struct got_patch_line *l, const char *b, size_t len, int *mangled)
{
	char *a = l->line;
	size_t i, j;

	if (len > 00 && b[len - 1] == '\n')
		len--;

	*mangled = 0;
	if (l->len == len && !memcmp(a, b, len))
		return 1;

	*mangled = 1;

	i = j = 0;
	for (;;) {
		while (i < l->len &&
		    (a[i] == '\t' || a[i] == ' ' || a[i] == '\f'))
			i++;
		while (j < len &&
		    (b[j] == '\t' || b[j] == ' ' || b[j] == '\f'))
			j++;
		if (i == l->len || j == len || a[i] != b[j])
			break;
		i++, j++;
	}

	return (i == l->len && j == len);
}

static const struct got_error *
test_hunk(FILE *orig, struct got_patch_hunk *h)
{
	const struct got_error *err = NULL;
	char *line = NULL;
	size_t linesize = 0, i = 0;
	ssize_t linelen;
	int mangled;

	for (i = 0; i < h->len; ++i) {
		switch (h->lines[i].mode) {
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
					    GOT_ERR_HUNK_FAILED);
				goto done;
			}
			if (!lines_eq(&h->lines[i], line, linelen, &mangled)) {
				err = got_error(GOT_ERR_HUNK_FAILED);
				goto done;
			}
			if (mangled)
				h->ws_mangled = 1;
			break;
		}
	}

done:
	free(line);
	return err;
}

static const struct got_error *
apply_hunk(FILE *orig, FILE *tmp, struct got_patch_hunk *h, int *lineno,
    off_t from)
{
	const struct got_error *err = NULL;
	const char *t;
	size_t linesize = 0, i, new = 0;
	char *line = NULL;
	char mode;
	size_t l;
	ssize_t linelen;

	if (orig != NULL && fseeko(orig, from, SEEK_SET) == -1)
		return got_error_from_errno("fseeko");

	for (i = 0; i < h->len; ++i) {
		switch (mode = h->lines[i].mode) {
		case '-':
		case ' ':
			(*lineno)++;
			if (orig != NULL) {
				linelen = getline(&line, &linesize, orig);
				if (linelen == -1) {
					err = got_error_from_errno("getline");
					goto done;
				}
				if (line[linelen - 1] == '\n')
					line[linelen - 1] = '\0';
				t = line;
				l = linelen - 1;
			} else {
				t = h->lines[i].line;
				l = h->lines[i].len;
			}
			if (mode == '-')
				continue;
			if (fwrite(t, 1, l, tmp) != l ||
			    fputc('\n', tmp) == EOF) {
				err = got_error_from_errno("fprintf");
				goto done;
			}
			break;
		case '+':
			new++;
			t = h->lines[i].line;
			l = h->lines[i].len;
			if (fwrite(t, 1, l, tmp) != l) {
				err = got_error_from_errno("fprintf");
				goto done;
			}
			if (new != h->new_lines || !h->new_nonl) {
				if (fprintf(tmp, "\n") < 0) {
					err = got_error_from_errno("fprintf");
					goto done;
				}
			}
			break;
		}
	}

done:
	free(line);
	return err;
}

static const struct got_error *
patch_file(struct got_patch *p, FILE *orig, FILE *tmp)
{
	const struct got_error *err = NULL;
	struct got_patch_hunk *h;
	struct stat sb;
	int lineno = 0;
	off_t copypos, pos;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;

	if (p->old == NULL) {				/* create */
		h = STAILQ_FIRST(&p->head);
		if (h == NULL || STAILQ_NEXT(h, entries) != NULL)
			return got_error(GOT_ERR_PATCH_MALFORMED);
		return apply_hunk(orig, tmp, h, &lineno, 0);
	}

	/* When deleting binary files there are no hunks to apply. */
	if (p->new == NULL && STAILQ_EMPTY(&p->head))
		return NULL;

	if (fstat(fileno(orig), &sb) == -1)
		return got_error_from_errno("fstat");

	copypos = 0;
	STAILQ_FOREACH(h, &p->head, entries) {
	tryagain:
		err = locate_hunk(orig, h, &pos, &lineno);
		if (err != NULL && err->code == GOT_ERR_HUNK_FAILED)
			h->err = err;
		if (err != NULL)
			return err;
		err = copy(tmp, orig, copypos, pos);
		if (err != NULL)
			return err;
		copypos = pos;

		err = test_hunk(orig, h);
		if (err != NULL && err->code == GOT_ERR_HUNK_FAILED) {
			/*
			 * try to apply the hunk again starting the search
			 * after the previous partial match.
			 */
			if (fseeko(orig, pos, SEEK_SET) == -1)
				return got_error_from_errno("fseeko");
			linelen = getline(&line, &linesize, orig);
			if (linelen == -1)
				return got_error_from_errno("getline");
			lineno++;
			goto tryagain;
		}
		if (err != NULL)
			return err;

		if (lineno + 1 != h->old_from)
			h->offset = lineno + 1 - h->old_from;

		err = apply_hunk(orig, tmp, h, &lineno, pos);
		if (err != NULL)
			return err;

		copypos = ftello(orig);
		if (copypos == -1)
			return got_error_from_errno("ftello");
	}

	if (p->new == NULL && sb.st_size != copypos) {
		h = STAILQ_FIRST(&p->head);
		h->err = got_error(GOT_ERR_HUNK_FAILED);
		err = h->err;
	} else if (!feof(orig))
		err = copy(tmp, orig, copypos, -1);

	return err;
}

static const struct got_error *
report_progress(struct patch_args *pa, const char *old, const char *new,
    unsigned char status, const struct got_error *orig_error)
{
	const struct got_error *err;
	struct got_patch_hunk *h;

	err = pa->progress_cb(pa->progress_arg, old, new, status,
	    orig_error, 0, 0, 0, 0, 0, 0, NULL);
	if (err)
		return err;

	STAILQ_FOREACH(h, pa->head, entries) {
		if (h->offset == 0 && !h->ws_mangled && h->err == NULL)
			continue;

		err = pa->progress_cb(pa->progress_arg, old, new, 0, NULL,
		    h->old_from, h->old_lines, h->new_from, h->new_lines,
		    h->offset, h->ws_mangled, h->err);
		if (err)
			return err;
	}

	return NULL;
}

static const struct got_error *
patch_delete(void *arg, unsigned char status, unsigned char staged_status,
    const char *path)
{
	return report_progress(arg, path, NULL, status, NULL);
}

static const struct got_error *
patch_add(void *arg, unsigned char status, const char *path)
{
	return report_progress(arg, NULL, path, status, NULL);
}

static const struct got_error *
open_blob(char **path, FILE **fp, const char *blobid,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_blob_object *blob = NULL;
	struct got_object_id id, *idptr, *matched_id = NULL;
	enum got_hash_algorithm algo;
	int fd = -1;

	*fp = NULL;
	*path = NULL;
	algo = got_repo_get_object_format(repo);

	if (strlen(blobid) != got_hash_digest_string_length(algo) - 1) {
		err = got_repo_match_object_id(&matched_id, NULL, blobid,
		    GOT_OBJ_TYPE_BLOB, NULL /* do not resolve tags */,
		    repo);
		if (err)
			return err;
		idptr = matched_id;
	} else {
		if (!got_parse_object_id(&id, blobid, algo))
			return got_error(GOT_ERR_BAD_OBJ_ID_STR);
		idptr = &id;
	}

	fd = got_opentempfd();
	if (fd == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	err = got_object_open_as_blob(&blob, repo, idptr, 8192, fd);
	if (err)
		goto done;

	err = got_opentemp_named(path, fp, GOT_TMPDIR_STR "/got-patch-blob",
	    "");
	if (err)
		goto done;

	err = got_object_blob_dump_to_file(NULL, NULL, NULL, *fp, blob);
	if (err)
		goto done;

done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (blob)
		got_object_blob_close(blob);
	if (matched_id != NULL)
		free(matched_id);
	if (err) {
		if (*fp != NULL)
			fclose(*fp);
		if (*path != NULL)
			unlink(*path);
		free(*path);
		*fp = NULL;
		*path = NULL;
	}
	return err;
}

static const struct got_error *
prepare_merge(int *do_merge, char **apath, FILE **afile,
    struct got_worktree *worktree, struct got_repository *repo,
    struct got_patch *p, struct got_object_id *commit_id,
    struct got_tree_object *tree, const char *path)
{
	const struct got_error *err = NULL;

	*do_merge = 0;
	*apath = NULL;
	*afile = NULL;

	/* don't run the diff3 merge on creations/deletions */
	if (p->old == NULL || p->new == NULL)
		return NULL;

	if (commit_id) {
		struct got_object_id *id;

		err = got_object_tree_find_path(&id, NULL, repo, tree, path);
		if (err)
			return err;
		got_object_id_hex(id, p->blob, sizeof(p->blob));
		got_object_id_hex(commit_id, p->cid, sizeof(p->cid));
		free(id);
		err = open_blob(apath, afile, p->blob, repo);
		*do_merge = err == NULL;
	} else if (*p->blob != '\0') {
		err = open_blob(apath, afile, p->blob, repo);
		/*
		 * ignore failures to open this blob, we might have
		 * parsed gibberish.
		 */
		if (err && !(err->code == GOT_ERR_ERRNO && errno == ENOENT) &&
		    err->code != GOT_ERR_NO_OBJ)
			return err;
		*do_merge = err == NULL;
		err = NULL;
	}

	return err;
}

static const struct got_error *
apply_patch(int *overlapcnt, struct got_worktree *worktree,
    struct got_repository *repo, struct got_fileindex *fileindex,
    const char *old, const char *new, struct got_patch *p, int nop,
    int reverse, struct got_object_id *commit_id,
    struct got_tree_object *tree, struct patch_args *pa,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct stat sb;
	int do_merge = 0, file_renamed = 0;
	char *oldlabel = NULL, *newlabel = NULL, *anclabel = NULL;
	char *oldpath = NULL, *newpath = NULL;
	char *tmppath = NULL, *template = NULL;
	char *apath = NULL, *mergepath = NULL;
	FILE *oldfile = NULL, *tmpfile = NULL, *afile = NULL, *mergefile = NULL;
	int outfd;
	mode_t mode = GOT_DEFAULT_FILE_MODE;

	*overlapcnt = 0;

	err = prepare_merge(&do_merge, &apath, &afile, worktree, repo, p,
	    commit_id, tree, old);
	if (err)
		return err;

	if (reverse && !do_merge)
		reverse_patch(p);

	if (asprintf(&oldpath, "%s/%s", got_worktree_get_root_path(worktree),
	    old) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (asprintf(&newpath, "%s/%s", got_worktree_get_root_path(worktree),
	    new) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	file_renamed = strcmp(oldpath, newpath);

	if (asprintf(&template, "%s/got-patch",
	    got_worktree_get_root_path(worktree)) == -1) {
		err = got_error_from_errno(template);
		goto done;
	}

	if (p->old != NULL) {
		if ((oldfile = fopen(oldpath, "r")) == NULL) {
			err = got_error_from_errno2("open", oldpath);
			goto done;
		}
		if (fstat(fileno(oldfile), &sb) == -1) {
			err = got_error_from_errno2("fstat", oldpath);
			goto done;
		}
		mode = sb.st_mode;
	} else if (p->xbit)
		mode |= (S_IXUSR | S_IXGRP | S_IXOTH);

	err = got_opentemp_named(&tmppath, &tmpfile, template, "");
	if (err)
		goto done;
	outfd = fileno(tmpfile);
	err = patch_file(p, afile != NULL ? afile : oldfile, tmpfile);
	if (err)
		goto done;

	if (do_merge) {
		const char *type, *id;

		if (fseeko(afile, 0, SEEK_SET) == -1 ||
		    fseeko(oldfile, 0, SEEK_SET) == -1 ||
		    fseeko(tmpfile, 0, SEEK_SET) == -1) {
			err = got_error_from_errno("fseeko");
			goto done;
		}

		if (asprintf(&oldlabel, "--- %s", p->old) == -1) {
			err = got_error_from_errno("asprintf");
			oldlabel = NULL;
			goto done;
		}

		if (asprintf(&newlabel, "+++ %s", p->new) == -1) {
			err = got_error_from_errno("asprintf");
			newlabel = NULL;
			goto done;
		}

		if (*p->cid != '\0') {
			type = "commit";
			id = p->cid;
		} else {
			type = "blob";
			id = p->blob;
		}

		if (asprintf(&anclabel, "%s %s", type, id) == -1) {
			err = got_error_from_errno("asprintf");
			anclabel = NULL;
			goto done;
		}

		if (reverse) {
			char *s;
			FILE *t;

			s = anclabel;
			anclabel = newlabel;
			newlabel = s;

			t = afile;
			afile = tmpfile;
			tmpfile = t;
		}

		err = got_opentemp_named(&mergepath, &mergefile, template, "");
		if (err)
			goto done;
		outfd = fileno(mergefile);

		err = got_merge_diff3(overlapcnt, outfd, tmpfile, afile,
		    oldfile, oldlabel, anclabel, newlabel,
		    GOT_DIFF_ALGORITHM_PATIENCE);
		if (err)
			goto done;
	}

	if (nop)
		goto done;

	if (p->old != NULL && p->new == NULL) {
		err = got_worktree_patch_schedule_rm(old, repo, worktree,
		    fileindex, patch_delete, pa);
		goto done;
	}

	if (fchmod(outfd, apply_umask(mode)) == -1) {
		err = got_error_from_errno2("chmod", tmppath);
		goto done;
	}

	if (mergepath) {
		err = got_path_move_file(mergepath, newpath);
		if (err)
			goto done;
		free(mergepath);
		mergepath = NULL;
	} else {
		err = got_path_move_file(tmppath, newpath);
		if (err)
			goto done;
		free(tmppath);
		tmppath = NULL;
	}

	if (file_renamed) {
		err = got_worktree_patch_schedule_rm(old, repo, worktree,
		    fileindex, patch_delete, pa);
		if (err == NULL)
			err = got_worktree_patch_schedule_add(new, repo,
			    worktree, fileindex, patch_add,
			    pa);
		if (err)
			unlink(newpath);
	} else if (p->old == NULL) {
		err = got_worktree_patch_schedule_add(new, repo, worktree,
		    fileindex, patch_add, pa);
		if (err)
			unlink(newpath);
	} else if (*overlapcnt != 0)
		err = report_progress(pa, old, new, GOT_STATUS_CONFLICT, NULL);
	else if (do_merge)
		err = report_progress(pa, old, new, GOT_STATUS_MERGE, NULL);
	else
		err = report_progress(pa, old, new, GOT_STATUS_MODIFY, NULL);

done:
	free(template);

	if (tmppath != NULL && unlink(tmppath) == -1 && err == NULL)
		err = got_error_from_errno("unlink");
	if (tmpfile != NULL && fclose(tmpfile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	free(tmppath);

	free(oldpath);
	if (oldfile != NULL && fclose(oldfile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");

	if (apath != NULL && unlink(apath) == -1 && err == NULL)
		err = got_error_from_errno("unlink");
	if (afile != NULL && fclose(afile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	free(apath);

	if (mergepath != NULL && unlink(mergepath) == -1 && err == NULL)
		err = got_error_from_errno("unlink");
	if (mergefile != NULL && fclose(mergefile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	free(mergepath);

	free(newpath);
	free(oldlabel);
	free(newlabel);
	free(anclabel);
	return err;
}

const struct got_error *
got_patch(int fd, struct got_worktree *worktree, struct got_repository *repo,
    int nop, int strip, int reverse, struct got_object_id *commit_id,
    got_patch_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL, *complete_err = NULL;
	struct got_fileindex *fileindex = NULL;
	struct got_commit_object *commit = NULL;
	struct got_tree_object *tree = NULL;
	char *fileindex_path = NULL;
	char *oldpath, *newpath;
	struct imsgbuf *ibuf;
	int imsg_fds[2] = {-1, -1};
	int overlapcnt, done = 0, failed = 0;
	pid_t pid;

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
	if (imsgbuf_init(ibuf, imsg_fds[0]) == -1) {
		err = got_error_from_errno("imsgbuf_init");
		goto done;
	}
	imsgbuf_allow_fdpass(ibuf);

	err = send_patch(ibuf, fd);
	fd = -1;
	if (err)
		goto done;

	err = got_worktree_patch_prepare(&fileindex, &fileindex_path,
	    worktree, repo);
	if (err)
		goto done;

	if (commit_id) {
		err = got_object_open_as_commit(&commit, repo, commit_id);
		if (err)
			goto done;

		err = got_object_open_as_tree(&tree, repo, commit->tree_id);
		if (err)
			goto done;
	}

	while (!done && err == NULL) {
		struct got_patch p;
		struct patch_args pa;

		pa.progress_cb = progress_cb;
		pa.progress_arg = progress_arg;
		pa.head = &p.head;

		err = recv_patch(ibuf, &done, &p, strip);
		if (err || done)
			break;

		err = got_worktree_patch_check_path(p.old, p.new, &oldpath,
		    &newpath, worktree, repo, fileindex);
		if (err == NULL)
			err = apply_patch(&overlapcnt, worktree, repo,
			    fileindex, oldpath, newpath, &p, nop, reverse,
			    commit_id, tree, &pa, cancel_cb, cancel_arg);
		if (err != NULL) {
			failed = 1;
			/* recoverable errors */
			if (err->code == GOT_ERR_FILE_STATUS ||
			    (err->code == GOT_ERR_ERRNO && errno == ENOENT))
				err = report_progress(&pa, p.old, p.new,
				    GOT_STATUS_CANNOT_UPDATE, err);
			else if (err->code == GOT_ERR_HUNK_FAILED)
				err = report_progress(&pa, p.old, p.new,
				    GOT_STATUS_CANNOT_UPDATE, NULL);
		}
		if (overlapcnt != 0)
			failed = 1;

		free(oldpath);
		free(newpath);
		patch_free(&p);

		if (err)
			break;
	}

done:
	complete_err = got_worktree_patch_complete(worktree, fileindex,
	    fileindex_path);
	if (complete_err && err == NULL)
		err = complete_err;
	free(fileindex_path);
	if (tree)
		got_object_tree_close(tree);
	if (commit)
		got_object_commit_close(commit);
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (ibuf != NULL)
		imsgbuf_clear(ibuf);
	if (imsg_fds[0] != -1 && close(imsg_fds[0]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (imsg_fds[1] != -1 && close(imsg_fds[1]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (err == NULL && failed)
		err = got_error(GOT_ERR_PATCH_FAILED);
	return err;
}
