/*
 * Copyright (c) 2018, 2019 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/mman.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>
#include <libgen.h>
#include <limits.h>
#include <imsg.h>

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_opentemp.h"
#include "got_path.h"

#include "got_lib_hash.h"
#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_idcache.h"
#include "got_lib_object_cache.h"
#include "got_lib_object_parse.h"
#include "got_lib_pack.h"
#include "got_lib_repository.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct got_object_id *
got_object_get_id(struct got_object *obj)
{
	return &obj->id;
}

const struct got_error *
got_object_get_id_str(char **outbuf, struct got_object *obj)
{
	return got_object_id_str(outbuf, &obj->id);
}

const struct got_error *
got_object_get_type(int *type, struct got_repository *repo,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct got_object *obj;

	err = got_object_open(&obj, repo, id);
	if (err)
		return err;

	switch (obj->type) {
	case GOT_OBJ_TYPE_COMMIT:
	case GOT_OBJ_TYPE_TREE:
	case GOT_OBJ_TYPE_BLOB:
	case GOT_OBJ_TYPE_TAG:
		*type = obj->type;
		break;
	default:
		err = got_error(GOT_ERR_OBJ_TYPE);
		break;
	}

	got_object_close(obj);
	return err;
}

const struct got_error *
got_object_get_path(char **path, struct got_object_id *id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *hex = NULL;
	char *path_objects;

	*path = NULL;

	path_objects = got_repo_get_path_objects(repo);
	if (path_objects == NULL)
		return got_error_from_errno("got_repo_get_path_objects");

	err = got_object_id_str(&hex, id);
	if (err)
		goto done;

	if (asprintf(path, "%s/%.2x/%s", path_objects,
	    id->hash[0], hex + 2) == -1)
		err = got_error_from_errno("asprintf");

done:
	free(hex);
	free(path_objects);
	return err;
}

const struct got_error *
got_object_open_loose_fd(int *fd, struct got_object_id *id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path;

	err = got_object_get_path(&path, id, repo);
	if (err)
		return err;
	*fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (*fd == -1) {
		err = got_error_from_errno2("open", path);
		goto done;
	}
done:
	free(path);
	return err;
}

const struct got_error *
got_object_open_by_id_str(struct got_object **obj, struct got_repository *repo,
    const char *id_str)
{
	struct got_object_id id;

	if (!got_parse_object_id(&id, id_str, GOT_HASH_SHA1))
		return got_error_path(id_str, GOT_ERR_BAD_OBJ_ID_STR);

	return got_object_open(obj, repo, &id);
}

const struct got_error *
got_object_resolve_id_str(struct got_object_id **id,
    struct got_repository *repo, const char *id_str)
{
	const struct got_error *err = NULL;
	struct got_object *obj;

	err = got_object_open_by_id_str(&obj, repo, id_str);
	if (err)
		return err;

	*id = got_object_id_dup(got_object_get_id(obj));
	got_object_close(obj);
	if (*id == NULL)
		return got_error_from_errno("got_object_id_dup");

	return NULL;
}

int
got_object_tree_get_nentries(struct got_tree_object *tree)
{
	return tree->nentries;
}

struct got_tree_entry *
got_object_tree_get_first_entry(struct got_tree_object *tree)
{
	return got_object_tree_get_entry(tree, 0);
}

struct got_tree_entry *
got_object_tree_get_last_entry(struct got_tree_object *tree)
{
	return got_object_tree_get_entry(tree, tree->nentries - 1);
}

struct got_tree_entry *
got_object_tree_get_entry(struct got_tree_object *tree, int i)
{
	if (i < 0 || i >= tree->nentries)
		return NULL;
	return &tree->entries[i];
}

mode_t
got_tree_entry_get_mode(struct got_tree_entry *te)
{
	return te->mode;
}

const char *
got_tree_entry_get_name(struct got_tree_entry *te)
{
	return &te->name[0];
}

struct got_object_id *
got_tree_entry_get_id(struct got_tree_entry *te)
{
	return &te->id;
}

const struct got_error *
got_object_blob_read_to_str(char **s, struct got_blob_object *blob)
{
	const struct got_error *err = NULL;
	size_t len, totlen, hdrlen, offset;

	*s = NULL;

	hdrlen = got_object_blob_get_hdrlen(blob);
	totlen = 0;
	offset = 0;
	do {
		char *p;

		err = got_object_blob_read_block(&len, blob);
		if (err)
			return err;

		if (len == 0)
			break;

		totlen += len - hdrlen;
		p = realloc(*s, totlen + 1);
		if (p == NULL) {
			err = got_error_from_errno("realloc");
			free(*s);
			*s = NULL;
			return err;
		}
		*s = p;
		/* Skip blob object header first time around. */
		memcpy(*s + offset,
		    got_object_blob_get_read_buf(blob) + hdrlen, len - hdrlen);
		hdrlen = 0;
		offset = totlen;
	} while (len > 0);

	(*s)[totlen] = '\0';
	return NULL;
}

const struct got_error *
got_tree_entry_get_symlink_target(char **link_target, struct got_tree_entry *te,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_blob_object *blob = NULL;
	int fd = -1;

	*link_target = NULL;

	if (!got_object_tree_entry_is_symlink(te))
		return got_error(GOT_ERR_TREE_ENTRY_TYPE);

	fd = got_opentempfd();
	if (fd == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	err = got_object_open_as_blob(&blob, repo,
	    got_tree_entry_get_id(te), PATH_MAX, fd);
	if (err)
		goto done;

	err = got_object_blob_read_to_str(link_target, blob);
done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (blob)
		got_object_blob_close(blob);
	if (err) {
		free(*link_target);
		*link_target = NULL;
	}
	return err;
}

int
got_tree_entry_get_index(struct got_tree_entry *te)
{
	return te->idx;
}

struct got_tree_entry *
got_tree_entry_get_next(struct got_tree_object *tree,
    struct got_tree_entry *te)
{
	return got_object_tree_get_entry(tree, te->idx + 1);
}

struct got_tree_entry *
got_tree_entry_get_prev(struct got_tree_object *tree,
    struct got_tree_entry *te)
{
	return got_object_tree_get_entry(tree, te->idx - 1);
}

const struct got_error *
got_object_blob_close(struct got_blob_object *blob)
{
	const struct got_error *err = NULL;
	free(blob->read_buf);
	if (blob->f && fclose(blob->f) == EOF)
		err = got_error_from_errno("fclose");
	free(blob->data);
	free(blob);
	return err;
}

void
got_object_blob_rewind(struct got_blob_object *blob)
{
	if (blob->f)
		rewind(blob->f);
}

char *
got_object_blob_id_str(struct got_blob_object *blob, char *buf, size_t size)
{
	return got_object_id_hex(&blob->id, buf, size);
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
got_object_blob_is_binary(int *binary, struct got_blob_object *blob)
{
	const struct got_error *err;
	size_t hdrlen, len;

	*binary = 0;
	hdrlen = got_object_blob_get_hdrlen(blob);

	if (fseeko(blob->f, hdrlen, SEEK_SET) == -1)
		return got_error_from_errno("fseeko");

	err = got_object_blob_read_block(&len, blob);
	if (err)
		return err;

	*binary = memchr(blob->read_buf, '\0', len) != NULL;

	if (fseeko(blob->f, hdrlen, SEEK_SET) == -1)
		return got_error_from_errno("fseeko");
	return NULL;
}

const struct got_error *
got_object_blob_getline(char **line, ssize_t *linelen, size_t *linesize,
    struct got_blob_object *blob)
{
	*linelen = getline(line, linesize, blob->f);
	if (*linelen == -1 && !feof(blob->f))
		return got_error_from_errno("getline");
	return NULL;
}

const struct got_error *
got_object_blob_dump_to_file(off_t *filesize, int *nlines,
    off_t **line_offsets, FILE *outfile, struct got_blob_object *blob)
{
	const struct got_error *err = NULL;
	size_t n, len, hdrlen;
	const uint8_t *buf;
	int i;
	const int alloc_chunksz = 512;
	size_t nalloc = 0;
	off_t off = 0, total_len = 0;

	if (line_offsets)
		*line_offsets = NULL;
	if (filesize)
		*filesize = 0;
	if (nlines)
		*nlines = 0;

	hdrlen = got_object_blob_get_hdrlen(blob);
	do {
		err = got_object_blob_read_block(&len, blob);
		if (err)
			return err;
		if (len == 0)
			break;
		buf = got_object_blob_get_read_buf(blob);
		i = hdrlen;
		if (nlines) {
			if (line_offsets && *line_offsets == NULL) {
				/* Have some data but perhaps no '\n'. */
				*nlines = 1;
				nalloc = alloc_chunksz;
				*line_offsets = calloc(nalloc,
				    sizeof(**line_offsets));
				if (*line_offsets == NULL)
					return got_error_from_errno("calloc");

				/* Skip forward over end of first line. */
				while (i < len) {
					if (buf[i] == '\n')
						break;
					i++;
				}
			}
			/* Scan '\n' offsets in remaining chunk of data. */
			while (i < len) {
				if (buf[i] != '\n') {
					i++;
					continue;
				}
				(*nlines)++;
				if (line_offsets && nalloc < *nlines) {
					size_t n = *nlines + alloc_chunksz;
					off_t *o = recallocarray(*line_offsets,
					    nalloc, n, sizeof(**line_offsets));
					if (o == NULL) {
						free(*line_offsets);
						*line_offsets = NULL;
						return got_error_from_errno(
						    "recallocarray");
					}
					*line_offsets = o;
					nalloc = n;
				}
				if (line_offsets) {
					off = total_len + i - hdrlen + 1;
					(*line_offsets)[*nlines - 1] = off;
				}
				i++;
			}
		}
		/* Skip blob object header first time around. */
		n = fwrite(buf + hdrlen, 1, len - hdrlen, outfile);
		if (n != len - hdrlen)
			return got_ferror(outfile, GOT_ERR_IO);
		total_len += len - hdrlen;
		hdrlen = 0;
	} while (len != 0);

	if (fflush(outfile) != 0)
		return got_error_from_errno("fflush");
	rewind(outfile);

	if (filesize)
		*filesize = total_len;

	return NULL;
}

const char *
got_object_tag_get_name(struct got_tag_object *tag)
{
	return tag->tag;
}

int
got_object_tag_get_object_type(struct got_tag_object *tag)
{
	return tag->obj_type;
}

struct got_object_id *
got_object_tag_get_object_id(struct got_tag_object *tag)
{
	return &tag->id;
}

time_t
got_object_tag_get_tagger_time(struct got_tag_object *tag)
{
	return tag->tagger_time;
}

time_t
got_object_tag_get_tagger_gmtoff(struct got_tag_object *tag)
{
	return tag->tagger_gmtoff;
}

const char *
got_object_tag_get_tagger(struct got_tag_object *tag)
{
	return tag->tagger;
}

const char *
got_object_tag_get_message(struct got_tag_object *tag)
{
	return tag->tagmsg;
}

static struct got_tree_entry *
find_entry_by_name(struct got_tree_object *tree, const char *name, size_t len)
{
	int i;

	/* Note that tree entries are sorted in strncmp() order. */
	for (i = 0; i < tree->nentries; i++) {
		struct got_tree_entry *te = &tree->entries[i];
		int cmp = strncmp(te->name, name, len);
		if (cmp < 0)
			continue;
		if (cmp > 0)
			break;
		if (te->name[len] == '\0')
			return te;
	}
	return NULL;
}

struct got_tree_entry *
got_object_tree_find_entry(struct got_tree_object *tree, const char *name)
{
	return find_entry_by_name(tree, name, strlen(name));
}

const struct got_error *
got_object_tree_find_path(struct got_object_id **id, mode_t *mode,
    struct got_repository *repo, struct got_tree_object *tree,
    const char *path)
{
	const struct got_error *err = NULL;
	struct got_tree_object *subtree = NULL;
	struct got_tree_entry *te = NULL;
	const char *seg, *s;
	size_t seglen;

	*id = NULL;

	s = path;
	while (s[0] == '/')
		s++;
	seg = s;
	seglen = 0;
	subtree = tree;
	while (*s) {
		struct got_tree_object *next_tree;

		if (*s != '/') {
			s++;
			seglen++;
			if (*s)
				continue;
		}

		te = find_entry_by_name(subtree, seg, seglen);
		if (te == NULL) {
			err = got_error_path(path, GOT_ERR_NO_TREE_ENTRY);
			goto done;
		}

		if (*s == '\0')
			break;

		seg = s + 1;
		seglen = 0;
		s++;
		if (*s) {
			err = got_object_open_as_tree(&next_tree, repo,
			    &te->id);
			te = NULL;
			if (err)
				goto done;
			if (subtree != tree)
				got_object_tree_close(subtree);
			subtree = next_tree;
		}
	}

	if (te) {
		*id = got_object_id_dup(&te->id);
		if (*id == NULL)
			return got_error_from_errno("got_object_id_dup");
		if (mode)
			*mode = te->mode;
	} else
		err = got_error_path(path, GOT_ERR_NO_TREE_ENTRY);
done:
	if (subtree && subtree != tree)
		got_object_tree_close(subtree);
	return err;
}

const struct got_error *
got_object_id_by_path(struct got_object_id **id, struct got_repository *repo,
    struct got_commit_object *commit, const char *path)
{
	const struct got_error *err = NULL;
	struct got_tree_object *tree = NULL;

	*id = NULL;

	/* Handle opening of root of commit's tree. */
	if (got_path_is_root_dir(path)) {
		*id = got_object_id_dup(commit->tree_id);
		if (*id == NULL)
			err = got_error_from_errno("got_object_id_dup");
	} else {
		err = got_object_open_as_tree(&tree, repo, commit->tree_id);
		if (err)
			goto done;
		err = got_object_tree_find_path(id, NULL, repo, tree, path);
	}
done:
	if (tree)
		got_object_tree_close(tree);
	return err;
}

/*
 * Normalize file mode bits to avoid false positive tree entry differences
 * in case tree entries have unexpected mode bits set.
 */
static mode_t
normalize_mode_for_comparison(mode_t mode)
{
	/*
	 * For directories, the only relevant bit is the IFDIR bit.
	 * This allows us to detect paths changing from a directory
	 * to a file and vice versa.
	 */
	if (S_ISDIR(mode))
		return mode & S_IFDIR;

	/*
	 * For symlinks, the only relevant bit is the IFLNK bit.
	 * This allows us to detect paths changing from a symlinks
	 * to a file or directory and vice versa.
	 */
	if (S_ISLNK(mode))
		return mode & S_IFLNK;

	/* For files, the only change we care about is the executable bit. */
	return mode & S_IXUSR;
}

const struct got_error *
got_object_tree_path_changed(int *changed,
    struct got_tree_object *tree01, struct got_tree_object *tree02,
    const char *path, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_tree_object *tree1 = NULL, *tree2 = NULL;
	struct got_tree_entry *te1 = NULL, *te2 = NULL;
	const char *seg, *s;
	size_t seglen;

	*changed = 0;

	/* We not do support comparing the root path. */
	if (got_path_is_root_dir(path))
		return got_error_path(path, GOT_ERR_BAD_PATH);

	tree1 = tree01;
	tree2 = tree02;
	s = path;
	while (*s == '/')
		s++;
	seg = s;
	seglen = 0;
	while (*s) {
		struct got_tree_object *next_tree1, *next_tree2;
		mode_t mode1, mode2;

		if (*s != '/') {
			s++;
			seglen++;
			if (*s)
				continue;
		}

		te1 = find_entry_by_name(tree1, seg, seglen);
		if (te1 == NULL) {
			err = got_error(GOT_ERR_NO_OBJ);
			goto done;
		}

		if (tree2)
			te2 = find_entry_by_name(tree2, seg, seglen);

		if (te2) {
			mode1 = normalize_mode_for_comparison(te1->mode);
			mode2 = normalize_mode_for_comparison(te2->mode);
			if (mode1 != mode2) {
				*changed = 1;
				goto done;
			}

			if (got_object_id_cmp(&te1->id, &te2->id) == 0) {
				*changed = 0;
				goto done;
			}
		}

		if (*s == '\0') { /* final path element */
			*changed = 1;
			goto done;
		}

		seg = s + 1;
		s++;
		seglen = 0;
		if (*s) {
			err = got_object_open_as_tree(&next_tree1, repo,
			    &te1->id);
			te1 = NULL;
			if (err)
				goto done;
			if (tree1 != tree01)
				got_object_tree_close(tree1);
			tree1 = next_tree1;

			if (te2) {
				err = got_object_open_as_tree(&next_tree2, repo,
				    &te2->id);
				te2 = NULL;
				if (err)
					goto done;
				if (tree2 != tree02)
					got_object_tree_close(tree2);
				tree2 = next_tree2;
			} else if (tree2) {
				if (tree2 != tree02)
					got_object_tree_close(tree2);
				tree2 = NULL;
			}
		}
	}
done:
	if (tree1 && tree1 != tree01)
		got_object_tree_close(tree1);
	if (tree2 && tree2 != tree02)
		got_object_tree_close(tree2);
	return err;
}

const struct got_error *
got_object_tree_entry_dup(struct got_tree_entry **new_te,
    struct got_tree_entry *te)
{
	const struct got_error *err = NULL;

	*new_te = calloc(1, sizeof(**new_te));
	if (*new_te == NULL)
		return got_error_from_errno("calloc");

	(*new_te)->mode = te->mode;
	memcpy((*new_te)->name, te->name, sizeof((*new_te)->name));
	memcpy(&(*new_te)->id, &te->id, sizeof((*new_te)->id));
	return err;
}

int
got_object_tree_entry_is_submodule(struct got_tree_entry *te)
{
	return (te->mode & S_IFMT) == (S_IFDIR | S_IFLNK);
}

int
got_object_tree_entry_is_symlink(struct got_tree_entry *te)
{
	/* S_IFDIR check avoids confusing symlinks with submodules. */
	return ((te->mode & (S_IFDIR | S_IFLNK)) == S_IFLNK);
}

static const struct got_error *
resolve_symlink(char **link_target, const char *path,
    struct got_commit_object *commit, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char buf[PATH_MAX];
	char *name, *parent_path = NULL;
	struct got_object_id *tree_obj_id = NULL;
	struct got_tree_object *tree = NULL;
	struct got_tree_entry *te = NULL;

	*link_target = NULL;

	if (strlcpy(buf, path, sizeof(buf)) >= sizeof(buf))
		return got_error(GOT_ERR_NO_SPACE);

	name = basename(buf);
	if (name == NULL)
		return got_error_from_errno2("basename", path);

	err = got_path_dirname(&parent_path, path);
	if (err)
		return err;

	err = got_object_id_by_path(&tree_obj_id, repo, commit,
	    parent_path);
	if (err) {
		if (err->code == GOT_ERR_NO_TREE_ENTRY) {
			/* Display the complete path in error message. */
			err = got_error_path(path, err->code);
		}
		goto done;
	}

	err = got_object_open_as_tree(&tree, repo, tree_obj_id);
	if (err)
		goto done;

	te = got_object_tree_find_entry(tree, name);
	if (te == NULL) {
		err = got_error_path(path, GOT_ERR_NO_TREE_ENTRY);
		goto done;
	}

	if (got_object_tree_entry_is_symlink(te)) {
		err = got_tree_entry_get_symlink_target(link_target, te, repo);
		if (err)
			goto done;
		if (!got_path_is_absolute(*link_target)) {
			char *abspath;
			if (asprintf(&abspath, "%s/%s", parent_path,
			    *link_target) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
			free(*link_target);
			*link_target = malloc(PATH_MAX);
			if (*link_target == NULL) {
				err = got_error_from_errno("malloc");
				goto done;
			}
			err = got_canonpath(abspath, *link_target, PATH_MAX);
			free(abspath);
			if (err)
				goto done;
		}
	}
done:
	free(parent_path);
	free(tree_obj_id);
	if (tree)
		got_object_tree_close(tree);
	if (err) {
		free(*link_target);
		*link_target = NULL;
	}
	return err;
}

const struct got_error *
got_object_resolve_symlinks(char **link_target, const char *path,
    struct got_commit_object *commit, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *next_target = NULL;
	int max_recursion = 40; /* matches Git */

	*link_target = NULL;

	do {
		err = resolve_symlink(&next_target,
		    *link_target ? *link_target : path, commit, repo);
		if (err)
			break;
		if (next_target) {
			free(*link_target);
			if (--max_recursion == 0) {
				err = got_error_path(path, GOT_ERR_RECURSION);
				*link_target = NULL;
				break;
			}
			*link_target = next_target;
		}
	} while (next_target);

	return err;
}

void
got_object_commit_retain(struct got_commit_object *commit)
{
	commit->refcnt++;
}

const struct got_error *
got_object_raw_alloc(struct got_raw_object **obj, uint8_t *outbuf, int *outfd,
    size_t max_in_mem_size, size_t hdrlen, off_t size)
{
	const struct got_error *err = NULL;
	off_t tot;

	tot = hdrlen + size;

	*obj = calloc(1, sizeof(**obj));
	if (*obj == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}
	(*obj)->fd = -1;
	(*obj)->tempfile_idx = -1;

	if (outbuf) {
		(*obj)->data = outbuf;
	} else {
		struct stat sb;
		if (fstat(*outfd, &sb) == -1) {
			err = got_error_from_errno("fstat");
			goto done;
		}

		if (sb.st_size != tot) {
			err = got_error_msg(GOT_ERR_BAD_OBJ_HDR,
			    "raw object has unexpected size");
			goto done;
		}
#ifndef GOT_PACK_NO_MMAP
		if (tot > 0 && tot <= max_in_mem_size) {
			(*obj)->data = mmap(NULL, tot, PROT_READ,
			    MAP_PRIVATE, *outfd, 0);
			if ((*obj)->data == MAP_FAILED) {
				if (errno != ENOMEM) {
					err = got_error_from_errno("mmap");
					goto done;
				}
				(*obj)->data = NULL;
			} else {
				(*obj)->fd = *outfd;
				*outfd = -1;
			}
		}
#endif
		if (*outfd != -1) {
			(*obj)->f = fdopen(*outfd, "r");
			if ((*obj)->f == NULL) {
				err = got_error_from_errno("fdopen");
				goto done;
			}
			*outfd = -1;
		}
	}
	(*obj)->hdrlen = hdrlen;
	(*obj)->size = size;
done:
	if (err) {
		if (*obj) {
			got_object_raw_close(*obj);
			*obj = NULL;
		}
	} else
		(*obj)->refcnt++;
	return err;
}
