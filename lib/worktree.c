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

#include <sys/stat.h>
#include <sys/limits.h>
#include <sys/queue.h>

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sha1.h>
#include <zlib.h>
#include <fnmatch.h>
#include <libgen.h>

#include "got_error.h"
#include "got_repository.h"
#include "got_reference.h"
#include "got_object.h"
#include "got_worktree.h"
#include "got_opentemp.h"

#include "got_lib_worktree.h"
#include "got_lib_path.h"
#include "got_lib_sha1.h"
#include "got_lib_fileindex.h"
#include "got_lib_inflate.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

static const struct got_error *
create_meta_file(const char *path_got, const char *name, const char *content)
{
	const struct got_error *err = NULL;
	char *path;
	int fd = -1;

	if (asprintf(&path, "%s/%s", path_got, name) == -1) {
		err = got_error_from_errno();
		path = NULL;
		goto done;
	}

	fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW,
	    GOT_DEFAULT_FILE_MODE);
	if (fd == -1) {
		err = got_error_from_errno();
		goto done;
	}

	if (content) {
		int len = dprintf(fd, "%s\n", content);
		if (len != strlen(content) + 1) {
			err = got_error_from_errno();
			goto done;
		}
	}

done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno();
	free(path);
	return err;
}

static const struct got_error *
update_meta_file(const char *path_got, const char *name, const char *content)
{
	const struct got_error *err = NULL;
	FILE *tmpfile = NULL;
	char *tmppath = NULL;
	char *path = NULL;

	if (asprintf(&path, "%s/%s", path_got, name) == -1) {
		err = got_error_from_errno();
		path = NULL;
		goto done;
	}

	err = got_opentemp_named(&tmppath, &tmpfile, path);
	if (err)
		goto done;

	if (content) {
		int len = fprintf(tmpfile, "%s\n", content);
		if (len != strlen(content) + 1) {
			err = got_error_from_errno();
			goto done;
		}
	}

	if (rename(tmppath, path) != 0) {
		err = got_error_from_errno();
		goto done;
	}

done:
	free(tmppath);
	fclose(tmpfile);
	return err;
}

static const struct got_error *
read_meta_file(char **content, const char *path_got, const char *name)
{
	const struct got_error *err = NULL;
	char *path;
	int fd = -1;
	ssize_t n;
	struct stat sb;

	*content = NULL;

	if (asprintf(&path, "%s/%s", path_got, name) == -1) {
		err = got_error_from_errno();
		path = NULL;
		goto done;
	}

	fd = open(path, O_RDONLY | O_NOFOLLOW);
	if (fd == -1) {
		err = got_error_from_errno();
		goto done;
	}
	if (flock(fd, LOCK_SH | LOCK_NB) == -1) {
		err = (errno == EWOULDBLOCK ? got_error(GOT_ERR_WORKTREE_BUSY)
		    : got_error_from_errno());
		goto done;
	}

	stat(path, &sb);
	*content = calloc(1, sb.st_size);
	if (*content == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	n = read(fd, *content, sb.st_size);
	if (n != sb.st_size) {
		err = (n == -1 ? got_error_from_errno() :
		    got_error(GOT_ERR_WORKTREE_META));
		goto done;
	}
	if ((*content)[sb.st_size - 1] != '\n') {
		err = got_error(GOT_ERR_WORKTREE_META);
		goto done;
	}
	(*content)[sb.st_size - 1] = '\0';

done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno();
	free(path);
	if (err) {
		free(*content);
		*content = NULL;
	}
	return err;
}

const struct got_error *
got_worktree_init(const char *path, struct got_reference *head_ref,
    const char *prefix, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id *commit_id = NULL;
	int obj_type;
	char *path_got = NULL;
	char *refstr = NULL;
	char *formatstr = NULL;
	char *absprefix = NULL;
	char *basestr = NULL;

	err = got_ref_resolve(&commit_id, repo, head_ref);
	if (err)
		return err;
	err = got_object_get_type(&obj_type, repo, commit_id);
	if (err)
		return err;
	if (obj_type != GOT_OBJ_TYPE_COMMIT)
		return got_error(GOT_ERR_OBJ_TYPE);

	if (!got_path_is_absolute(prefix)) {
		if (asprintf(&absprefix, "/%s", prefix) == -1)
			return got_error_from_errno();
	}

	/* Create top-level directory (may already exist). */
	if (mkdir(path, GOT_DEFAULT_DIR_MODE) == -1 && errno != EEXIST) {
		err = got_error_from_errno();
		goto done;
	}

	/* Create .got directory (may already exist). */
	if (asprintf(&path_got, "%s/%s", path, GOT_WORKTREE_GOT_DIR) == -1) {
		err = got_error_from_errno();
		goto done;
	}
	if (mkdir(path_got, GOT_DEFAULT_DIR_MODE) == -1 && errno != EEXIST) {
		err = got_error_from_errno();
		goto done;
	}

	/* Create an empty lock file. */
	err = create_meta_file(path_got, GOT_WORKTREE_LOCK, NULL);
	if (err)
		goto done;

	/* Create an empty file index. */
	err = create_meta_file(path_got, GOT_WORKTREE_FILE_INDEX, NULL);
	if (err)
		goto done;

	/* Write the HEAD reference. */
	refstr = got_ref_to_str(head_ref);
	if (refstr == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	err = create_meta_file(path_got, GOT_WORKTREE_HEAD_REF, refstr);
	if (err)
		goto done;

	/* Record our base commit. */
	err = got_object_id_str(&basestr, commit_id);
	if (err)
		goto done;
	err = create_meta_file(path_got, GOT_WORKTREE_BASE_COMMIT, basestr);
	if (err)
		goto done;

	/* Store path to repository. */
	err = create_meta_file(path_got, GOT_WORKTREE_REPOSITORY,
	    got_repo_get_path(repo));
	if (err)
		goto done;

	/* Store in-repository path prefix. */
	err = create_meta_file(path_got, GOT_WORKTREE_PATH_PREFIX,
	    absprefix ? absprefix : prefix);
	if (err)
		goto done;

	/* Stamp work tree with format file. */
	if (asprintf(&formatstr, "%d", GOT_WORKTREE_FORMAT_VERSION) == -1) {
		err = got_error_from_errno();
		goto done;
	}
	err = create_meta_file(path_got, GOT_WORKTREE_FORMAT, formatstr);
	if (err)
		goto done;

done:
	free(commit_id);
	free(path_got);
	free(formatstr);
	free(refstr);
	free(absprefix);
	free(basestr);
	return err;
}

const struct got_error *
got_worktree_open(struct got_worktree **worktree, const char *path)
{
	const struct got_error *err = NULL;
	char *path_got;
	char *formatstr = NULL;
	char *path_lock = NULL;
	char *base_commit_id_str = NULL;
	char *head_ref_str = NULL;
	int version, fd = -1;
	const char *errstr;
	struct got_repository *repo = NULL;

	*worktree = NULL;

	if (asprintf(&path_got, "%s/%s", path, GOT_WORKTREE_GOT_DIR) == -1) {
		err = got_error_from_errno();
		path_got = NULL;
		goto done;
	}

	if (asprintf(&path_lock, "%s/%s", path_got, GOT_WORKTREE_LOCK) == -1) {
		err = got_error_from_errno();
		path_lock = NULL;
		goto done;
	}

	fd = open(path_lock, O_RDWR | O_EXLOCK | O_NONBLOCK);
	if (fd == -1) {
		err = (errno == EWOULDBLOCK ? got_error(GOT_ERR_WORKTREE_BUSY)
		    : got_error_from_errno());
		goto done;
	}

	err = read_meta_file(&formatstr, path_got, GOT_WORKTREE_FORMAT);
	if (err)
		goto done;

	version = strtonum(formatstr, 1, INT_MAX, &errstr);
	if (errstr) {
		err = got_error(GOT_ERR_WORKTREE_META);
		goto done;
	}
	if (version != GOT_WORKTREE_FORMAT_VERSION) {
		err = got_error(GOT_ERR_WORKTREE_VERS);
		goto done;
	}

	*worktree = calloc(1, sizeof(**worktree));
	if (*worktree == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	(*worktree)->lockfd = -1;

	(*worktree)->root_path = strdup(path);
	if ((*worktree)->root_path == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	err = read_meta_file(&(*worktree)->repo_path, path_got,
	    GOT_WORKTREE_REPOSITORY);
	if (err)
		goto done;

	err = read_meta_file(&(*worktree)->path_prefix, path_got,
	    GOT_WORKTREE_PATH_PREFIX);
	if (err)
		goto done;

	err = read_meta_file(&base_commit_id_str, path_got,
	    GOT_WORKTREE_BASE_COMMIT);
	if (err)
		goto done;

	err = got_repo_open(&repo, (*worktree)->repo_path);
	if (err)
		goto done;

	err = got_object_resolve_id_str(&(*worktree)->base_commit_id, repo,
	    base_commit_id_str);
	if (err)
		goto done;

	err = read_meta_file(&head_ref_str, path_got, GOT_WORKTREE_HEAD_REF);
	if (err)
		goto done;

	err = got_ref_open(&(*worktree)->head_ref, repo, head_ref_str);
done:
	if (repo)
		got_repo_close(repo);
	free(path_got);
	free(path_lock);
	free(head_ref_str);
	free(base_commit_id_str);
	if (err) {
		if (fd != -1)
			close(fd);
		if (*worktree != NULL)
			got_worktree_close(*worktree);
		*worktree = NULL;
	} else
		(*worktree)->lockfd = fd;

	return err;
}

void
got_worktree_close(struct got_worktree *worktree)
{
	free(worktree->root_path);
	free(worktree->repo_path);
	free(worktree->path_prefix);
	free(worktree->base_commit_id);
	if (worktree->head_ref)
		got_ref_close(worktree->head_ref);
	if (worktree->lockfd != -1)
		close(worktree->lockfd);
	free(worktree);
}

const char *
got_worktree_get_repo_path(struct got_worktree *worktree)
{
	return worktree->repo_path;
}

const char *
got_worktree_get_path_prefix(struct got_worktree *worktree)
{
	return worktree->path_prefix;
}

const struct got_error *
got_worktree_match_path_prefix(int *match, struct got_worktree *worktree,
    const char *path_prefix)
{
	char *absprefix = NULL;

	if (!got_path_is_absolute(path_prefix)) {
		if (asprintf(&absprefix, "/%s", path_prefix) == -1)
			return got_error_from_errno();
	}
	*match = (strcmp(absprefix ? absprefix : path_prefix,
	    worktree->path_prefix) == 0);
	free(absprefix);
	return NULL;
}

char *
got_worktree_get_head_ref_name(struct got_worktree *worktree)
{
	return got_ref_to_str(worktree->head_ref);
}

struct got_reference *
got_worktree_get_head_ref(struct got_worktree *worktree)
{
	return got_ref_dup(worktree->head_ref);
}

const struct got_object_id *
got_worktree_get_base_commit_id(struct got_worktree *worktree)
{
	return worktree->base_commit_id;
}

const struct got_error *
got_worktree_set_base_commit_id(struct got_worktree *worktree,
    struct got_repository *repo, struct got_object_id *commit_id)
{
	const struct got_error *err;
	struct got_object *obj = NULL;
	char *id_str = NULL;
	char *path_got = NULL;

	if (asprintf(&path_got, "%s/%s", worktree->root_path,
	    GOT_WORKTREE_GOT_DIR) == -1) {
		err = got_error_from_errno();
		path_got = NULL;
		goto done;
	}

	err = got_object_open(&obj, repo, commit_id);
	if (err)
		return err;

	if (obj->type != GOT_OBJ_TYPE_COMMIT) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	/* Record our base commit. */
	err = got_object_id_str(&id_str, commit_id);
	if (err)
		goto done;
	err = update_meta_file(path_got, GOT_WORKTREE_BASE_COMMIT, id_str);
	if (err)
		goto done;

	free(worktree->base_commit_id);
	worktree->base_commit_id = got_object_id_dup(commit_id);
	if (worktree->base_commit_id == NULL) {
		err = got_error_from_errno();
		goto done;
	}
done:
	if (obj)
		got_object_close(obj);
	free(id_str);
	free(path_got);
	return err;
}

static const struct got_error *
lock_worktree(struct got_worktree *worktree, int operation)
{
	if (flock(worktree->lockfd, operation | LOCK_NB) == -1)
		return (errno == EWOULDBLOCK ? got_error(GOT_ERR_WORKTREE_BUSY)
		    : got_error_from_errno());
	return NULL;
}

static const char *
apply_path_prefix(struct got_worktree *worktree, const char *path)
{
	const char *p = path;
	p += strlen(worktree->path_prefix);
	if (*p == '/')
		p++;
	return p;
}

static const struct got_error *
blob_checkout(struct got_worktree *worktree, struct got_fileindex *fileindex,
   struct got_fileindex_entry *entry, const char *path,
   struct got_blob_object *blob, struct got_repository *repo,
   got_worktree_checkout_cb progress_cb, void *progress_arg,
   const char *progress_path)
{
	const struct got_error *err = NULL;
	char *ondisk_path;
	int fd = -1;
	size_t len, hdrlen;
	int update = 0;
	char *tmppath = NULL;

	if (asprintf(&ondisk_path, "%s/%s", worktree->root_path,
	    apply_path_prefix(worktree, path)) == -1)
		return got_error_from_errno();

	fd = open(ondisk_path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW,
	    GOT_DEFAULT_FILE_MODE);
	if (fd == -1) {
		err = got_error_from_errno();
		if (errno == EEXIST) {
			struct stat sb;
			if (lstat(ondisk_path, &sb) == -1) {
				err = got_error_from_errno();
				goto done;
			} else if (!S_ISREG(sb.st_mode)) {
				/* TODO file is obstructed; do something */
				err = got_error(GOT_ERR_FILE_OBSTRUCTED);
				goto done;
			} else {
				err = got_opentemp_named_fd(&tmppath, &fd,
				    ondisk_path);
				if (err)
					goto done;
				update = 1;
			}
		} else
			return err;
	}

	(*progress_cb)(progress_arg,
	    update ? GOT_STATUS_UPDATE : GOT_STATUS_ADD, progress_path);

	hdrlen = got_object_blob_get_hdrlen(blob);
	do {
		const uint8_t *buf = got_object_blob_get_read_buf(blob);
		err = got_object_blob_read_block(&len, blob);
		if (err)
			break;
		if (len > 0) {
			/* Skip blob object header first time around. */
			ssize_t outlen = write(fd, buf + hdrlen, len - hdrlen);
			if (outlen == -1) {
				err = got_error_from_errno();
				goto done;
			} else if (outlen != len - hdrlen) {
				err = got_error(GOT_ERR_IO);
				goto done;
			}
			hdrlen = 0;
		}
	} while (len != 0);

	fsync(fd);

	if (update) {
		if (rename(tmppath, ondisk_path) != 0) {
			err = got_error_from_errno();
			goto done;
		}
	}

	if (entry)
		err = got_fileindex_entry_update(entry, ondisk_path,
		    blob->id.sha1, worktree->base_commit_id->sha1);
	else {
		err = got_fileindex_entry_alloc(&entry, ondisk_path,
		    apply_path_prefix(worktree, path), blob->id.sha1,
		    worktree->base_commit_id->sha1);
		if (err)
			goto done;
		err = got_fileindex_entry_add(fileindex, entry);
	}
	if (err)
		goto done;
done:
	if (fd != -1)
		close(fd);
	free(ondisk_path);
	free(tmppath);
	return err;
}

static const struct got_error *
add_dir_on_disk(struct got_worktree *worktree, const char *path)
{
	const struct got_error *err = NULL;
	char *abspath;

	if (asprintf(&abspath, "%s/%s", worktree->root_path,
	    apply_path_prefix(worktree, path)) == -1)
		return got_error_from_errno();

	/* XXX queue work rather than editing disk directly? */
	if (mkdir(abspath, GOT_DEFAULT_DIR_MODE) == -1) {
		struct stat sb;

		if (errno != EEXIST) {
			err = got_error_from_errno();
			goto done;
		}

		if (lstat(abspath, &sb) == -1) {
			err = got_error_from_errno();
			goto done;
		}

		if (!S_ISDIR(sb.st_mode)) {
			/* TODO directory is obstructed; do something */
			return got_error(GOT_ERR_FILE_OBSTRUCTED);
		}
	}

done:
	free(abspath);
	return err;
}

static const struct got_error *
tree_checkout(struct got_worktree *, struct got_fileindex *,
    struct got_tree_object *, const char *, struct got_repository *,
    got_worktree_checkout_cb progress_cb, void *progress_arg,
    got_worktree_cancel_cb cancel_cb, void *cancel_arg);

static const struct got_error *
tree_checkout_entry(struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_tree_entry *te,
    const char *parent, struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg,
    got_worktree_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL;
	struct got_blob_object *blob = NULL;
	struct got_fileindex_entry *entry = NULL;
	struct got_tree_object *tree = NULL;
	char *path = NULL;
	char *progress_path = NULL;
	size_t len;

	if (parent[0] == '/' && parent[1] == '\0')
		parent = "";
	if (asprintf(&path, "%s/%s", parent, te->name) == -1)
		return got_error_from_errno();

	/* Skip this entry if it is outside of our path prefix. */
	len = MIN(strlen(worktree->path_prefix), strlen(path));
	if (strncmp(path, worktree->path_prefix, len) != 0) {
		free(path);
		return NULL;
	}

	err = got_object_open(&obj, repo, te->id);
	if (err)
		goto done;

	progress_path = path;
	if (strncmp(progress_path, worktree->path_prefix, len) == 0)
		progress_path += len;

	switch (obj->type) {
	case GOT_OBJ_TYPE_BLOB:
		if (strlen(worktree->path_prefix) >= strlen(path))
			break;
		entry = got_fileindex_entry_get(fileindex,
		    apply_path_prefix(worktree, path));
		if (entry &&
		    memcmp(entry->commit_sha1, worktree->base_commit_id->sha1,
		    SHA1_DIGEST_LENGTH) == 0) {
			(*progress_cb)(progress_arg, GOT_STATUS_EXISTS,
			    progress_path);
			break;
		}
		if (entry && memcmp(entry->blob_sha1, obj->id.sha1,
		    SHA1_DIGEST_LENGTH) == 0)
			break;
		err = got_object_blob_open(&blob, repo, obj, 8192);
		if (err)
			goto done;
		err = blob_checkout(worktree, fileindex, entry, path, blob,
		    repo, progress_cb, progress_arg, progress_path);
		break;
	case GOT_OBJ_TYPE_TREE:
		if (strlen(worktree->path_prefix) < strlen(path)) {
			err = add_dir_on_disk(worktree, path);
			if (err)
				break;
		}
		err = got_object_tree_open(&tree, repo, obj);
		if (err)
			goto done;
		/* XXX infinite recursion possible */
		err = tree_checkout(worktree, fileindex, tree, path, repo,
		    progress_cb, progress_arg, cancel_cb, cancel_arg);
		break;
	default:
		break;
	}

done:
	if (blob)
		got_object_blob_close(blob);
	if (tree)
		got_object_tree_close(tree);
	if (obj)
		got_object_close(obj);
	free(path);
	return err;
}

struct collect_missing_entry_args {
	struct got_fileindex *fileindex;
	const struct got_tree_entries *entries;
	struct got_fileindex missing_entries;
	const char *current_subdir;
};

static const struct got_error *
collect_missing_file(void *args, struct got_fileindex_entry *entry)
{
	struct collect_missing_entry_args *a = args;
	char *start, *end;
	ptrdiff_t len;
	struct got_tree_entry *te;
	int found = 0;

	if (a->current_subdir[0] != '\0' &&
	    strncmp(a->current_subdir, entry->path,
	    strlen(a->current_subdir)) != 0)
		return NULL;

	start = entry->path + strlen(a->current_subdir);
	while (start[0] == '/')
		start++;
	end = strchr(start, '/');
	if (end == NULL) {
		end = strchr(start, '\0');
		if (end == NULL)
			return got_error(GOT_ERR_BAD_PATH);
	}
	len = end - start;

	SIMPLEQ_FOREACH(te, &a->entries->head, entry) {
		if (strncmp(start, te->name, len) == 0 &&
		    te->name[len] == '\0') {
			found = 1;
			break;
		}
	}

	if (found)
		return NULL;

	got_fileindex_entry_remove(a->fileindex, entry);
	return got_fileindex_entry_add(&a->missing_entries, entry);
}

/* Remove files which exist in the file index but not in the tree. */
static const struct got_error *
remove_missing_files(struct got_worktree *worktree, const char *path,
    struct got_fileindex *fileindex, const struct got_tree_entries *entries,
    got_worktree_checkout_cb progress_cb, void *progress_arg,
    got_worktree_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct collect_missing_entry_args a;
	struct got_fileindex_entry *entry, *tmp;

	a.fileindex = fileindex;
	a.entries = entries;
	a.missing_entries.nentries = 0;
	a.current_subdir = apply_path_prefix(worktree, path);
	TAILQ_INIT(&a.missing_entries.entries);
	err = got_fileindex_for_each_entry_safe(fileindex,
	    collect_missing_file, &a);
	if (err)
		return err;

	TAILQ_FOREACH_SAFE(entry, &a.missing_entries.entries, entry, tmp) {
		char *ondisk_path = NULL;

		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}

		(*progress_cb)(progress_arg, GOT_STATUS_DELETE, entry->path);

		if (asprintf(&ondisk_path, "%s/%s", worktree->root_path,
		    entry->path) == -1) {
			err = got_error_from_errno();
			break;
		}

		if (unlink(ondisk_path) == -1)
			err = got_error_from_errno();
		else {
			char *parent = dirname(ondisk_path);
			if (rmdir(parent) == -1 && errno != ENOTEMPTY)
				err = got_error_from_errno();
		}
		free(ondisk_path);
		if (err)
			break;

		TAILQ_REMOVE(&a.missing_entries.entries, entry, entry);
		got_fileindex_entry_free(entry);
	}

	if (err) {
		while (!TAILQ_EMPTY(&a.missing_entries.entries)) {
			entry = TAILQ_FIRST(&a.missing_entries.entries);
			TAILQ_REMOVE(&a.missing_entries.entries, entry, entry);
			got_fileindex_entry_free(entry);
		}
	}

	return err;
}

static const struct got_error *
tree_checkout(struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_tree_object *tree,
    const char *path, struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg,
    got_worktree_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	const struct got_tree_entries *entries;
	struct got_tree_entry *te;
	size_t len;

	/* Skip this tree if it shares no path components with the prefix. */
	len = MIN(strlen(worktree->path_prefix), strlen(path));
	if (strncmp(path, worktree->path_prefix, len) != 0)
		return NULL;

	entries = got_object_tree_get_entries(tree);
	SIMPLEQ_FOREACH(te, &entries->head, entry) {
		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				return err;
		}
		err = tree_checkout_entry(worktree, fileindex, te, path, repo,
		    progress_cb, progress_arg, cancel_cb, cancel_arg);
		if (err)
			return err;
	}

	len = strlen(worktree->path_prefix);
	if (strncmp(worktree->path_prefix, path, len) == 0) {
		err = remove_missing_files(worktree, path, fileindex, entries,
		    progress_cb, progress_arg, cancel_cb, cancel_arg);
		if (err)
			return err;
	}

	return err;
}

const struct got_error *
got_worktree_checkout_files(struct got_worktree *worktree,
    struct got_repository *repo, got_worktree_checkout_cb progress_cb,
    void *progress_arg, got_worktree_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL, *unlockerr, *checkout_err = NULL;
	struct got_commit_object *commit = NULL;
	struct got_tree_object *tree = NULL;
	char *fileindex_path = NULL, *new_fileindex_path = NULL;
	struct got_fileindex *fileindex = NULL;
	FILE *index = NULL, *new_index = NULL;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	fileindex = got_fileindex_alloc();
	if (fileindex == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	if (asprintf(&fileindex_path, "%s/%s/%s", worktree->root_path,
	    GOT_WORKTREE_GOT_DIR, GOT_WORKTREE_FILE_INDEX) == -1) {
		err = got_error_from_errno();
		fileindex_path = NULL;
		goto done;
	}

	/*
	 * Read the file index.
	 * Checking out files is supposed to be an idempotent operation.
	 * If the on-disk file index is incomplete we will try to complete it.
	 */
	index = fopen(fileindex_path, "rb");
	if (index == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	err = got_fileindex_read(fileindex, index);
	fclose(index);
	if (err)
		goto done;

	err = got_opentemp_named(&new_fileindex_path, &new_index,
	    fileindex_path);
	if (err)
		goto done;

	err = got_object_open_as_commit(&commit, repo,
	   worktree->base_commit_id);
	if (err)
		goto done;

	err = got_object_open_as_tree(&tree, repo, commit->tree_id);
	if (err)
		goto done;

	checkout_err = tree_checkout(worktree, fileindex, tree, "/", repo,
	    progress_cb, progress_arg, cancel_cb, cancel_arg);

	/* Try to sync the fileindex back to disk in any case. */
	err = got_fileindex_write(fileindex, new_index);
	if (err)
		goto done;

	if (rename(new_fileindex_path, fileindex_path) != 0) {
		err = got_error_from_errno();
		goto done;
	}

	free(new_fileindex_path);
	new_fileindex_path = NULL;

done:
	if (tree)
		got_object_tree_close(tree);
	if (commit)
		got_object_commit_close(commit);
	if (new_fileindex_path)
		unlink(new_fileindex_path);
	if (new_index)
		fclose(new_index);
	free(new_fileindex_path);
	free(fileindex_path);
	got_fileindex_free(fileindex);
	if (checkout_err)
		err = checkout_err;
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	return err;
}
