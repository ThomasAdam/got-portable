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

#include <sys/stat.h>
#include <sys/limits.h>
#include <sys/queue.h>
#include <sys/tree.h>

#include <dirent.h>
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
#include <uuid.h>

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
#include "got_lib_diff.h"

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
		unlink(tmppath);
		goto done;
	}

done:
	free(tmppath);
	if (fclose(tmpfile) != 0 && err == NULL)
		err = got_error_from_errno();
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
		if (errno == ENOENT)
			err = got_error(GOT_ERR_WORKTREE_META);
		else
			err = got_error_from_errno();
		goto done;
	}
	if (flock(fd, LOCK_SH | LOCK_NB) == -1) {
		err = (errno == EWOULDBLOCK ? got_error(GOT_ERR_WORKTREE_BUSY)
		    : got_error_from_errno());
		goto done;
	}

	if (lstat(path, &sb) != 0) {
		err = got_error_from_errno();
		goto done;
	}
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
	uuid_t uuid;
	uint32_t uuid_status;
	int obj_type;
	char *path_got = NULL;
	char *refstr = NULL;
	char *formatstr = NULL;
	char *absprefix = NULL;
	char *basestr = NULL;
	char *uuidstr = NULL;

	if (strcmp(path, got_repo_get_path(repo)) == 0) {
		err = got_error(GOT_ERR_WORKTREE_REPO);
		goto done;
	}

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

	/* Generate UUID. */
	uuid_create(&uuid, &uuid_status);
	if (uuid_status != uuid_s_ok) {
		err = got_error_uuid(uuid_status);
		goto done;
	}
	uuid_to_string(&uuid, &uuidstr, &uuid_status);
	if (uuid_status != uuid_s_ok) {
		err = got_error_uuid(uuid_status);
		goto done;
	}
	err = create_meta_file(path_got, GOT_WORKTREE_UUID, uuidstr);
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
	free(uuidstr);
	return err;
}

static const struct got_error *
open_worktree(struct got_worktree **worktree, const char *path)
{
	const struct got_error *err = NULL;
	char *path_got;
	char *formatstr = NULL;
	char *uuidstr = NULL;
	char *path_lock = NULL;
	char *base_commit_id_str = NULL;
	char *head_ref_str = NULL;
	int version, fd = -1;
	const char *errstr;
	struct got_repository *repo = NULL;
	uint32_t uuid_status;

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

	err = read_meta_file(&uuidstr, path_got, GOT_WORKTREE_UUID);
	if (err)
		goto done;
	uuid_from_string(uuidstr, &(*worktree)->uuid, &uuid_status);
	if (uuid_status != uuid_s_ok) {
		err = got_error_uuid(uuid_status);
		goto done;
	}

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
	free(uuidstr);
	free(formatstr);
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

const struct got_error *
got_worktree_open(struct got_worktree **worktree, const char *path)
{
	const struct got_error *err = NULL;

	do {
		err = open_worktree(worktree, path);
		if (err && !(err->code == GOT_ERR_ERRNO && errno == ENOENT))
			return err;
		if (*worktree)
			return NULL;
		path = dirname(path);
		if (path == NULL)
			return got_error_from_errno();
	} while (!((path[0] == '.' || path[0] == '/') && path[1] == '\0'));

	return got_error(GOT_ERR_NOT_WORKTREE);
}

const struct got_error *
got_worktree_close(struct got_worktree *worktree)
{
	const struct got_error *err = NULL;
	free(worktree->root_path);
	free(worktree->repo_path);
	free(worktree->path_prefix);
	free(worktree->base_commit_id);
	if (worktree->head_ref)
		got_ref_close(worktree->head_ref);
	if (worktree->lockfd != -1)
		if (close(worktree->lockfd) != 0)
			err = got_error_from_errno();
	free(worktree);
	return err;
}

const char *
got_worktree_get_root_path(struct got_worktree *worktree)
{
	return worktree->root_path;
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

struct got_object_id *
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

static const struct got_error *
add_dir_on_disk(struct got_worktree *worktree, const char *path)
{
	const struct got_error *err = NULL;
	char *abspath;

	if (asprintf(&abspath, "%s/%s", worktree->root_path, path) == -1)
		return got_error_from_errno();

	err = got_path_mkdir(abspath);
	if (err && err->code == GOT_ERR_ERRNO && errno == EEXIST) {
		struct stat sb;
		err = NULL;
		if (lstat(abspath, &sb) == -1) {
			err = got_error_from_errno();
		} else if (!S_ISDIR(sb.st_mode)) {
			/* TODO directory is obstructed; do something */
			err = got_error(GOT_ERR_FILE_OBSTRUCTED);
		}
	}
	free(abspath);
	return err;
}

static const struct got_error *
check_file_contents_equal(int *same, FILE *f1, FILE *f2)
{
	const struct got_error *err = NULL;
	uint8_t fbuf1[8192];
	uint8_t fbuf2[8192];
	size_t flen1 = 0, flen2 = 0;

	*same = 1;

	while (1) {
		flen1 = fread(fbuf1, 1, sizeof(fbuf1), f1);
		if (flen1 == 0 && ferror(f1)) {
			err = got_error_from_errno();
			break;
		}
		flen2 = fread(fbuf2, 1, sizeof(fbuf2), f2);
		if (flen2 == 0 && ferror(f2)) {
			err = got_error_from_errno();
			break;
		}
		if (flen1 == 0) {
			if (flen2 != 0)
				*same = 0;
			break;
		} else if (flen2 == 0) {
			if (flen1 != 0)
				*same = 0;
			break;
		} else if (flen1 == flen2) {
			if (memcmp(fbuf1, fbuf2, flen2) != 0) {
				*same = 0;
				break;
			}
		} else {
			*same = 0;
			break;
		}
	}

	return err;
}

static const struct got_error *
check_files_equal(int *same, const char *f1_path, const char *f2_path)
{
	const struct got_error *err = NULL;
	struct stat sb;
	size_t size1, size2;
	FILE *f1 = NULL, *f2 = NULL;

	*same = 1;

	if (lstat(f1_path, &sb) != 0) {
		err = got_error_from_errno();
		goto done;
	}
	size1 = sb.st_size;

	if (lstat(f2_path, &sb) != 0) {
		err = got_error_from_errno();
		goto done;
	}
	size2 = sb.st_size;

	if (size1 != size2) {
		*same = 0;
		return NULL;
	}

	f1 = fopen(f1_path, "r");
	if (f1 == NULL)
		return got_error_from_errno();

	f2 = fopen(f2_path, "r");
	if (f2 == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	err = check_file_contents_equal(same, f1, f2);
done:
	if (f1 && fclose(f1) != 0 && err == NULL)
		err = got_error_from_errno();
	if (f2 && fclose(f2) != 0 && err == NULL)
		err = got_error_from_errno();

	return err;
}

/*
 * Perform a 3-way merge where the file's version in the file index (blob2)
 * acts as the common ancestor, the incoming blob (blob1) acts as the first
 * derived version, and the file on disk acts as the second derived version.
 */
static const struct got_error *
merge_blob(struct got_worktree *worktree, struct got_fileindex *fileindex,
   struct got_fileindex_entry *ie, const char *ondisk_path, const char *path,
   uint16_t te_mode, uint16_t st_mode, struct got_blob_object *blob1,
   struct got_repository *repo,
   got_worktree_checkout_cb progress_cb, void *progress_arg)
{
	const struct got_error *err = NULL;
	int merged_fd = -1;
	struct got_blob_object *blob2 = NULL;
	FILE *f1 = NULL, *f2 = NULL;
	char *blob1_path = NULL, *blob2_path = NULL;
	char *merged_path = NULL, *base_path = NULL;
	struct got_object_id id2;
	char *id_str = NULL;
	char *label1 = NULL;
	int overlapcnt = 0, update_timestamps = 0;
	char *parent;

	parent = dirname(ondisk_path);
	if (parent == NULL)
		return got_error_from_errno();

	if (asprintf(&base_path, "%s/got-merged", parent) == -1)
		return got_error_from_errno();

	err = got_opentemp_named_fd(&merged_path, &merged_fd, base_path);
	if (err)
		goto done;

	free(base_path);
	if (asprintf(&base_path, "%s/got-merge-blob1", parent) == -1) {
		err = got_error_from_errno();
		base_path = NULL;
		goto done;
	}

	err = got_opentemp_named(&blob1_path, &f1, base_path);
	if (err)
		goto done;
	err = got_object_blob_dump_to_file(NULL, NULL, f1, blob1);
	if (err)
		goto done;

	free(base_path);
	if (asprintf(&base_path, "%s/got-merge-blob2", parent) == -1) {
		err = got_error_from_errno();
		base_path = NULL;
		goto done;
	}

	err = got_opentemp_named(&blob2_path, &f2, base_path);
	if (err)
		goto done;

	memcpy(id2.sha1, ie->blob_sha1, SHA1_DIGEST_LENGTH);
	err = got_object_open_as_blob(&blob2, repo, &id2, 8192);
	if (err)
		goto done;
	err = got_object_blob_dump_to_file(NULL, NULL, f2, blob2);
	if (err)
		goto done;

	err = got_object_id_str(&id_str, worktree->base_commit_id);
	if (err)
		goto done;
	if (asprintf(&label1, "commit %s", id_str) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	err = got_merge_diff3(&overlapcnt, merged_fd, blob1_path,
	    blob2_path, ondisk_path, label1, path);
	if (err)
		goto done;

	(*progress_cb)(progress_arg,
	    overlapcnt > 0 ? GOT_STATUS_CONFLICT : GOT_STATUS_MERGE, path);


	if (fsync(merged_fd) != 0) {
		err = got_error_from_errno();
		goto done;
	}

	/* Check if a clean merge has subsumed all local changes. */
	if (overlapcnt == 0) {
		err = check_files_equal(&update_timestamps, blob1_path,
		    merged_path);
		if (err)
			goto done;
	}

	if (chmod(merged_path, st_mode) != 0) {
		err = got_error_from_errno();
		goto done;
	}

	if (rename(merged_path, ondisk_path) != 0) {
		err = got_error_from_errno();
		unlink(merged_path);
		goto done;
	}

	/*
	 * Do not update timestamps of already modified files. Otherwise,
	 * a future status walk would treat them as unmodified files again.
	 */
	err = got_fileindex_entry_update(ie, ondisk_path,
	    blob1->id.sha1, worktree->base_commit_id->sha1, update_timestamps);
done:
	if (merged_fd != -1 && close(merged_fd) != 0 && err == NULL)
		err = got_error_from_errno();
	if (f1 && fclose(f1) != 0 && err == NULL)
		err = got_error_from_errno();
	if (f2 && fclose(f2) != 0 && err == NULL)
		err = got_error_from_errno();
	if (blob2)
		got_object_blob_close(blob2);
	free(merged_path);
	free(base_path);
	if (blob1_path) {
		unlink(blob1_path);
		free(blob1_path);
	}
	if (blob2_path) {
		unlink(blob2_path);
		free(blob2_path);
	}
	free(id_str);
	free(label1);
	return err;
}

static const struct got_error *
install_blob(struct got_worktree *worktree, struct got_fileindex *fileindex,
   struct got_fileindex_entry *entry, const char *ondisk_path, const char *path,
   uint16_t te_mode, uint16_t st_mode, struct got_blob_object *blob,
   int restoring_missing_file, struct got_repository *repo,
   got_worktree_checkout_cb progress_cb, void *progress_arg)
{
	const struct got_error *err = NULL;
	int fd = -1;
	size_t len, hdrlen;
	int update = 0;
	char *tmppath = NULL;

	fd = open(ondisk_path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW,
	    GOT_DEFAULT_FILE_MODE);
	if (fd == -1) {
		if (errno == ENOENT) {
			char *parent = dirname(path);
			if (parent == NULL)
				return got_error_from_errno();
			err = add_dir_on_disk(worktree, parent);
			if (err)
				return err;
			fd = open(ondisk_path,
			    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW,
			    GOT_DEFAULT_FILE_MODE);
			if (fd == -1)
				return got_error_from_errno();
		} else if (errno == EEXIST) {
			if (!S_ISREG(st_mode)) {
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
			return got_error_from_errno();
	}

	if (restoring_missing_file)
		(*progress_cb)(progress_arg, GOT_STATUS_MISSING, path);
	else
		(*progress_cb)(progress_arg,
		    update ? GOT_STATUS_UPDATE : GOT_STATUS_ADD, path);

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

	if (fsync(fd) != 0) {
		err = got_error_from_errno();
		goto done;
	}

	if (update) {
		if (rename(tmppath, ondisk_path) != 0) {
			err = got_error_from_errno();
			unlink(tmppath);
			goto done;
		}
	}

	if (te_mode & S_IXUSR) {
		if (chmod(ondisk_path, st_mode | S_IXUSR) == -1) {
			err = got_error_from_errno();
			goto done;
		}
	} else {
		if (chmod(ondisk_path, st_mode & ~S_IXUSR) == -1) {
			err = got_error_from_errno();
			goto done;
		}
	}

	if (entry == NULL)
		entry = got_fileindex_entry_get(fileindex, path);
	if (entry)
		err = got_fileindex_entry_update(entry, ondisk_path,
		    blob->id.sha1, worktree->base_commit_id->sha1, 1);
	else {
		err = got_fileindex_entry_alloc(&entry, ondisk_path,
		    path, blob->id.sha1, worktree->base_commit_id->sha1);
		if (err)
			goto done;
		err = got_fileindex_entry_add(fileindex, entry);
	}
done:
	if (fd != -1 && close(fd) != 0 && err == NULL)
		err = got_error_from_errno();
	free(tmppath);
	return err;
}

static const struct got_error *
get_file_status(unsigned char *status, struct stat *sb,
    struct got_fileindex_entry *ie, const char *abspath,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id id;
	size_t hdrlen;
	FILE *f = NULL;
	uint8_t fbuf[8192];
	struct got_blob_object *blob = NULL;
	size_t flen, blen;

	*status = GOT_STATUS_NO_CHANGE;

	if (lstat(abspath, sb) == -1) {
		if (errno == ENOENT) {
			if (ie) {
				*status = GOT_STATUS_MISSING;
				sb->st_mode =
				    ((ie->mode >> GOT_FILEIDX_MODE_PERMS_SHIFT)
				    & (S_IRWXU | S_IRWXG | S_IRWXO));
			} else
				sb->st_mode = GOT_DEFAULT_FILE_MODE;
			return NULL;
		}
		return got_error_from_errno();
	}

	if (!S_ISREG(sb->st_mode)) {
		*status = GOT_STATUS_OBSTRUCTED;
		return NULL;
	}

	if (ie == NULL)
		return NULL;

	if (!got_fileindex_entry_has_blob(ie)) {
		*status = GOT_STATUS_ADD;
		return NULL;
	}

	if (ie->ctime_sec == sb->st_ctime &&
	    ie->ctime_nsec == sb->st_ctimensec &&
	    ie->mtime_sec == sb->st_mtime &&
	    ie->mtime_sec == sb->st_mtime &&
	    ie->mtime_nsec == sb->st_mtimensec &&
	    ie->size == (sb->st_size & 0xffffffff))
		return NULL;

	memcpy(id.sha1, ie->blob_sha1, sizeof(id.sha1));
	err = got_object_open_as_blob(&blob, repo, &id, sizeof(fbuf));
	if (err)
		return err;

	f = fopen(abspath, "r");
	if (f == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	hdrlen = got_object_blob_get_hdrlen(blob);
	while (1) {
		const uint8_t *bbuf = got_object_blob_get_read_buf(blob);
		err = got_object_blob_read_block(&blen, blob);
		if (err)
			break;
		/* Skip length of blob object header first time around. */
		flen = fread(fbuf, 1, sizeof(fbuf) - hdrlen, f);
		if (flen == 0 && ferror(f)) {
			err = got_error_from_errno();
			break;
		}
		if (blen == 0) {
			if (flen != 0)
				*status = GOT_STATUS_MODIFY;
			break;
		} else if (flen == 0) {
			if (blen != 0)
				*status = GOT_STATUS_MODIFY;
			break;
		} else if (blen - hdrlen == flen) {
			/* Skip blob object header first time around. */
			if (memcmp(bbuf + hdrlen, fbuf, flen) != 0) {
				*status = GOT_STATUS_MODIFY;
				break;
			}
		} else {
			*status = GOT_STATUS_MODIFY;
			break;
		}
		hdrlen = 0;
	}
done:
	if (blob)
		got_object_blob_close(blob);
	if (f)
		fclose(f);
	return err;
}

static const struct got_error *
update_blob(struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_fileindex_entry *ie,
    struct got_tree_entry *te, const char *path,
    struct got_repository *repo, got_worktree_checkout_cb progress_cb,
    void *progress_arg, got_worktree_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_blob_object *blob = NULL;
	char *ondisk_path;
	unsigned char status = GOT_STATUS_NO_CHANGE;
	struct stat sb;

	if (asprintf(&ondisk_path, "%s/%s", worktree->root_path, path) == -1)
		return got_error_from_errno();

	err = get_file_status(&status, &sb, ie, ondisk_path, repo);
	if (err)
		goto done;

	if (status == GOT_STATUS_OBSTRUCTED) {
		(*progress_cb)(progress_arg, status, path);
		goto done;
	}

	if (ie && status != GOT_STATUS_MISSING) {
		if (memcmp(ie->commit_sha1, worktree->base_commit_id->sha1,
		    SHA1_DIGEST_LENGTH) == 0) {
			(*progress_cb)(progress_arg, GOT_STATUS_EXISTS,
			    path);
			goto done;
		}
		if (memcmp(ie->blob_sha1,
		    te->id->sha1, SHA1_DIGEST_LENGTH) == 0)
			goto done;
	}

	err = got_object_open_as_blob(&blob, repo, te->id, 8192);
	if (err)
		goto done;

	if (status == GOT_STATUS_MODIFY)
		err = merge_blob(worktree, fileindex, ie, ondisk_path, path,
		    te->mode, sb.st_mode, blob, repo, progress_cb,
		    progress_arg);
	else
		err = install_blob(worktree, fileindex, ie, ondisk_path, path,
		    te->mode, sb.st_mode, blob, status == GOT_STATUS_MISSING,
		    repo, progress_cb, progress_arg);

	got_object_blob_close(blob);
done:
	free(ondisk_path);
	return err;
}

static const struct got_error *
remove_ondisk_file(const char *root_path, const char *path)
{
	const struct got_error *err = NULL;
	char *ondisk_path = NULL;

	if (asprintf(&ondisk_path, "%s/%s", root_path, path) == -1)
		return got_error_from_errno();

	if (unlink(ondisk_path) == -1) {
		if (errno != ENOENT)
			err = got_error_from_errno();
	} else {
		char *parent = dirname(ondisk_path);
		while (parent && strcmp(parent, root_path) != 0) {
			if (rmdir(parent) == -1) {
				if (errno != ENOTEMPTY)
					err = got_error_from_errno();
				break;
			}
			parent = dirname(parent);
		}
	}
	free(ondisk_path);
	return err;
}

struct diff_cb_arg {
    struct got_fileindex *fileindex;
    struct got_worktree *worktree;
    struct got_repository *repo;
    got_worktree_checkout_cb progress_cb;
    void *progress_arg;
    got_worktree_cancel_cb cancel_cb;
    void *cancel_arg;
};

static const struct got_error *
diff_old_new(void *arg, struct got_fileindex_entry *ie,
    struct got_tree_entry *te, const char *parent_path)
{
	struct diff_cb_arg *a = arg;

	return update_blob(a->worktree, a->fileindex, ie, te,
	    ie->path, a->repo, a->progress_cb, a->progress_arg,
	    a->cancel_cb, a->cancel_arg);
}

static const struct got_error *
diff_old(void *arg, struct got_fileindex_entry *ie, const char *parent_path)
{
	const struct got_error *err;
	struct diff_cb_arg *a = arg;

	(*a->progress_cb)(a->progress_arg, GOT_STATUS_DELETE, ie->path);

	err = remove_ondisk_file(a->worktree->root_path, ie->path);
	if (err)
		return err;
	got_fileindex_entry_remove(a->fileindex, ie);
	return NULL;
}

static const struct got_error *
diff_new(void *arg, struct got_tree_entry *te, const char *parent_path)
{
	struct diff_cb_arg *a = arg;
	const struct got_error *err;
	char *path;

	if (asprintf(&path, "%s%s%s", parent_path,
	    parent_path[0] ? "/" : "", te->name)
	    == -1)
		return got_error_from_errno();

	if (S_ISDIR(te->mode))
		err = add_dir_on_disk(a->worktree, path);
	else
		err = update_blob(a->worktree, a->fileindex, NULL, te, path,
		    a->repo, a->progress_cb, a->progress_arg,
		    a->cancel_cb, a->cancel_arg);

	free(path);
	return err;
}

const struct got_error *
got_worktree_get_base_ref_name(char **refname, struct got_worktree *worktree)
{
	const struct got_error *err = NULL;
	char *uuidstr = NULL;
	uint32_t uuid_status;

	*refname = NULL;

	uuid_to_string(&worktree->uuid, &uuidstr, &uuid_status);
	if (uuid_status != uuid_s_ok)
		return got_error_uuid(uuid_status);

	if (asprintf(refname, "%s-%s", GOT_WORKTREE_BASE_REF_PREFIX, uuidstr)
	    == -1) {
		err = got_error_from_errno();
		*refname = NULL;
	}
	free(uuidstr);
	return err;
}

/*
 * Prevent Git's garbage collector from deleting our base commit by
 * setting a reference to our base commit's ID.
 */
static const struct got_error *
ref_base_commit(struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_reference *ref = NULL;
	char *refname;

	err = got_worktree_get_base_ref_name(&refname, worktree);
	if (err)
		return err;

	err = got_ref_alloc(&ref, refname, worktree->base_commit_id);
	if (err)
		goto done;

	err = got_ref_write(ref, repo);
done:
	free(refname);
	if (ref)
		got_ref_close(ref);
	return err;
}


const struct got_error *
got_worktree_checkout_files(struct got_worktree *worktree,
    struct got_repository *repo, got_worktree_checkout_cb progress_cb,
    void *progress_arg, got_worktree_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL, *unlockerr, *checkout_err = NULL;
	struct got_commit_object *commit = NULL;
	struct got_object_id *tree_id = NULL;
	struct got_tree_object *tree = NULL;
	char *fileindex_path = NULL, *new_fileindex_path = NULL;
	struct got_fileindex *fileindex = NULL;
	FILE *index = NULL, *new_index = NULL;
	struct got_fileindex_diff_tree_cb diff_cb;
	struct diff_cb_arg arg;

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
		if (errno != ENOENT) {
			err = got_error_from_errno();
			goto done;
		}
	} else {
		err = got_fileindex_read(fileindex, index);
		fclose(index);
		if (err)
			goto done;
	}

	err = got_opentemp_named(&new_fileindex_path, &new_index,
	    fileindex_path);
	if (err)
		goto done;

	err = ref_base_commit(worktree, repo);
	if (err)
		goto done;

	err = got_object_open_as_commit(&commit, repo,
	   worktree->base_commit_id);
	if (err)
		goto done;

	err = got_object_id_by_path(&tree_id, repo,
	    worktree->base_commit_id, worktree->path_prefix);
	if (err)
		goto done;

	err = got_object_open_as_tree(&tree, repo, tree_id);
	if (err)
		goto done;

	diff_cb.diff_old_new = diff_old_new;
	diff_cb.diff_old = diff_old;
	diff_cb.diff_new = diff_new;
	arg.fileindex = fileindex;
	arg.worktree = worktree;
	arg.repo = repo;
	arg.progress_cb = progress_cb;
	arg.progress_arg = progress_arg;
	arg.cancel_cb = cancel_cb;
	arg.cancel_arg = cancel_arg;
	checkout_err = got_fileindex_diff_tree(fileindex, tree, repo,
	    &diff_cb, &arg);

	/* Try to sync the fileindex back to disk in any case. */
	err = got_fileindex_write(fileindex, new_index);
	if (err)
		goto done;

	if (rename(new_fileindex_path, fileindex_path) != 0) {
		err = got_error_from_errno();
		unlink(new_fileindex_path);
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

struct diff_dir_cb_arg {
    struct got_fileindex *fileindex;
    struct got_worktree *worktree;
    const char *status_path;
    size_t status_path_len;
    struct got_repository *repo;
    got_worktree_status_cb status_cb;
    void *status_arg;
    got_worktree_cancel_cb cancel_cb;
    void *cancel_arg;
};

static const struct got_error *
report_file_status(struct got_fileindex_entry *ie, const char *abspath,
    got_worktree_status_cb status_cb, void *status_arg,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	unsigned char status = GOT_STATUS_NO_CHANGE;
	struct stat sb;
	struct got_object_id id;

	err = get_file_status(&status, &sb, ie, abspath, repo);
	if (err == NULL && status != GOT_STATUS_NO_CHANGE) {
		memcpy(id.sha1, ie->blob_sha1, SHA1_DIGEST_LENGTH);
		err = (*status_cb)(status_arg, status, ie->path, &id);
	}
	return err;
}

static const struct got_error *
status_old_new(void *arg, struct got_fileindex_entry *ie,
    struct dirent *de, const char *parent_path)
{
	const struct got_error *err = NULL;
	struct diff_dir_cb_arg *a = arg;
	char *abspath;

	if (got_path_cmp(parent_path, a->status_path) != 0 &&
	    !got_path_is_child(parent_path, a->status_path, a->status_path_len))
		return NULL;

	if (parent_path[0]) {
		if (asprintf(&abspath, "%s/%s/%s", a->worktree->root_path,
		    parent_path, de->d_name) == -1)
			return got_error_from_errno();
	} else {
		if (asprintf(&abspath, "%s/%s", a->worktree->root_path,
		    de->d_name) == -1)
			return got_error_from_errno();
	}

	err = report_file_status(ie, abspath, a->status_cb, a->status_arg,
	    a->repo);
	free(abspath);
	return err;
}

static const struct got_error *
status_old(void *arg, struct got_fileindex_entry *ie, const char *parent_path)
{
	struct diff_dir_cb_arg *a = arg;
	struct got_object_id id;

	if (!got_path_is_child(parent_path, a->status_path, a->status_path_len))
		return NULL;

	memcpy(id.sha1, ie->blob_sha1, SHA1_DIGEST_LENGTH);
	return (*a->status_cb)(a->status_arg, GOT_STATUS_MISSING, ie->path,
	    &id);
}

static const struct got_error *
status_new(void *arg, struct dirent *de, const char *parent_path)
{
	const struct got_error *err = NULL;
	struct diff_dir_cb_arg *a = arg;
	char *path = NULL;

	if (de->d_type == DT_DIR)
		return NULL;

	/* XXX ignore symlinks for now */
	if (de->d_type == DT_LNK)
		return NULL;

	if (!got_path_is_child(parent_path, a->status_path, a->status_path_len))
		return NULL;

	if (parent_path[0]) {
		if (asprintf(&path, "%s/%s", parent_path, de->d_name) == -1)
			return got_error_from_errno();
	} else {
		path = de->d_name;
	}

	err = (*a->status_cb)(a->status_arg, GOT_STATUS_UNVERSIONED, path,
	    NULL);
	if (parent_path[0])
		free(path);
	return err;
}

const struct got_error *
got_worktree_status(struct got_worktree *worktree, const char *path,
    struct got_repository *repo, got_worktree_status_cb status_cb,
    void *status_arg, got_worktree_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	DIR *workdir = NULL;
	char *fileindex_path = NULL;
	struct got_fileindex *fileindex = NULL;
	FILE *index = NULL;
	struct got_fileindex_diff_dir_cb fdiff_cb;
	struct diff_dir_cb_arg arg;
	char *ondisk_path = NULL;

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

	index = fopen(fileindex_path, "rb");
	if (index == NULL) {
		if (errno != ENOENT) {
			err = got_error_from_errno();
			goto done;
		}
	} else {
		err = got_fileindex_read(fileindex, index);
		fclose(index);
		if (err)
			goto done;
	}

	if (asprintf(&ondisk_path, "%s%s%s",
	    worktree->root_path, path[0] ? "/" : "", path) == -1) {
		err = got_error_from_errno();
		goto done;
	}
	workdir = opendir(ondisk_path);
	if (workdir == NULL) {
		if (errno == ENOTDIR) {
			struct got_fileindex_entry *ie;
			ie = got_fileindex_entry_get(fileindex, path);
			if (ie == NULL) {
				err = got_error(GOT_ERR_BAD_PATH);
				goto done;
			}
			err = report_file_status(ie, ondisk_path,
			    status_cb, status_arg, repo);
			goto done;
		} else {
			err = got_error_from_errno();
			goto done;
		}
	}
	fdiff_cb.diff_old_new = status_old_new;
	fdiff_cb.diff_old = status_old;
	fdiff_cb.diff_new = status_new;
	arg.fileindex = fileindex;
	arg.worktree = worktree;
	arg.status_path = path;
	arg.status_path_len = strlen(path);
	arg.repo = repo;
	arg.status_cb = status_cb;
	arg.status_arg = status_arg;
	arg.cancel_cb = cancel_cb;
	arg.cancel_arg = cancel_arg;
	err = got_fileindex_diff_dir(fileindex, workdir, worktree->root_path,
	    path, repo, &fdiff_cb, &arg);
done:
	if (workdir)
		closedir(workdir);
	free(ondisk_path);
	free(fileindex_path);
	got_fileindex_free(fileindex);
	return err;
}

const struct got_error *
got_worktree_resolve_path(char **wt_path, struct got_worktree *worktree,
    const char *arg)
{
	const struct got_error *err = NULL;
	char *resolved, *path = NULL;
	size_t len;

	*wt_path = NULL;

	resolved = realpath(arg, NULL);
	if (resolved == NULL)
		return got_error_from_errno();

	if (strncmp(got_worktree_get_root_path(worktree), resolved,
	    strlen(got_worktree_get_root_path(worktree)))) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}

	path = strdup(resolved + strlen(got_worktree_get_root_path(worktree)));
	if (path == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	/* XXX status walk can't deal with trailing slash! */
	len = strlen(path);
	while (path[len - 1] == '/') {
		path[len - 1] = '\0';
		len--;
	}
done:
	free(resolved);
	if (err == NULL)
		*wt_path = path;
	else
		free(path);
	return err;
}

const struct got_error *
got_worktree_schedule_add(char **relpath, struct got_worktree *worktree,
    const char *ondisk_path)
{
	struct got_fileindex *fileindex = NULL;
	struct got_fileindex_entry *ie = NULL;
	char *fileindex_path = NULL, *new_fileindex_path = NULL;
	FILE *index = NULL, *new_index = NULL;
	const struct got_error *err = NULL, *unlockerr = NULL;

	*relpath = NULL;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = got_path_skip_common_ancestor(relpath,
	    got_worktree_get_root_path(worktree), ondisk_path);
	if (err)
		goto done;

	err = got_fileindex_entry_alloc(&ie, ondisk_path, *relpath, NULL, NULL);
	if (err)
		goto done;

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

	index = fopen(fileindex_path, "rb");
	if (index == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	err = got_fileindex_read(fileindex, index);
	if (err)
		goto done;

	err = got_fileindex_entry_add(fileindex, ie);
	if (err)
		goto done;
	ie = NULL; /* now owned by fileindex; don't free separately */

	err = got_opentemp_named(&new_fileindex_path, &new_index,
	    fileindex_path);
	if (err)
		goto done;

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
	if (index) {
		if (fclose(index) != 0 && err == NULL)
			err = got_error_from_errno();
	}
	if (new_fileindex_path) {
		if (unlink(new_fileindex_path) != 0 && err == NULL)
			err = got_error_from_errno();
		free(new_fileindex_path);
	}
	if (ie)
		got_fileindex_entry_free(ie);
	if (fileindex)
		got_fileindex_free(fileindex);
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	if (err) {
		free(*relpath);
		*relpath = NULL;
	}
	return err;
}
