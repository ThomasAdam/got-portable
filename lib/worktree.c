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
#include <util.h>

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
#include "got_lib_object_parse.h"
#include "got_lib_object_create.h"
#include "got_lib_object_idset.h"
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
	if (got_fileindex_entry_has_blob(ie)) {
		struct got_object_id id2;
		memcpy(id2.sha1, ie->blob_sha1, SHA1_DIGEST_LENGTH);
		err = got_object_open_as_blob(&blob2, repo, &id2, 8192);
		if (err)
			goto done;
		err = got_object_blob_dump_to_file(NULL, NULL, f2, blob2);
		if (err)
			goto done;
	} else {
		/*
		 * If the file has no blob, this is an "add vs add" conflict,
		 * and we simply use an empty ancestor file to make both files
		 * appear in the merged result in their entirety.
		 */
	}

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
update_blob_fileindex_entry(struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_fileindex_entry *ie,
    const char *ondisk_path, const char *path, struct got_blob_object *blob,
    int update_timestamps)
{
	const struct got_error *err = NULL;

	if (ie == NULL)
		ie = got_fileindex_entry_get(fileindex, path);
	if (ie)
		err = got_fileindex_entry_update(ie, ondisk_path,
		    blob->id.sha1, worktree->base_commit_id->sha1,
		    update_timestamps);
	else {
		struct got_fileindex_entry *new_ie;
		err = got_fileindex_entry_alloc(&new_ie, ondisk_path,
		    path, blob->id.sha1, worktree->base_commit_id->sha1);
		if (!err)
			err = got_fileindex_entry_add(fileindex, new_ie);
	}
	return err;
}

static const struct got_error *
install_blob(struct got_worktree *worktree, const char *ondisk_path,
   const char *path, uint16_t te_mode, uint16_t st_mode,
   struct got_blob_object *blob, int restoring_missing_file,
   int reverting_versioned_file, struct got_repository *repo,
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
	else if (reverting_versioned_file)
		(*progress_cb)(progress_arg, GOT_STATUS_REVERT, path);
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

done:
	if (fd != -1 && close(fd) != 0 && err == NULL)
		err = got_error_from_errno();
	free(tmppath);
	return err;
}

/* Upgrade STATUS_MODIFY to STATUS_CONFLICT if a conflict marker is found. */
static const struct got_error *
get_modified_file_content_status(unsigned char *status, FILE *f)
{
	const struct got_error *err = NULL;
	const char *markers[3] = {
		GOT_DIFF_CONFLICT_MARKER_BEGIN,
		GOT_DIFF_CONFLICT_MARKER_SEP,
		GOT_DIFF_CONFLICT_MARKER_END
	};
	int i = 0;
	char *line;
	size_t len;
	const char delim[3] = {'\0', '\0', '\0'};

	while (*status == GOT_STATUS_MODIFY) {
		line = fparseln(f, &len, NULL, delim, 0);
		if (line == NULL) {
			if (feof(f))
				break;
			err = got_ferror(f, GOT_ERR_IO);
			break;
		}

		if (strncmp(line, markers[i], strlen(markers[i])) == 0) {
			if (markers[i] == GOT_DIFF_CONFLICT_MARKER_END)
				*status = GOT_STATUS_CONFLICT;
			else
				i++;
		}
	}

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
				if (got_fileindex_entry_has_file_on_disk(ie))
					*status = GOT_STATUS_MISSING;
				else
					*status = GOT_STATUS_DELETE;
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

	if (!got_fileindex_entry_has_file_on_disk(ie)) {
		*status = GOT_STATUS_DELETE;
		return NULL;
	} else if (!got_fileindex_entry_has_blob(ie)) {
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
			goto done;
		/* Skip length of blob object header first time around. */
		flen = fread(fbuf, 1, sizeof(fbuf) - hdrlen, f);
		if (flen == 0 && ferror(f)) {
			err = got_error_from_errno();
			goto done;
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

	if (*status == GOT_STATUS_MODIFY) {
		rewind(f);
		err = get_modified_file_content_status(status, f);
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
    void *progress_arg)
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
		if (got_fileindex_entry_has_commit(ie) &&
		    memcmp(ie->commit_sha1, worktree->base_commit_id->sha1,
		    SHA1_DIGEST_LENGTH) == 0) {
			(*progress_cb)(progress_arg, GOT_STATUS_EXISTS,
			    path);
			goto done;
		}
		if (got_fileindex_entry_has_blob(ie) &&
		    memcmp(ie->blob_sha1, te->id->sha1,
		    SHA1_DIGEST_LENGTH) == 0)
			goto done;
	}

	err = got_object_open_as_blob(&blob, repo, te->id, 8192);
	if (err)
		goto done;

	if (status == GOT_STATUS_MODIFY || status == GOT_STATUS_ADD)
		err = merge_blob(worktree, fileindex, ie, ondisk_path, path,
		    te->mode, sb.st_mode, blob, repo, progress_cb,
		    progress_arg);
	else if (status == GOT_STATUS_DELETE) {
		(*progress_cb)(progress_arg, GOT_STATUS_MERGE, path);
		err = update_blob_fileindex_entry(worktree, fileindex, ie,
		    ondisk_path, path, blob, 0);
		if (err)
			goto done;
	} else {
		err = install_blob(worktree, ondisk_path, path, te->mode,
		    sb.st_mode, blob, status == GOT_STATUS_MISSING, 0,
		    repo, progress_cb, progress_arg);
		if (err)
			goto done;
		err = update_blob_fileindex_entry(worktree, fileindex, ie,
		    ondisk_path, path, blob, 1);
		if (err)
			goto done;
	}
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

static const struct got_error *
delete_blob(struct got_worktree *worktree, struct got_fileindex *fileindex,
    struct got_fileindex_entry *ie, const char *parent_path,
    struct got_repository *repo,
    got_worktree_checkout_cb progress_cb, void *progress_arg)
{
	const struct got_error *err = NULL;
	unsigned char status;
	struct stat sb;
	char *ondisk_path;

	if (asprintf(&ondisk_path, "%s/%s", worktree->root_path, ie->path)
	    == -1)
		return got_error_from_errno();

	err = get_file_status(&status, &sb, ie, ondisk_path, repo);
	if (err)
		return err;

	if (status == GOT_STATUS_MODIFY || status == GOT_STATUS_CONFLICT ||
	    status == GOT_STATUS_ADD) {
		(*progress_cb)(progress_arg, GOT_STATUS_MERGE, ie->path);
		/*
		 * Preserve the working file and change the deleted blob's
		 * entry into a schedule-add entry.
		 */
		err = got_fileindex_entry_update(ie, ondisk_path, NULL, NULL,
		    0);
		if (err)
			return err;
	} else {
		(*progress_cb)(progress_arg, GOT_STATUS_DELETE, ie->path);
		if (status == GOT_STATUS_NO_CHANGE) {
			err = remove_ondisk_file(worktree->root_path, ie->path);
			if (err)
				return err;
		}
		got_fileindex_entry_remove(fileindex, ie);
	}

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

	if (a->cancel_cb && a->cancel_cb(a->cancel_arg))
		return got_error(GOT_ERR_CANCELLED);

	return update_blob(a->worktree, a->fileindex, ie, te,
	    ie->path, a->repo, a->progress_cb, a->progress_arg);
}

static const struct got_error *
diff_old(void *arg, struct got_fileindex_entry *ie, const char *parent_path)
{
	struct diff_cb_arg *a = arg;

	if (a->cancel_cb && a->cancel_cb(a->cancel_arg))
		return got_error(GOT_ERR_CANCELLED);

	return delete_blob(a->worktree, a->fileindex, ie, parent_path,
	    a->repo, a->progress_cb, a->progress_arg);
}

static const struct got_error *
diff_new(void *arg, struct got_tree_entry *te, const char *parent_path)
{
	struct diff_cb_arg *a = arg;
	const struct got_error *err;
	char *path;

	if (a->cancel_cb && a->cancel_cb(a->cancel_arg))
		return got_error(GOT_ERR_CANCELLED);

	if (asprintf(&path, "%s%s%s", parent_path,
	    parent_path[0] ? "/" : "", te->name)
	    == -1)
		return got_error_from_errno();

	if (S_ISDIR(te->mode))
		err = add_dir_on_disk(a->worktree, path);
	else
		err = update_blob(a->worktree, a->fileindex, NULL, te, path,
		    a->repo, a->progress_cb, a->progress_arg);

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
got_worktree_checkout_files(struct got_worktree *worktree, const char *path,
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
	char *relpath = NULL, *entry_name = NULL;

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

	if (path[0]) {
		char *tree_path;
		int obj_type;
		relpath = strdup(path);
		if (relpath == NULL) {
			err = got_error_from_errno();
			goto done;
		}
		if (asprintf(&tree_path, "%s%s%s", worktree->path_prefix,
		    got_path_is_root_dir(worktree->path_prefix) ? "" : "/",
		    path) == -1) {
			err = got_error_from_errno();
			goto done;
		}
		err = got_object_id_by_path(&tree_id, repo,
		    worktree->base_commit_id, tree_path);
		free(tree_path);
		if (err)
			goto done;
		err = got_object_get_type(&obj_type, repo, tree_id);
		if (err)
			goto done;
		if (obj_type == GOT_OBJ_TYPE_BLOB) {
			/* Split provided path into parent dir + entry name. */
			if (strchr(path, '/')  == NULL) {
				relpath = strdup("");
				if (relpath == NULL) {
					err = got_error_from_errno();
					goto done;
				}
				tree_path = strdup(worktree->path_prefix);
				if (tree_path == NULL) {
					err = got_error_from_errno();
					goto done;
				}
			} else {
				err = got_path_dirname(&relpath, path);
				if (err)
					goto done;
				if (asprintf(&tree_path, "%s%s%s",
				    worktree->path_prefix,
				    got_path_is_root_dir(
				    worktree->path_prefix) ? "" : "/",
				    relpath) == -1) {
					err = got_error_from_errno();
					goto done;
				}
			}
			err = got_object_id_by_path(&tree_id, repo,
			    worktree->base_commit_id, tree_path);
			free(tree_path);
			if (err)
				goto done;
			entry_name = basename(path);
			if (entry_name == NULL) {
				err = got_error_from_errno();
				goto done;
			}
		}
	} else {
		relpath = strdup("");
		if (relpath == NULL) {
			err = got_error_from_errno();
			goto done;
		}
		err = got_object_id_by_path(&tree_id, repo,
		    worktree->base_commit_id, worktree->path_prefix);
		if (err)
			goto done;
	}

	err = got_object_open_as_tree(&tree, repo, tree_id);
	if (err)
		goto done;

	if (entry_name &&
	    got_object_tree_find_entry(tree, entry_name) == NULL) {
		err = got_error(GOT_ERR_NO_TREE_ENTRY);
		goto done;
	}

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
	checkout_err = got_fileindex_diff_tree(fileindex, tree, relpath,
	    entry_name, repo, &diff_cb, &arg);

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
	free(relpath);
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

	if (a->cancel_cb && a->cancel_cb(a->cancel_arg))
		return got_error(GOT_ERR_CANCELLED);

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
	unsigned char status;

	if (a->cancel_cb && a->cancel_cb(a->cancel_arg))
		return got_error(GOT_ERR_CANCELLED);

	if (!got_path_is_child(parent_path, a->status_path, a->status_path_len))
		return NULL;

	memcpy(id.sha1, ie->blob_sha1, SHA1_DIGEST_LENGTH);
	if (got_fileindex_entry_has_file_on_disk(ie))
		status = GOT_STATUS_MISSING;
	else
		status = GOT_STATUS_DELETE;
	return (*a->status_cb)(a->status_arg, status, ie->path, &id);
}

static const struct got_error *
status_new(void *arg, struct dirent *de, const char *parent_path)
{
	const struct got_error *err = NULL;
	struct diff_dir_cb_arg *a = arg;
	char *path = NULL;

	if (a->cancel_cb && a->cancel_cb(a->cancel_arg))
		return got_error(GOT_ERR_CANCELLED);

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
		if (errno == ENOTDIR || errno == ENOENT) {
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

	path = strdup(resolved +
	    strlen(got_worktree_get_root_path(worktree)) + 1 /* skip '/' */);
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
got_worktree_schedule_add(struct got_worktree *worktree,
    const char *ondisk_path, got_worktree_status_cb status_cb, void *status_arg,
    struct got_repository *repo)
{
	struct got_fileindex *fileindex = NULL;
	struct got_fileindex_entry *ie = NULL;
	char *relpath, *fileindex_path = NULL, *new_fileindex_path = NULL;
	FILE *index = NULL, *new_index = NULL;
	const struct got_error *err = NULL, *unlockerr = NULL;
	int ie_added = 0;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = got_path_skip_common_ancestor(&relpath,
	    got_worktree_get_root_path(worktree), ondisk_path);
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

	if (got_fileindex_entry_get(fileindex, relpath) != NULL) {
		err = got_error_set_errno(EEXIST);
		goto done;
	}

	err = got_fileindex_entry_alloc(&ie, ondisk_path, relpath, NULL, NULL);
	if (err)
		goto done;

	err = got_fileindex_entry_add(fileindex, ie);
	if (err)
		goto done;
	ie_added = 1; /* now owned by fileindex; don't free separately */

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

	err = report_file_status(ie, ondisk_path, status_cb, status_arg, repo);
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
	if (ie && !ie_added)
		got_fileindex_entry_free(ie);
	if (fileindex)
		got_fileindex_free(fileindex);
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	free(relpath);
	return err;
}

const struct got_error *
got_worktree_schedule_delete(struct got_worktree *worktree,
    const char *ondisk_path, int delete_local_mods,
    got_worktree_status_cb status_cb, void *status_arg,
    struct got_repository *repo)
{
	struct got_fileindex *fileindex = NULL;
	struct got_fileindex_entry *ie = NULL;
	char *relpath, *fileindex_path = NULL, *new_fileindex_path = NULL;
	FILE *index = NULL, *new_index = NULL;
	const struct got_error *err = NULL, *unlockerr = NULL;
	unsigned char status;
	struct stat sb;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = got_path_skip_common_ancestor(&relpath,
	    got_worktree_get_root_path(worktree), ondisk_path);
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

	ie = got_fileindex_entry_get(fileindex, relpath);
	if (ie == NULL) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}

	err = get_file_status(&status, &sb, ie, ondisk_path, repo);
	if (err)
		goto done;

	if (status != GOT_STATUS_NO_CHANGE) {
		if (status == GOT_STATUS_DELETE) {
			err = got_error_set_errno(ENOENT);
			goto done;
		}
		if (status != GOT_STATUS_MODIFY) {
			err = got_error(GOT_ERR_FILE_STATUS);
			goto done;
		}
		if (!delete_local_mods) {
			err = got_error(GOT_ERR_FILE_MODIFIED);
			goto done;
		}
	}

	if (unlink(ondisk_path) != 0) {
		err = got_error_from_errno();
		goto done;
	}

	got_fileindex_entry_mark_deleted_from_disk(ie);

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

	err = report_file_status(ie, ondisk_path, status_cb, status_arg, repo);
done:
	free(relpath);
	if (index) {
		if (fclose(index) != 0 && err == NULL)
			err = got_error_from_errno();
	}
	if (new_fileindex_path) {
		if (unlink(new_fileindex_path) != 0 && err == NULL)
			err = got_error_from_errno();
		free(new_fileindex_path);
	}
	if (fileindex)
		got_fileindex_free(fileindex);
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	return err;
}

const struct got_error *
got_worktree_revert(struct got_worktree *worktree,
    const char *ondisk_path,
    got_worktree_checkout_cb progress_cb, void *progress_arg,
    struct got_repository *repo)
{
	struct got_fileindex *fileindex = NULL;
	struct got_fileindex_entry *ie = NULL;
	char *relpath, *fileindex_path = NULL, *new_fileindex_path = NULL;
	char *tree_path = NULL, *parent_path, *te_name;
	FILE *index = NULL, *new_index = NULL;
	const struct got_error *err = NULL, *unlockerr = NULL;
	struct got_tree_object *tree = NULL;
	struct got_object_id id, *tree_id = NULL;
	const struct got_tree_entry *te;
	struct got_blob_object *blob = NULL;
	unsigned char status;
	struct stat sb;

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		return err;

	err = got_path_skip_common_ancestor(&relpath,
	    got_worktree_get_root_path(worktree), ondisk_path);
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

	ie = got_fileindex_entry_get(fileindex, relpath);
	if (ie == NULL) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}

	/* Construct in-repository path of tree which contains this blob. */
	err = got_path_dirname(&parent_path, ie->path);
	if (err) {
		if (err->code != GOT_ERR_BAD_PATH)
			goto done;
		parent_path = "/";
	}
	if (got_path_is_root_dir(worktree->path_prefix)) {
		tree_path = strdup(parent_path);
		if (tree_path == NULL) {
			err = got_error_from_errno();
			goto done;
		}
	} else {
		if (got_path_is_root_dir(parent_path)) {
			tree_path = strdup(worktree->path_prefix);
			if (tree_path == NULL) {
				err = got_error_from_errno();
				goto done;
			}
		} else {
			if (asprintf(&tree_path, "%s/%s",
			    worktree->path_prefix, parent_path) == -1) {
				err = got_error_from_errno();
				goto done;
			}
		}
	}

	err = got_object_id_by_path(&tree_id, repo, worktree->base_commit_id,
	    tree_path);
	if (err)
		goto done;

	err = got_object_open_as_tree(&tree, repo, tree_id);
	if (err)
		goto done;

	te_name = basename(ie->path);
	if (te_name == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	err = get_file_status(&status, &sb, ie, ondisk_path, repo);
	if (err)
		goto done;

	te = got_object_tree_find_entry(tree, te_name);
	if (te == NULL && status != GOT_STATUS_ADD) {
		err = got_error(GOT_ERR_NO_TREE_ENTRY);
		goto done;
	}

	switch (status) {
	case GOT_STATUS_ADD:
		(*progress_cb)(progress_arg, GOT_STATUS_REVERT, ie->path);
		got_fileindex_entry_remove(fileindex, ie);
		break;
	case GOT_STATUS_DELETE:
	case GOT_STATUS_MODIFY:
	case GOT_STATUS_CONFLICT:
	case GOT_STATUS_MISSING:
		memcpy(id.sha1, ie->blob_sha1, SHA1_DIGEST_LENGTH);
		err = got_object_open_as_blob(&blob, repo, &id, 8192);
		if (err)
			goto done;
		err = install_blob(worktree, ondisk_path, ie->path,
		    te->mode, sb.st_mode, blob, 0, 1, repo, progress_cb,
		    progress_arg);
		if (err)
			goto done;
		if (status == GOT_STATUS_DELETE) {
			err = update_blob_fileindex_entry(worktree,
			    fileindex, ie, ondisk_path, ie->path, blob, 1);
			if (err)
				goto done;
		}
		break;
	default:
			goto done;
	}

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
	free(relpath);
	free(tree_path);
	if (blob)
		got_object_blob_close(blob);
	if (tree)
		got_object_tree_close(tree);
	free(tree_id);
	if (index) {
		if (fclose(index) != 0 && err == NULL)
			err = got_error_from_errno();
	}
	if (new_fileindex_path) {
		if (unlink(new_fileindex_path) != 0 && err == NULL)
			err = got_error_from_errno();
		free(new_fileindex_path);
	}
	if (fileindex)
		got_fileindex_free(fileindex);
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	return err;
}

struct commitable {
	char *path;
	unsigned char status;
	struct got_object_id *id;
	struct got_object_id *base_id;
	struct got_object_id *tree_id;
};

static void
free_commitable(struct commitable *ct)
{
	free(ct->path);
	free(ct->id);
	free(ct->base_id);
	free(ct->tree_id);
	free(ct);
}

struct collect_commitables_arg {
	struct got_pathlist_head *commitable_paths;
	struct got_repository *repo;
	struct got_worktree *worktree;
};

static const struct got_error *
collect_commitables(void *arg, unsigned char status, const char *relpath,
    struct got_object_id *id)
{
	struct collect_commitables_arg *a = arg;
	const struct got_error *err = NULL;
	struct commitable *ct = NULL;
	struct got_pathlist_entry *new = NULL;
	char *parent_path = NULL, *path = NULL;

	if (status == GOT_STATUS_CONFLICT)
		return got_error(GOT_ERR_COMMIT_CONFLICT);

	if (status != GOT_STATUS_MODIFY && status != GOT_STATUS_ADD &&
	    status != GOT_STATUS_DELETE)
		return NULL;

	if (asprintf(&path, "/%s", relpath) == -1) {
		err = got_error_from_errno();
		goto done;
	}
	if (strcmp(path, "/") == 0) {
		parent_path = strdup("");
		if (parent_path == NULL)
			return got_error_from_errno();
	} else {
		err = got_path_dirname(&parent_path, path);
		if (err)
			return err;
	}

	ct = calloc(1, sizeof(*ct));
	if (ct == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	ct->status = status;
	ct->id = NULL; /* will be filled in when blob gets created */
	if (ct->status != GOT_STATUS_ADD) {
		ct->base_id = got_object_id_dup(id);
		if (ct->base_id == NULL) {
			err = got_error_from_errno();
			goto done;
		}
	}
	err = got_object_id_by_path(&ct->tree_id, a->repo,
	    a->worktree->base_commit_id, parent_path);
	if (err)
		goto done;
	ct->path = strdup(path);
	if (ct->path == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	err = got_pathlist_insert(&new, a->commitable_paths, ct->path, ct);
done:
	if (ct && (err || new == NULL))
		free_commitable(ct);
	free(parent_path);
	free(path);
	return err;
}

static const struct got_error *write_tree(struct got_object_id **,
    struct got_tree_object *, const char *, struct got_pathlist_head *,
    struct got_repository *);

static const struct got_error *
write_subtree(struct got_object_id **new_subtree_id,
    struct got_tree_entry *te, const char *parent_path,
    struct got_pathlist_head *commitable_paths, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_tree_object *subtree;
	char *subpath;

	if (asprintf(&subpath, "%s%s%s", parent_path,
	    parent_path[0] == '\0' ? "" : "/", te->name) == -1)
		return got_error_from_errno();

	err = got_object_open_as_tree(&subtree, repo, te->id);
	if (err)
		return err;

	err = write_tree(new_subtree_id, subtree, subpath, commitable_paths,
	    repo);
	got_object_tree_close(subtree);
	free(subpath);
	return err;
}

static const struct got_error *
match_ct_parent_path(int *match, struct commitable *ct, const char *path)
{
	const struct got_error *err = NULL;
	char *ct_parent_path = NULL;

	*match = 0;

	if (strchr(ct->path, '/') == NULL) {
		ct_parent_path = strdup("/");
		if (ct_parent_path == NULL)
			return got_error_from_errno();
	} else {
		err = got_path_dirname(&ct_parent_path, ct->path);
		if (err)
			return err;
	}

	*match = (strcmp(path, ct_parent_path) == 0);
	free(ct_parent_path);
	return err;
}

static const struct got_error *
alloc_modified_blob_tree_entry(struct got_tree_entry **new_te,
    struct got_tree_entry *te, struct commitable *ct)
{
	const struct got_error *err = NULL;

	*new_te = NULL;

	err = got_object_tree_entry_dup(new_te, te);
	if (err)
		goto done;

	/* XXX TODO: update mode from disk (derive from ct?)! */
	(*new_te)->mode = GOT_DEFAULT_FILE_MODE;

	free((*new_te)->id);
	(*new_te)->id = got_object_id_dup(ct->id);
	if ((*new_te)->id == NULL) {
		err = got_error_from_errno();
		goto done;
	}
done:
	if (err && *new_te) {
		got_object_tree_entry_close(*new_te);
		*new_te = NULL;
	}
	return err;
}

static const struct got_error *
alloc_added_blob_tree_entry(struct got_tree_entry **new_te,
    struct commitable *ct)
{
	const struct got_error *err = NULL;
	char *ct_name;

	 *new_te = NULL;

	*new_te = calloc(1, sizeof(*new_te));
	if (*new_te == NULL)
		return got_error_from_errno();

	ct_name = basename(ct->path);
	if (ct_name == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	(*new_te)->name = strdup(ct_name);
	if ((*new_te)->name == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	/* XXX TODO: update mode from disk (derive from ct?)! */
	(*new_te)->mode = GOT_DEFAULT_FILE_MODE;

	(*new_te)->id = got_object_id_dup(ct->id);
	if ((*new_te)->id == NULL) {
		err = got_error_from_errno();
		goto done;
	}
done:
	if (err && *new_te) {
		got_object_tree_entry_close(*new_te);
		*new_te = NULL;
	}
	return err;
}

static const struct got_error *
insert_tree_entry(struct got_tree_entry *new_te,
    struct got_pathlist_head *paths)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *new_pe;

	err = got_pathlist_insert(&new_pe, paths, new_te->name, new_te);
	if (err)
		return err;
	if (new_pe == NULL)
		return got_error(GOT_ERR_TREE_DUP_ENTRY);
	return NULL;
}

static const struct got_error *
match_deleted_or_modified_ct(struct commitable **ctp,
    struct got_tree_entry *te, const char *base_tree_path,
    struct got_pathlist_head *commitable_paths)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe;

	*ctp = NULL;

	TAILQ_FOREACH(pe, commitable_paths, entry) {
		struct commitable *ct = pe->data;
		char *ct_name = NULL;
		int path_matches;

		if (ct->status != GOT_STATUS_MODIFY &&
		    ct->status != GOT_STATUS_DELETE)
			continue;

		if (got_object_id_cmp(ct->base_id, te->id) != 0)
			continue;

		 err = match_ct_parent_path(&path_matches, ct, base_tree_path);
		 if (err)
			return err;
		if (!path_matches)
			continue;

		ct_name = basename(pe->path);
		if (ct_name == NULL)
			return got_error_from_errno();

		if (strcmp(te->name, ct_name) != 0)
			continue;

		*ctp = ct;
		break;
	}

	return err;
}

static const struct got_error *
write_tree(struct got_object_id **new_tree_id,
    struct got_tree_object *base_tree, const char *path_base_tree,
    struct got_pathlist_head *commitable_paths,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	const struct got_tree_entries *base_entries = NULL;
	struct got_pathlist_head paths;
	struct got_tree_entries new_tree_entries;
	struct got_tree_entry *te, *new_te = NULL;
	struct got_pathlist_entry *pe;

	TAILQ_INIT(&paths);
	new_tree_entries.nentries = 0;
	SIMPLEQ_INIT(&new_tree_entries.head);

	/* Insert, and recurse into, newly added entries first. */
	TAILQ_FOREACH(pe, commitable_paths, entry) {
		struct commitable *ct = pe->data;
		char *child_path = NULL, *slash;

		if (ct->status != GOT_STATUS_ADD)
			continue;

		 if (!got_path_is_child(pe->path, path_base_tree,
		     strlen(path_base_tree)))
			continue;

		err = got_path_skip_common_ancestor(&child_path, path_base_tree,
		    pe->path);
		if (err)
			goto done;

		slash = strchr(child_path, '/');
		if (slash == NULL) {
			err = alloc_added_blob_tree_entry(&new_te, ct);
			if (err)
				goto done;
		} else {
			char *subtree_path;

			*slash = '\0'; /* trim trailing path components */

			new_te = calloc(1, sizeof(*new_te));
			new_te->mode = GOT_DEFAULT_DIR_MODE;
			new_te->name = strdup(child_path);
			if (new_te->name == NULL) {
				got_object_tree_entry_close(new_te);
				err = got_error_from_errno();
				goto done;
			}
			if (asprintf(&subtree_path, "%s/%s", path_base_tree,
			    child_path) == -1) {
				err = got_error_from_errno();
				goto done;
			}
			err = write_subtree(&new_te->id, NULL, subtree_path,
			    commitable_paths, repo);
			free(subtree_path);
			if (err)
				goto done;
		}

		err = insert_tree_entry(new_te, &paths);
		if (err)
			goto done;
	}

	if (base_tree) {
		/* Handle modified and deleted entries. */
		base_entries = got_object_tree_get_entries(base_tree);
		SIMPLEQ_FOREACH(te, &base_entries->head, entry) {
			struct commitable *ct = NULL;

			if (S_ISDIR(te->mode)) {
				err = got_object_tree_entry_dup(&new_te, te);
				if (err)
					goto done;
				free(new_te->id);
				err = write_subtree(&new_te->id, te,
				    path_base_tree, commitable_paths, repo);
				if (err)
					goto done;
				err = insert_tree_entry(new_te, &paths);
				if (err)
					goto done;
				continue;
			}

			err = match_deleted_or_modified_ct(&ct, te,
			    path_base_tree, commitable_paths);
			if (ct) {
				/* NB: Deleted entries get dropped here. */
				if (ct->status == GOT_STATUS_MODIFY) {
					err = alloc_modified_blob_tree_entry(
					    &new_te, te, ct);
					if (err)
						goto done;
					err = insert_tree_entry(new_te, &paths);
					if (err)
						goto done;
				}
			} else {
				/* Entry is unchanged; just copy it. */
				err = got_object_tree_entry_dup(&new_te, te);
				if (err)
					goto done;
				err = insert_tree_entry(new_te, &paths);
				if (err)
					goto done;
			}
		}
	}

	/* Write new list of entries; deleted entries have been dropped. */
	TAILQ_FOREACH(pe, &paths, entry) {
		struct got_tree_entry *te = pe->data;
		new_tree_entries.nentries++;
		SIMPLEQ_INSERT_TAIL(&new_tree_entries.head, te, entry);
	}
	err = got_object_tree_create(new_tree_id, &new_tree_entries, repo);
done:
	got_object_tree_entries_close(&new_tree_entries);
	got_pathlist_free(&paths);
	if (base_tree)
		got_object_tree_close(base_tree);
	return err;
}

const struct got_error *
got_worktree_commit(struct got_object_id **new_commit_id,
    struct got_worktree *worktree, const char *ondisk_path,
    const char *logmsg, struct got_repository *repo)
{
	const struct got_error *err = NULL, *unlockerr = NULL;
	struct collect_commitables_arg cc_arg;
	struct got_pathlist_head commitable_paths;
	struct got_pathlist_entry *pe;
	char *relpath = NULL;
	struct got_commit_object *base_commit = NULL;
	struct got_tree_object *base_tree = NULL;
	struct got_object_id *new_tree_id = NULL;

	*new_commit_id = NULL;

	TAILQ_INIT(&commitable_paths);

	if (ondisk_path) {
		err = got_path_skip_common_ancestor(&relpath,
		    worktree->root_path, ondisk_path);
		if (err)
			return err;
	}

	err = lock_worktree(worktree, LOCK_EX);
	if (err)
		goto done;

	cc_arg.commitable_paths = &commitable_paths;
	cc_arg.worktree = worktree;
	cc_arg.repo = repo;
	err = got_worktree_status(worktree, relpath ? relpath : "",
	    repo, collect_commitables, &cc_arg, NULL, NULL);
	if (err)
		goto done;

	/* TODO: collect commit message if not specified */

	/* Create blobs from added and modified files and record their IDs. */
	TAILQ_FOREACH(pe, &commitable_paths, entry) {
		struct commitable *ct = pe->data;
		char *ondisk_path;

		if (ct->status != GOT_STATUS_ADD &&
		    ct->status != GOT_STATUS_MODIFY)
			continue;

		if (asprintf(&ondisk_path, "%s/%s",
		    worktree->root_path, pe->path) == -1) {
			err = got_error_from_errno();
			goto done;
		}
		err = got_object_blob_create(&ct->id, ondisk_path, repo);
		free(ondisk_path);
		if (err)
			goto done;
	}

	err = got_object_open_as_commit(&base_commit, repo,
	    worktree->base_commit_id);
	if (err)
		goto done;
	err = got_object_open_as_tree(&base_tree, repo, base_commit->tree_id);
	if (err)
		goto done;

	/* Recursively write new tree objects. */
	err = write_tree(&new_tree_id, base_tree, "/", &commitable_paths, repo);
	if (err)
		goto done;

	/* TODO: Write new commit. */

done:
	unlockerr = lock_worktree(worktree, LOCK_SH);
	if (unlockerr && err == NULL)
		err = unlockerr;
	TAILQ_FOREACH(pe, &commitable_paths, entry) {
		struct commitable *ct = pe->data;
		free_commitable(ct);
	}
	got_pathlist_free(&commitable_paths);
	if (base_tree)
		got_object_tree_close(base_tree);
	if (base_commit)
		got_object_commit_close(base_commit);
	free(relpath);
	return err;
}
