/*
 * Copyright (c) 2020 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <imsg.h>

#include "got_error.h"
#include "got_cancel.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_repository_admin.h"
#include "got_opentemp.h"
#include "got_path.h"

#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_object_idset.h"
#include "got_lib_object_cache.h"
#include "got_lib_pack.h"
#include "got_lib_privsep.h"
#include "got_lib_repository.h"
#include "got_lib_ratelimit.h"
#include "got_lib_pack_create.h"
#include "got_lib_sha1.h"
#include "got_lib_lockfile.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static const struct got_error *
get_reflist_object_ids(struct got_object_id ***ids, int *nobjects,
    unsigned int wanted_obj_type_mask, struct got_reflist_head *refs,
    struct got_repository *repo,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	const size_t alloc_chunksz = 256;
	size_t nalloc;
	struct got_reflist_entry *re;
	int i;

	*ids = NULL;
	*nobjects = 0;

	err = got_reflist_sort(refs,
	    got_ref_cmp_by_commit_timestamp_descending, repo);
	if (err)
		return err;

	*ids = reallocarray(NULL, alloc_chunksz, sizeof(struct got_object_id *));
	if (*ids == NULL)
		return got_error_from_errno("reallocarray");
	nalloc = alloc_chunksz;

	TAILQ_FOREACH(re, refs, entry) {
		struct got_object_id *id;

		if (cancel_cb) {
			err = cancel_cb(cancel_arg);
			if (err)
				goto done;
		}

		err = got_ref_resolve(&id, repo, re->ref);
		if (err)
			goto done;

		if (wanted_obj_type_mask != GOT_OBJ_TYPE_ANY) {
			int obj_type;
			err = got_object_get_type(&obj_type, repo, id);
			if (err)
				goto done;
			if ((wanted_obj_type_mask & (1 << obj_type)) == 0) {
				free(id);
				id = NULL;
				continue;
			}
		}

		if (nalloc <= *nobjects) {
			struct got_object_id **new;
			new = recallocarray(*ids, nalloc,
			    nalloc + alloc_chunksz,
			    sizeof(struct got_object_id *));
			if (new == NULL) {
				err = got_error_from_errno(
				    "recallocarray");
				goto done;
			}
			*ids = new;
			nalloc += alloc_chunksz;
		}
		(*ids)[*nobjects] = id;
		if ((*ids)[*nobjects] == NULL) {
			err = got_error_from_errno("got_object_id_dup");
			goto done;
		}
		(*nobjects)++;
	}
done:
	if (err) {
		for (i = 0; i < *nobjects; i++)
			free((*ids)[i]);
		free(*ids);
		*ids = NULL;
		*nobjects = 0;
	}
	return err;
}

const struct got_error *
got_repo_pack_objects(FILE **packfile, struct got_object_id **pack_hash,
    struct got_reflist_head *include_refs,
    struct got_reflist_head *exclude_refs, struct got_repository *repo,
    int loose_obj_only,
    got_pack_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id **ours = NULL, **theirs = NULL;
	int nours = 0, ntheirs = 0, packfd = -1, i;
	char *tmpfile_path = NULL, *path = NULL, *packfile_path = NULL;
	char *sha1_str = NULL;
	FILE *delta_cache = NULL;
	struct got_ratelimit rl;

	*packfile = NULL;
	*pack_hash = NULL;

	got_ratelimit_init(&rl, 0, 500);

	if (asprintf(&path, "%s/%s/packing.pack",
	    got_repo_get_path_git_dir(repo), GOT_OBJECTS_PACK_DIR) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	err = got_opentemp_named_fd(&tmpfile_path, &packfd, path, "");
	if (err)
		goto done;

	if (fchmod(packfd, GOT_DEFAULT_FILE_MODE) != 0) {
		err = got_error_from_errno2("fchmod", tmpfile_path);
		goto done;
	}

	delta_cache = got_opentemp();
	if (delta_cache == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	err = get_reflist_object_ids(&ours, &nours,
	    (1 << GOT_OBJ_TYPE_COMMIT) | (1 << GOT_OBJ_TYPE_TAG),
	    include_refs, repo, cancel_cb, cancel_arg);
	if (err)
		goto done;

	if (nours == 0) {
		err = got_error(GOT_ERR_CANNOT_PACK);
		goto done;
	}

	if (!TAILQ_EMPTY(exclude_refs)) {
		err = get_reflist_object_ids(&theirs, &ntheirs,
		    (1 << GOT_OBJ_TYPE_COMMIT) | (1 << GOT_OBJ_TYPE_TAG),
		    exclude_refs, repo,
		    cancel_cb, cancel_arg);
		if (err)
			goto done;
	}

	*pack_hash = calloc(1, sizeof(**pack_hash));
	if (*pack_hash == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	err = got_pack_create((*pack_hash)->sha1, packfd, delta_cache,
	    theirs, ntheirs, ours, nours, repo, loose_obj_only, 0,
	    progress_cb, progress_arg, &rl, cancel_cb, cancel_arg);
	if (err)
		goto done;

	err = got_object_id_str(&sha1_str, *pack_hash);
	if (err)
		goto done;
	if (asprintf(&packfile_path, "%s/%s/pack-%s.pack",
	    got_repo_get_path_git_dir(repo), GOT_OBJECTS_PACK_DIR,
	    sha1_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (lseek(packfd, 0L, SEEK_SET) == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}
	if (rename(tmpfile_path, packfile_path) == -1) {
		err = got_error_from_errno3("rename", tmpfile_path,
		    packfile_path);
		goto done;
	}
	free(tmpfile_path);
	tmpfile_path = NULL;

	*packfile = fdopen(packfd, "w");
	if (*packfile == NULL) {
		err = got_error_from_errno2("fdopen", tmpfile_path);
		goto done;
	}
	packfd = -1;
done:
	for (i = 0; i < nours; i++)
		free(ours[i]);
	free(ours);
	for (i = 0; i < ntheirs; i++)
		free(theirs[i]);
	free(theirs);
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno2("close", packfile_path);
	if (delta_cache && fclose(delta_cache) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (tmpfile_path && unlink(tmpfile_path) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", tmpfile_path);
	free(tmpfile_path);
	free(packfile_path);
	free(sha1_str);
	free(path);
	if (err) {
		free(*pack_hash);
		*pack_hash = NULL;
		if (*packfile)
			fclose(*packfile);
		*packfile = NULL;
	}
	return err;
}

const struct got_error *
got_repo_index_pack(FILE *packfile, struct got_object_id *pack_hash,
    struct got_repository *repo,
    got_pack_index_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	size_t i;
	char *path;
	int imsg_idxfds[2];
	int npackfd = -1, idxfd = -1, nidxfd = -1;
	int tmpfds[3];
	int idxstatus, done = 0;
	const struct got_error *err;
	struct imsgbuf idxibuf;
	pid_t idxpid;
	char *tmpidxpath = NULL;
	char *packfile_path = NULL, *idxpath = NULL, *id_str = NULL;
	const char *repo_path = got_repo_get_path_git_dir(repo);
	struct stat sb;

	for (i = 0; i < nitems(tmpfds); i++)
		tmpfds[i] = -1;

	if (asprintf(&path, "%s/%s/indexing.idx",
	    repo_path, GOT_OBJECTS_PACK_DIR) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	err = got_opentemp_named_fd(&tmpidxpath, &idxfd, path, "");
	free(path);
	if (err)
		goto done;
	if (fchmod(idxfd, GOT_DEFAULT_FILE_MODE) != 0) {
		err = got_error_from_errno2("fchmod", tmpidxpath);
		goto done;
	}

	nidxfd = dup(idxfd);
	if (nidxfd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}

	for (i = 0; i < nitems(tmpfds); i++) {
		tmpfds[i] = got_opentempfd();
		if (tmpfds[i] == -1) {
			err = got_error_from_errno("got_opentempfd");
			goto done;
		}
	}

	err = got_object_id_str(&id_str, pack_hash);
	if (err)
		goto done;

	if (asprintf(&packfile_path, "%s/%s/pack-%s.pack",
	    repo_path, GOT_OBJECTS_PACK_DIR, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (fstat(fileno(packfile), &sb) == -1) {
		err = got_error_from_errno2("fstat", packfile_path);
		goto done;
	}

	if (asprintf(&idxpath, "%s/%s/pack-%s.idx",
	    repo_path, GOT_OBJECTS_PACK_DIR, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_idxfds) == -1) {
		err = got_error_from_errno("socketpair");
		goto done;
	}
	idxpid = fork();
	if (idxpid == -1) {
		err= got_error_from_errno("fork");
		goto done;
	} else if (idxpid == 0)
		got_privsep_exec_child(imsg_idxfds,
		    GOT_PATH_PROG_INDEX_PACK, packfile_path);
	if (close(imsg_idxfds[1]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	imsg_init(&idxibuf, imsg_idxfds[0]);

	npackfd = dup(fileno(packfile));
	if (npackfd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}
	err = got_privsep_send_index_pack_req(&idxibuf, pack_hash->sha1,
	    npackfd);
	if (err != NULL)
		goto done;
	npackfd = -1;
	err = got_privsep_send_index_pack_outfd(&idxibuf, nidxfd);
	if (err != NULL)
		goto done;
	nidxfd = -1;
	for (i = 0; i < nitems(tmpfds); i++) {
		err = got_privsep_send_tmpfd(&idxibuf, tmpfds[i]);
		if (err != NULL)
			goto done;
		tmpfds[i] = -1;
	}
	done = 0;
	while (!done) {
		int nobj_total, nobj_indexed, nobj_loose, nobj_resolved;

		if (cancel_cb) {
			err = cancel_cb(cancel_arg);
			if (err)
				goto done;
		}

		err = got_privsep_recv_index_progress(&done, &nobj_total,
		    &nobj_indexed, &nobj_loose, &nobj_resolved,
		    &idxibuf);
		if (err != NULL)
			goto done;
		if (nobj_indexed != 0) {
			err = progress_cb(progress_arg, sb.st_size,
			    nobj_total, nobj_indexed, nobj_loose,
			    nobj_resolved);
			if (err)
				break;
		}
	}
	if (close(imsg_idxfds[0]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	if (waitpid(idxpid, &idxstatus, 0) == -1) {
		err = got_error_from_errno("waitpid");
		goto done;
	}

	if (rename(tmpidxpath, idxpath) == -1) {
		err = got_error_from_errno3("rename", tmpidxpath, idxpath);
		goto done;
	}
	free(tmpidxpath);
	tmpidxpath = NULL;

done:
	if (tmpidxpath && unlink(tmpidxpath) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", tmpidxpath);
	if (npackfd != -1 && close(npackfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (idxfd != -1 && close(idxfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	for (i = 0; i < nitems(tmpfds); i++) {
		if (tmpfds[i] != -1 && close(tmpfds[i]) == -1 && err == NULL)
			err = got_error_from_errno("close");
	}
	free(tmpidxpath);
	free(idxpath);
	free(packfile_path);
	return err;
}

const struct got_error *
got_repo_find_pack(FILE **packfile, struct got_object_id **pack_hash,
    struct got_repository *repo, const char *packfile_path)
{
	const struct got_error *err = NULL;
	const char *packdir_path = NULL;
	char *packfile_name = NULL, *p, *dot;
	struct got_object_id id;
	int packfd = -1;

	*packfile = NULL;
	*pack_hash = NULL;

	packdir_path = got_repo_get_path_objects_pack(repo);
	if (packdir_path == NULL)
		return got_error_from_errno("got_repo_get_path_objects_pack");

	if (!got_path_is_child(packfile_path, packdir_path,
	    strlen(packdir_path))) {
		err = got_error_path(packfile_path, GOT_ERR_BAD_PATH);
		goto done;

	}

	err = got_path_basename(&packfile_name, packfile_path);
	if (err)
		goto done;
	p = packfile_name;

	if (strncmp(p, "pack-", 5) != 0) {
		err = got_error_fmt(GOT_ERR_BAD_PATH,
		    "'%s' is not a valid pack file name",
		    packfile_name);
		goto done;
	}
	p += 5;
	dot = strchr(p, '.');
	if (dot == NULL) {
		err = got_error_fmt(GOT_ERR_BAD_PATH,
		    "'%s' is not a valid pack file name",
		    packfile_name);
		goto done;
	}
	if (strcmp(dot + 1, "pack") != 0) {
		err = got_error_fmt(GOT_ERR_BAD_PATH,
		    "'%s' is not a valid pack file name",
		    packfile_name);
		goto done;
	}
	*dot = '\0';
	if (!got_parse_sha1_digest(id.sha1, p)) {
		err = got_error_fmt(GOT_ERR_BAD_PATH,
		    "'%s' is not a valid pack file name",
		    packfile_name);
		goto done;
	}

	*pack_hash = got_object_id_dup(&id);
	if (*pack_hash == NULL) {
		err = got_error_from_errno("got_object_id_dup");
		goto done;
	}

	packfd = open(packfile_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (packfd == -1) {
		err = got_error_from_errno2("open", packfile_path);
		goto done;
	}

	*packfile = fdopen(packfd, "r");
	if (*packfile == NULL) {
		err = got_error_from_errno2("fdopen", packfile_path);
		goto done;
	}
	packfd = -1;
done:
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno2("close", packfile_path);
	free(packfile_name);
	if (err) {
		free(*pack_hash);
		*pack_hash = NULL;
	}
	return err;
}

const struct got_error *
got_repo_list_pack(FILE *packfile, struct got_object_id *pack_hash,
    struct got_repository *repo, got_pack_list_cb list_cb, void *list_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	char *id_str = NULL, *idxpath = NULL, *packpath = NULL;
	struct got_packidx *packidx = NULL;
	struct got_pack *pack = NULL;
	uint32_t nobj, i;

	err = got_object_id_str(&id_str, pack_hash);
	if (err)
		goto done;

	if (asprintf(&packpath, "%s/pack-%s.pack",
	    GOT_OBJECTS_PACK_DIR, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	if (asprintf(&idxpath, "%s/pack-%s.idx",
	    GOT_OBJECTS_PACK_DIR, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_packidx_open(&packidx, got_repo_get_fd(repo), idxpath, 1);
	if (err)
		goto done;

	err = got_repo_cache_pack(&pack, repo, packpath, packidx);
	if (err)
		goto done;

	nobj = be32toh(packidx->hdr.fanout_table[0xff]);
	for (i = 0; i < nobj; i++) {
		struct got_packidx_object_id *oid;
		struct got_object_id id, base_id;
		off_t offset, base_offset = 0;
		uint8_t type;
		uint64_t size;
		size_t tslen, len;

		if (cancel_cb) {
			err = cancel_cb(cancel_arg);
			if (err)
				break;
		}
		oid = &packidx->hdr.sorted_ids[i];
		memcpy(id.sha1, oid->sha1, SHA1_DIGEST_LENGTH);

		offset = got_packidx_get_object_offset(packidx, i);
		if (offset == -1) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}

		err = got_pack_parse_object_type_and_size(&type, &size, &tslen,
		    pack, offset);
		if (err)
			goto done;

		switch (type) {
		case GOT_OBJ_TYPE_OFFSET_DELTA:
			err = got_pack_parse_offset_delta(&base_offset, &len,
			    pack, offset, tslen);
			if (err)
				goto done;
			break;
		case GOT_OBJ_TYPE_REF_DELTA:
			err = got_pack_parse_ref_delta(&base_id,
			    pack, offset, tslen);
			if (err)
				goto done;
			break;
		}
		err = (*list_cb)(list_arg, &id, type, offset, size,
		    base_offset, &base_id);
		if (err)
			goto done;
	}

done:
	free(id_str);
	free(idxpath);
	free(packpath);
	if (packidx)
		got_packidx_close(packidx);
	return err;
}

static const struct got_error *
report_cleanup_progress(got_cleanup_progress_cb progress_cb,
    void *progress_arg, struct got_ratelimit *rl,
    int nloose, int ncommits, int npurged)
{
	const struct got_error *err;
	int elapsed;

	if (progress_cb == NULL)
		return NULL;

	err = got_ratelimit_check(&elapsed, rl);
	if (err || !elapsed)
		return err;

	return progress_cb(progress_arg, nloose, ncommits, npurged);
}

static const struct got_error *
get_loose_object_ids(struct got_object_idset **loose_ids, off_t *ondisk_size,
    got_cleanup_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path_objects = NULL, *path = NULL;
	DIR *dir = NULL;
	struct got_object *obj = NULL;
	struct got_object_id id;
	int i, fd = -1;
	struct stat sb;

	*ondisk_size = 0;
	*loose_ids = got_object_idset_alloc();
	if (*loose_ids == NULL)
		return got_error_from_errno("got_object_idset_alloc");

	path_objects = got_repo_get_path_objects(repo);
	if (path_objects == NULL) {
		err = got_error_from_errno("got_repo_get_path_objects");
		goto done;
	}

	for (i = 0; i <= 0xff; i++) {
		struct dirent *dent;

		if (asprintf(&path, "%s/%.2x", path_objects, i) == -1) {
			err = got_error_from_errno("asprintf");
			break;
		}

		dir = opendir(path);
		if (dir == NULL) {
			if (errno == ENOENT) {
				err = NULL;
				continue;
			}
			err = got_error_from_errno2("opendir", path);
			break;
		}

		while ((dent = readdir(dir)) != NULL) {
			char *id_str;

			if (strcmp(dent->d_name, ".") == 0 ||
			    strcmp(dent->d_name, "..") == 0)
				continue;

			if (asprintf(&id_str, "%.2x%s", i, dent->d_name) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}

			memset(&id, 0, sizeof(id));
			if (!got_parse_sha1_digest(id.sha1, id_str)) {
				free(id_str);
				continue;
			}
			free(id_str);

			err = got_object_open_loose_fd(&fd, &id, repo);
			if (err)
				goto done;
			if (fstat(fd, &sb) == -1) {
				err = got_error_from_errno("fstat");
				goto done;
			}
			err = got_object_read_header_privsep(&obj, &id, repo,
			    fd);
			if (err)
				goto done;
			fd = -1; /* already closed */

			switch (obj->type) {
			case GOT_OBJ_TYPE_COMMIT:
			case GOT_OBJ_TYPE_TREE:
			case GOT_OBJ_TYPE_BLOB:
			case GOT_OBJ_TYPE_TAG:
				break;
			default:
				err = got_error_fmt(GOT_ERR_OBJ_TYPE,
				    "%d", obj->type);
				goto done;
			}
			got_object_close(obj);
			obj = NULL;
			(*ondisk_size) += sb.st_size;
			err = got_object_idset_add(*loose_ids, &id, NULL);
			if (err)
				goto done;
			err = report_cleanup_progress(progress_cb,
			    progress_arg, rl,
			    got_object_idset_num_elements(*loose_ids), -1, -1);
			if (err)
				goto done;
		}

		if (closedir(dir) != 0) {
			err = got_error_from_errno("closedir");
			goto done;
		}
		dir = NULL;

		free(path);
		path = NULL;
	}
done:
	if (dir && closedir(dir) != 0 && err == NULL)
		err = got_error_from_errno("closedir");
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (err) {
		got_object_idset_free(*loose_ids);
		*loose_ids = NULL;
	}
	if (obj)
		got_object_close(obj);
	free(path_objects);
	free(path);
	return err;
}

static const struct got_error *
preserve_loose_object(struct got_object_idset *loose_ids,
    struct got_object_id *id, struct got_repository *repo, int *npacked)
{
	const struct got_error *err = NULL;
	struct got_object *obj;

	if (!got_object_idset_contains(loose_ids, id))
		return NULL;

	/*
	 * Try to open this object from a pack file. This ensures that
	 * we do in fact have a valid packed copy of the object. Otherwise
	 * we should not delete the loose representation of this object.
	 */
	err = got_object_open_packed(&obj, id, repo);
	if (err == NULL) {
		got_object_close(obj);
		/*
		 * The object is referenced and packed.
		 * We can purge the redundantly stored loose object.
		 */
		(*npacked)++;
		return NULL;
	} else if (err->code != GOT_ERR_NO_OBJ)
		return err;

	/*
	 * This object is referenced and not packed.
	 * Remove it from our purge set.
	 */
	return got_object_idset_remove(NULL, loose_ids, id);
}

static const struct got_error *
load_tree_entries(struct got_object_id_queue *ids,
    struct got_object_idset *loose_ids,
    struct got_object_idset *traversed_ids, struct got_object_id *tree_id,
    const char *dpath, struct got_repository *repo, int *npacked,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct got_tree_object *tree;
	char *p = NULL;
	int i;

	err = got_object_open_as_tree(&tree, repo, tree_id);
	if (err)
		return err;

	for (i = 0; i < got_object_tree_get_nentries(tree); i++) {
		struct got_tree_entry *e = got_object_tree_get_entry(tree, i);
		struct got_object_id *id = got_tree_entry_get_id(e);
		mode_t mode = got_tree_entry_get_mode(e);

		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}

		if (got_object_tree_entry_is_symlink(e) ||
		    got_object_tree_entry_is_submodule(e) ||
		    got_object_idset_contains(traversed_ids, id))
			continue;

		if (asprintf(&p, "%s%s%s", dpath, dpath[0] != '\0' ? "/" : "",
		    got_tree_entry_get_name(e)) == -1) {
			err = got_error_from_errno("asprintf");
			break;
		}

		if (S_ISDIR(mode)) {
			struct got_object_qid *qid;
			err = got_object_qid_alloc(&qid, id);
			if (err)
				break;
			STAILQ_INSERT_TAIL(ids, qid, entry);
		} else if (S_ISREG(mode)) {
			/* This blob is referenced. */
			err = preserve_loose_object(loose_ids, id, repo,
			    npacked);
			if (err)
				break;
			err = got_object_idset_add(traversed_ids, id, NULL);
			if (err)
				break;
		}
		free(p);
		p = NULL;
	}

	got_object_tree_close(tree);
	free(p);
	return err;
}

static const struct got_error *
load_tree(struct got_object_idset *loose_ids,
    struct got_object_idset *traversed_ids, struct got_object_id *tree_id,
    const char *dpath, struct got_repository *repo, int *npacked,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id_queue tree_ids;
	struct got_object_qid *qid;

	err = got_object_qid_alloc(&qid, tree_id);
	if (err)
		return err;

	STAILQ_INIT(&tree_ids);
	STAILQ_INSERT_TAIL(&tree_ids, qid, entry);

	while (!STAILQ_EMPTY(&tree_ids)) {
		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}

		qid = STAILQ_FIRST(&tree_ids);
		STAILQ_REMOVE_HEAD(&tree_ids, entry);

		if (got_object_idset_contains(traversed_ids, &qid->id)) {
			got_object_qid_free(qid);
			continue;
		}

		err = got_object_idset_add(traversed_ids, &qid->id, NULL);
		if (err) {
			got_object_qid_free(qid);
			break;
		}

		/* This tree is referenced. */
		err = preserve_loose_object(loose_ids, &qid->id, repo, npacked);
		if (err)
			break;

		err = load_tree_entries(&tree_ids, loose_ids, traversed_ids,
		    &qid->id, dpath, repo, npacked, cancel_cb, cancel_arg);
		got_object_qid_free(qid);
		if (err)
			break;
	}

	got_object_id_queue_free(&tree_ids);
	return err;
}

static const struct got_error *
load_commit_or_tag(struct got_object_idset *loose_ids, int *ncommits,
    int *npacked, struct got_object_idset *traversed_ids,
    struct got_object_id *id, struct got_repository *repo,
    got_cleanup_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, int nloose,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct got_commit_object *commit = NULL;
	struct got_tag_object *tag = NULL;
	struct got_object_id *tree_id = NULL;
	struct got_object_id_queue ids;
	struct got_object_qid *qid;
	int obj_type;

	err = got_object_qid_alloc(&qid, id);
	if (err)
		return err;

	STAILQ_INIT(&ids);
	STAILQ_INSERT_TAIL(&ids, qid, entry);

	while (!STAILQ_EMPTY(&ids)) {
		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}

		qid = STAILQ_FIRST(&ids);
		STAILQ_REMOVE_HEAD(&ids, entry);

		if (got_object_idset_contains(traversed_ids, &qid->id)) {
			got_object_qid_free(qid);
			qid = NULL;
			continue;
		}

		err = got_object_idset_add(traversed_ids, &qid->id, NULL);
		if (err)
			break;

		/* This commit or tag is referenced. */
		err = preserve_loose_object(loose_ids, &qid->id, repo, npacked);
		if (err)
			break;

		err = got_object_get_type(&obj_type, repo, &qid->id);
		if (err)
			break;
		switch (obj_type) {
		case GOT_OBJ_TYPE_COMMIT:
			err = got_object_open_as_commit(&commit, repo,
			    &qid->id);
			if (err)
				goto done;
			break;
		case GOT_OBJ_TYPE_TAG:
			err = got_object_open_as_tag(&tag, repo, &qid->id);
			if (err)
				goto done;
			break;
		default:
			/* should not happen */
			err = got_error(GOT_ERR_OBJ_TYPE);
			goto done;
		}

		/* Find a tree object to scan. */
		if (commit) {
			tree_id = got_object_commit_get_tree_id(commit);
		} else if (tag) {
			obj_type = got_object_tag_get_object_type(tag);
			switch (obj_type) {
			case GOT_OBJ_TYPE_COMMIT:
				err = got_object_open_as_commit(&commit, repo,
				    got_object_tag_get_object_id(tag));
				if (err)
					goto done;
				tree_id = got_object_commit_get_tree_id(commit);
				break;
			case GOT_OBJ_TYPE_TREE:
				tree_id = got_object_tag_get_object_id(tag);
				break;
			default:
				/*
				 * Tag points at something other than a
				 * commit or tree. Leave this weird tag object
				 * and the object it points to on disk.
				 */
				err = got_object_idset_remove(NULL, loose_ids,
				    &qid->id);
				if (err && err->code != GOT_ERR_NO_OBJ)
					goto done;
				err = got_object_idset_remove(NULL, loose_ids,
				    got_object_tag_get_object_id(tag));
				if (err && err->code != GOT_ERR_NO_OBJ)
					goto done;
				err = NULL;
				break;
			}
		}

		if (tree_id) {
			err = load_tree(loose_ids, traversed_ids, tree_id, "",
			    repo, npacked, cancel_cb, cancel_arg);
			if (err)
				break;
		}

		if (commit || tag)
			(*ncommits)++; /* scanned tags are counted as commits */

		err = report_cleanup_progress(progress_cb, progress_arg, rl,
		    nloose, *ncommits, -1);
		if (err)
			break;

		if (commit) {
			/* Find parent commits to scan. */
			const struct got_object_id_queue *parent_ids;
			parent_ids = got_object_commit_get_parent_ids(commit);
			err = got_object_id_queue_copy(parent_ids, &ids);
			if (err)
				break;
			got_object_commit_close(commit);
			commit = NULL;
		}
		if (tag) {
			got_object_tag_close(tag);
			tag = NULL;
		}
		got_object_qid_free(qid);
		qid = NULL;
	}
done:
	if (qid)
		got_object_qid_free(qid);
	if (commit)
		got_object_commit_close(commit);
	if (tag)
		got_object_tag_close(tag);
	got_object_id_queue_free(&ids);
	return err;
}

struct purge_loose_object_arg {
	struct got_repository *repo;
	got_cleanup_progress_cb progress_cb;
	void *progress_arg;
	struct got_ratelimit *rl;
	int nloose;
	int ncommits;
	int npurged;
	off_t size_purged;
	int dry_run;
	time_t max_mtime;
	int ignore_mtime;
};

static const struct got_error *
purge_loose_object(struct got_object_id *id, void *data, void *arg)
{
	struct purge_loose_object_arg *a = arg;
	const struct got_error *err, *unlock_err = NULL;
	char *path = NULL;
	int fd = -1;
	struct stat sb;
	struct got_lockfile *lf = NULL;

	err = got_object_get_path(&path, id, a->repo);
	if (err)
		return err;

	err = got_object_open_loose_fd(&fd, id, a->repo);
	if (err)
		goto done;

	if (fstat(fd, &sb) == -1) {
		err = got_error_from_errno("fstat");
		goto done;
	}

	/*
	 * Do not delete objects which are younger than our maximum
	 * modification time threshold. This prevents a race where
	 * new objects which are being added to the repository
	 * concurrently would be deleted.
	 */
	if (a->ignore_mtime || sb.st_mtime <= a->max_mtime) {
		if (!a->dry_run) {
			err = got_lockfile_lock(&lf, path, -1);
			if (err)
				goto done;
			if (unlink(path) == -1) {
				err = got_error_from_errno2("unlink", path);
				goto done;
			}
		}

		a->npurged++;
		a->size_purged += sb.st_size;
		err = report_cleanup_progress(a->progress_cb, a->progress_arg,
		    a->rl, a->nloose, a->ncommits, a->npurged);
		if (err)
			goto done;
	}
done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	free(path);
	if (lf)
		unlock_err = got_lockfile_unlock(lf, -1);
	return err ? err : unlock_err;
}

const struct got_error *
got_repo_purge_unreferenced_loose_objects(struct got_repository *repo,
    off_t *size_before, off_t *size_after, int *npacked, int dry_run,
    int ignore_mtime, got_cleanup_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct got_object_idset *loose_ids;
	struct got_object_idset *traversed_ids;
	struct got_object_id **referenced_ids;
	int i, nreferenced, nloose, ncommits = 0;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	struct purge_loose_object_arg arg;
	time_t max_mtime = 0;
	struct got_ratelimit rl;

	TAILQ_INIT(&refs);
	got_ratelimit_init(&rl, 0, 500);

	*size_before = 0;
	*size_after = 0;
	*npacked = 0;

	err = get_loose_object_ids(&loose_ids, size_before,
	    progress_cb, progress_arg, &rl, repo);
	if (err)
		return err;
	nloose = got_object_idset_num_elements(loose_ids);
	if (nloose == 0) {
		got_object_idset_free(loose_ids);
		if (progress_cb) {
			err = progress_cb(progress_arg, 0, 0, 0);
			if (err)
				return err;
		}
		return NULL;
	}

	traversed_ids = got_object_idset_alloc();
	if (traversed_ids == NULL) {
		err = got_error_from_errno("got_object_idset_alloc");
		goto done;
	}

	err = got_ref_list(&refs, repo, "", got_ref_cmp_by_name, NULL);
	if (err)
		goto done;
	if (!ignore_mtime) {
		TAILQ_FOREACH(re, &refs, entry) {
			time_t mtime = got_ref_get_mtime(re->ref);
			if (mtime > max_mtime)
				max_mtime = mtime;
		}
		/*
		 * For safety, keep objects created within 10 minutes
		 * before the youngest reference was created.
		 */
		if (max_mtime >= 600)
			max_mtime -= 600;
	}

	err = get_reflist_object_ids(&referenced_ids, &nreferenced,
	    (1 << GOT_OBJ_TYPE_COMMIT) | (1 << GOT_OBJ_TYPE_TAG),
	    &refs, repo, cancel_cb, cancel_arg);
	if (err)
		goto done;

	for (i = 0; i < nreferenced; i++) {
		struct got_object_id *id = referenced_ids[i];
		err = load_commit_or_tag(loose_ids, &ncommits, npacked,
		    traversed_ids, id, repo, progress_cb, progress_arg, &rl,
		    nloose, cancel_cb, cancel_arg);
		if (err)
			goto done;
	}

	/* Any remaining loose objects are unreferenced and can be purged. */
	arg.repo = repo;
	arg.progress_arg = progress_arg;
	arg.progress_cb = progress_cb;
	arg.rl = &rl;
	arg.nloose = nloose;
	arg.npurged = 0;
	arg.size_purged = 0;
	arg.ncommits = ncommits;
	arg.dry_run = dry_run;
	arg.max_mtime = max_mtime;
	arg.ignore_mtime = ignore_mtime;
	err = got_object_idset_for_each(loose_ids, purge_loose_object, &arg);
	if (err)
		goto done;
	*size_after = *size_before - arg.size_purged;

	/* Produce a final progress report. */
	if (progress_cb) {
		err = progress_cb(progress_arg, nloose, ncommits, arg.npurged);
		if (err)
			goto done;
	}
done:
	got_object_idset_free(loose_ids);
	got_object_idset_free(traversed_ids);
	return err;
}

static const struct got_error *
remove_packidx(int dir_fd, const char *relpath)
{
	const struct got_error *err, *unlock_err;
	struct got_lockfile *lf;

	err = got_lockfile_lock(&lf, relpath, dir_fd);
	if (err)
		return err;
	if (unlinkat(dir_fd, relpath, 0) == -1)
		err = got_error_from_errno("unlinkat");
	unlock_err = got_lockfile_unlock(lf, dir_fd);
	return err ? err : unlock_err;
}

const struct got_error *
got_repo_remove_lonely_packidx(struct got_repository *repo, int dry_run,
    got_lonely_packidx_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	DIR *packdir = NULL;
	struct dirent *dent;
	char *pack_relpath = NULL;
	int packdir_fd;
	struct stat sb;

	packdir_fd = openat(got_repo_get_fd(repo),
	    GOT_OBJECTS_PACK_DIR, O_DIRECTORY | O_CLOEXEC);
	if (packdir_fd == -1) {
		if (errno == ENOENT)
			return NULL;
		return got_error_from_errno_fmt("openat: %s/%s",
		    got_repo_get_path_git_dir(repo),
		    GOT_OBJECTS_PACK_DIR);
	}

	packdir = fdopendir(packdir_fd);
	if (packdir == NULL) {
		err = got_error_from_errno("fdopendir");
		goto done;
	}

	while ((dent = readdir(packdir)) != NULL) {
		if (cancel_cb) {
			err = cancel_cb(cancel_arg);
			if (err)
				goto done;
		}

		if (!got_repo_is_packidx_filename(dent->d_name, dent->d_namlen))
			continue;

		err = got_packidx_get_packfile_path(&pack_relpath,
		    dent->d_name);
		if (err)
			goto done;

		if (fstatat(packdir_fd, pack_relpath, &sb, 0) != -1) {
			free(pack_relpath);
			pack_relpath = NULL;
			continue;
		}
		if (errno != ENOENT) {
			err = got_error_from_errno_fmt("fstatat: %s/%s/%s",
			    got_repo_get_path_git_dir(repo),
			    GOT_OBJECTS_PACK_DIR,
			    pack_relpath);
			goto done;
		}

		if (!dry_run) {
			err = remove_packidx(packdir_fd, dent->d_name);
			if (err)
				goto done;
		}
		if (progress_cb) {
			char *path;
			if (asprintf(&path, "%s/%s/%s",
			    got_repo_get_path_git_dir(repo),
			    GOT_OBJECTS_PACK_DIR,
			    dent->d_name) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
			err = progress_cb(progress_arg, path);
			free(path);
			if (err)
				goto done;
		}
		free(pack_relpath);
		pack_relpath = NULL;
	}
done:
	if (packdir && closedir(packdir) != 0 && err == NULL)
		err = got_error_from_errno("closedir");
	free(pack_relpath);
	return err;
}
