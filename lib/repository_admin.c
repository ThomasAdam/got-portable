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
#include "got_lib_object_cache.h"
#include "got_lib_pack.h"
#include "got_lib_privsep.h"
#include "got_lib_repository.h"
#include "got_lib_pack_create.h"
#include "got_lib_sha1.h"

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
    int loose_obj_only, got_pack_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id **ours = NULL, **theirs = NULL;
	int nours = 0, ntheirs = 0, packfd = -1, i;
	char *tmpfile_path = NULL, *path = NULL, *packfile_path = NULL;
	char *sha1_str = NULL;

	*packfile = NULL;
	*pack_hash = NULL;

	if (asprintf(&path, "%s/%s/packing.pack",
	    got_repo_get_path_git_dir(repo), GOT_OBJECTS_PACK_DIR) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	err = got_opentemp_named_fd(&tmpfile_path, &packfd, path);
	if (err)
		goto done;

	if (fchmod(packfd, GOT_DEFAULT_FILE_MODE) != 0) {
		err = got_error_from_errno2("fchmod", tmpfile_path);
		goto done;
	}

	*packfile = fdopen(packfd, "w");
	if (*packfile == NULL) {
		err = got_error_from_errno2("fdopen", tmpfile_path);
		goto done;
	}
	packfd = -1;

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

	err = got_pack_create((*pack_hash)->sha1, *packfile, theirs, ntheirs,
	    ours, nours, repo, loose_obj_only, progress_cb, progress_arg,
	    cancel_cb, cancel_arg);
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

	if (fflush(*packfile) == -1) {
		err = got_error_from_errno("fflush");
		goto done;
	}
	if (fseek(*packfile, 0L, SEEK_SET) == -1) {
		err = got_error_from_errno("fseek");
		goto done;
	}
	if (rename(tmpfile_path, packfile_path) == -1) {
		err = got_error_from_errno3("rename", tmpfile_path,
		    packfile_path);
		goto done;
	}
	free(tmpfile_path);
	tmpfile_path = NULL;
done:
	for (i = 0; i < nours; i++)
		free(ours[i]);
	free(ours);
	for (i = 0; i < ntheirs; i++)
		free(theirs[i]);
	free(theirs);
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno2("close", packfile_path);
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
	err = got_opentemp_named_fd(&tmpidxpath, &idxfd, path);
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
		imsg_clear(&idxibuf);
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

	packfd = open(packfile_path, O_RDONLY | O_NOFOLLOW);
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
