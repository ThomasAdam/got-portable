/*
 * Copyright (c) 2023 Omar Polo <op@openbsd.org>
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

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/tree.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <endian.h>
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
#include "got_cancel.h"
#include "got_object.h"
#include "got_opentemp.h"
#include "got_path.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_repository_load.h"

#include "got_lib_delta.h"
#include "got_lib_hash.h"
#include "got_lib_object.h"
#include "got_lib_object_cache.h"
#include "got_lib_pack.h"
#include "got_lib_ratelimit.h"
#include "got_lib_repository.h"
#include "got_lib_privsep.h"

#define GIT_BUNDLE_SIGNATURE_V2 "# v2 git bundle\n"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#ifndef ssizeof
#define ssizeof(_x) ((ssize_t)(sizeof(_x)))
#endif

static const struct got_error *
temp_file(int *fd, char **path, const char *ext, struct got_repository *repo)
{
	const struct got_error *err;
	char p[PATH_MAX];
	int r;

	*path = NULL;

	r = snprintf(p, sizeof(p), "%s/%s/loading",
	    got_repo_get_path_git_dir(repo), GOT_OBJECTS_PACK_DIR);
	if (r < 0 || (size_t)r >= sizeof(p))
		return got_error_from_errno("snprintf");

	err = got_opentemp_named_fd(path, fd, p, ext);
	if (err)
		return err;

	if (fchmod(*fd, GOT_DEFAULT_FILE_MODE) == -1)
		return got_error_from_errno("fchmod");

	return NULL;
}

static const struct got_error *
load_report_progress(got_load_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, off_t packsiz, int nobj_total,
    int nobj_indexed, int nobj_loose, int nobj_resolved)
{
	const struct got_error *err;
	int elapsed;

	if (progress_cb == NULL)
		return NULL;

	err = got_ratelimit_check(&elapsed, rl);
	if (err || !elapsed)
		return err;

	return progress_cb(progress_arg, packsiz, nobj_total, nobj_indexed,
	    nobj_loose, nobj_resolved);
}

static const struct got_error *
copypack(FILE *in, int outfd, off_t *tot,
    struct got_object_id *id, struct got_ratelimit *rl,
    got_load_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct got_hash hash;
	struct got_object_id expected_id;
	char buf[BUFSIZ], sha1buf[SHA1_DIGEST_LENGTH];
	size_t r, sha1buflen = 0;

	*tot = 0;
	got_hash_init(&hash, GOT_HASH_SHA1);

	for (;;) {
		err = cancel_cb(cancel_arg);
		if (err)
			return err;

		r = fread(buf, 1, sizeof(buf), in);
		if (r == 0)
			break;

		/*
		 * An expected SHA1 checksum sits at the end of the
		 * pack file.  Since we don't know the file size ahead
		 * of time we have to keep SHA1_DIGEST_LENGTH bytes
		 * buffered and avoid mixing those bytes int our hash
		 * computation until we know for sure that additional
		 * pack file data bytes follow.
		 *
		 * We can assume that BUFSIZE is greater than
		 * SHA1_DIGEST_LENGTH and that a short read means that
		 * we've reached EOF.
		 */

		if (r >= sizeof(sha1buf)) {
			*tot += sha1buflen;
			got_hash_update(&hash, sha1buf, sha1buflen);
			if (write(outfd, sha1buf, sha1buflen) == -1)
				return got_error_from_errno("write");

			r -= sizeof(sha1buf);
			memcpy(sha1buf, &buf[r], sizeof(sha1buf));
			sha1buflen = sizeof(sha1buf);

			*tot += r;
			got_hash_update(&hash, buf, r);
			if (write(outfd, buf, r) == -1)
				return got_error_from_errno("write");

			err = load_report_progress(progress_cb, progress_arg,
			    rl, *tot, 0, 0, 0, 0);
			if (err)
				return err;

			continue;
		}

		if (sha1buflen == 0)
			return got_error(GOT_ERR_BAD_PACKFILE);

		/* short read, we've reached EOF */
		*tot += r;
		got_hash_update(&hash, sha1buf, r);
		if (write(outfd, sha1buf, r) == -1)
			return got_error_from_errno("write");

		memmove(&sha1buf[0], &sha1buf[r], sizeof(sha1buf) - r);
		memcpy(&sha1buf[sizeof(sha1buf) - r], buf, r);
		break;
	}

	if (sha1buflen == 0)
		return got_error(GOT_ERR_BAD_PACKFILE);

	got_hash_final_object_id(&hash, id);

	/* XXX SHA256 */
	memset(&expected_id, 0, sizeof(expected_id));
	memcpy(&expected_id.hash, sha1buf, sizeof(expected_id.hash));

	if (got_object_id_cmp(id, &expected_id) != 0)
		return got_error(GOT_ERR_PACKIDX_CSUM);

	/* re-add the expected hash at the end of the pack */
	if (write(outfd, sha1buf, sizeof(sha1buf)) == -1)
		return got_error_from_errno("write");

	*tot += sizeof(sha1buf);
	err = progress_cb(progress_arg, *tot, 0, 0, 0, 0);
	if (err)
		return err;

	return NULL;
}

const struct got_error *
got_repo_load(FILE *in, struct got_pathlist_head *refs_found,
    struct got_repository *repo, int list_refs_only, int noop,
    got_load_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id id;
	struct got_object *obj;
	struct got_packfile_hdr pack_hdr;
	struct got_ratelimit rl;
	struct imsgbuf idxibuf;
	const char *repo_path;
	char *packpath = NULL, *idxpath = NULL;
	char *tmppackpath = NULL, *tmpidxpath = NULL;
	int packfd = -1, idxfd = -1;
	char *spc, *refname, *id_str = NULL;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	size_t i;
	ssize_t n;
	off_t packsiz;
	int tmpfds[3] = {-1, -1, -1};
	int imsg_idxfds[2] = {-1, -1};
	int ch, done, nobj, idxstatus;
	pid_t idxpid;

	got_ratelimit_init(&rl, 0, 500);

	repo_path = got_repo_get_path_git_dir(repo);

	linelen = getline(&line, &linesize, in);
	if (linelen == -1) {
		err = got_ferror(in, GOT_ERR_IO);
		goto done;
	}

	if (strcmp(line, GIT_BUNDLE_SIGNATURE_V2) != 0) {
		err = got_error(GOT_ERR_BUNDLE_FORMAT);
		goto done;
	}

	/* Parse the prerequisite */
	for (;;) {
		ch = fgetc(in);
		if (ch != '-') {
			if (ch != EOF)
				ungetc(ch, in);
			break;
		}

		linelen = getline(&line, &linesize, in);
		if (linelen == -1) {
			err = got_ferror(in, GOT_ERR_IO);
			goto done;
		}

		if (line[linelen - 1] == '\n')
			line[linelen - 1] = '\0';

		if (!got_parse_object_id(&id, line, GOT_HASH_SHA1)) {
			err = got_error_path(line, GOT_ERR_BAD_OBJ_ID_STR);
			goto done;
		}

		err = got_object_open(&obj, repo, &id);
		if (err)
			goto done;
		got_object_close(obj);
	}

	/* Read references */
	for (;;) {
		struct got_object_id *id;
		char *dup;

		linelen = getline(&line, &linesize, in);
		if (linelen == -1) {
			err = got_ferror(in, GOT_ERR_IO);
			goto done;
		}
		if (line[linelen - 1] == '\n')
			line[linelen - 1] = '\0';
		if (*line == '\0')
			break;

		spc = strchr(line, ' ');
		if (spc == NULL) {
			err = got_error(GOT_ERR_IO);
			goto done;
		}
		*spc = '\0';

		refname = spc + 1;
		if (!got_ref_name_is_valid(refname)) {
			err = got_error(GOT_ERR_BAD_REF_DATA);
			goto done;
		}

		id = malloc(sizeof(*id));
		if (id == NULL) {
			err = got_error_from_errno("malloc");
			goto done;
		}

		if (!got_parse_object_id(id, line, GOT_HASH_SHA1)) {
			free(id);
			err = got_error(GOT_ERR_BAD_OBJ_ID_STR);
			goto done;
		}

		dup = strdup(refname);
		if (dup == NULL) {
			free(id);
			err = got_error_from_errno("strdup");
			goto done;
		}

		err = got_pathlist_append(refs_found, dup, id);
		if (err) {
			free(id);
			free(dup);
			goto done;
		}
	}

	if (list_refs_only)
		goto done;

	err = temp_file(&packfd, &tmppackpath, ".pack", repo);
	if (err)
		goto done;

	err = temp_file(&idxfd, &tmpidxpath, ".idx", repo);
	if (err)
		goto done;

	err = copypack(in, packfd, &packsiz, &id, &rl,
	    progress_cb, progress_arg, cancel_cb, cancel_arg);
	if (err)
		goto done;

	if (lseek(packfd, 0, SEEK_SET) == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}

	/* Safety checks on the pack' content. */
	if (packsiz <= ssizeof(pack_hdr) + SHA1_DIGEST_LENGTH) {
		err = got_error_msg(GOT_ERR_BAD_PACKFILE, "short pack file");
		goto done;
	}

	n = read(packfd, &pack_hdr, ssizeof(pack_hdr));
	if (n == -1) {
		err = got_error_from_errno("read");
		goto done;
	}
	if (n != ssizeof(pack_hdr)) {
		err = got_error(GOT_ERR_IO);
		goto done;
	}
	if (pack_hdr.signature != htobe32(GOT_PACKFILE_SIGNATURE)) {
		err = got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "bad pack file signature");
		goto done;
	}
	if (pack_hdr.version != htobe32(GOT_PACKFILE_VERSION)) {
		err = got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "bad pack file version");
		goto done;
	}
	nobj = be32toh(pack_hdr.nobjects);
	if (nobj == 0 &&
	    packsiz > ssizeof(pack_hdr) + SHA1_DIGEST_LENGTH) {
		err = got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "bad pack file with zero objects");
		goto done;
	}
	if (nobj != 0 &&
	    packsiz <= ssizeof(pack_hdr) + SHA1_DIGEST_LENGTH) {
		err = got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "empty pack file with non-zero object count");
		goto done;
	}

	/* nothing to do if there are no objects. */
	if (nobj == 0)
		goto done;

	for (i = 0; i < nitems(tmpfds); i++) {
		tmpfds[i] = got_opentempfd();
		if (tmpfds[i] == -1) {
			err = got_error_from_errno("got_opentempfd");
			goto done;
		}
	}

	if (lseek(packfd, 0, SEEK_SET) == -1) {
		err = got_error_from_errno("lseek");
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
		    GOT_PATH_PROG_INDEX_PACK, tmppackpath);
	if (close(imsg_idxfds[1]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	imsg_idxfds[1] = -1;
	imsg_init(&idxibuf, imsg_idxfds[0]);

	err = got_privsep_send_index_pack_req(&idxibuf, id.hash, packfd);
	if (err)
		goto done;
	packfd = -1;

	err = got_privsep_send_index_pack_outfd(&idxibuf, idxfd);
	if (err)
		goto done;
	idxfd = -1;

	for (i = 0; i < nitems(tmpfds); i++) {
		err = got_privsep_send_tmpfd(&idxibuf, tmpfds[i]);
		if (err != NULL)
			goto done;
		tmpfds[i] = -1;
	}

	done = 0;
	while (!done) {
		int nobj_total, nobj_indexed, nobj_loose, nobj_resolved;

		err = got_privsep_recv_index_progress(&done, &nobj_total,
		    &nobj_indexed, &nobj_loose, &nobj_resolved, &idxibuf);
		if (err)
			goto done;
		if (nobj_indexed != 0) {
			err = load_report_progress(progress_cb, progress_arg,
			    &rl, packsiz, nobj_total, nobj_indexed,
			    nobj_loose, nobj_resolved);
			if (err)
				goto done;
		}
	}
	if (close(imsg_idxfds[0]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	imsg_idxfds[0] = -1;
	if (waitpid(idxpid, &idxstatus, 0) == -1) {
		err = got_error_from_errno("waitpid");
		goto done;
	}

	if (noop)
		goto done;

	err = got_object_id_str(&id_str, &id);
	if (err)
		goto done;

	if (asprintf(&packpath, "%s/%s/pack-%s.pack", repo_path,
	    GOT_OBJECTS_PACK_DIR, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (asprintf(&idxpath, "%s/%s/pack-%s.idx", repo_path,
	    GOT_OBJECTS_PACK_DIR, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (rename(tmppackpath, packpath) == -1) {
		err = got_error_from_errno3("rename", tmppackpath, packpath);
		goto done;
	}
	free(tmppackpath);
	tmppackpath = NULL;

	if (rename(tmpidxpath, idxpath) == -1) {
		err = got_error_from_errno3("rename", tmpidxpath, idxpath);
		goto done;
	}
	free(tmpidxpath);
	tmpidxpath = NULL;

 done:
	free(line);
	free(packpath);
	free(idxpath);
	free(id_str);

	if (tmppackpath && unlink(tmppackpath) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", tmppackpath);
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	free(tmppackpath);

	if (tmpidxpath && unlink(tmpidxpath) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", tmpidxpath);
	if (idxfd != -1 && close(idxfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	free(tmpidxpath);

	if (imsg_idxfds[0] != -1 && close(imsg_idxfds[0]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (imsg_idxfds[1] != -1 && close(imsg_idxfds[1]) == -1 && err == NULL)
		err = got_error_from_errno("close");

	for (i = 0; i < nitems(tmpfds); ++i)
		if (tmpfds[i] != -1 && close(tmpfds[i]) == -1 && err == NULL)
			err = got_error_from_errno("close");

	return err;
}
