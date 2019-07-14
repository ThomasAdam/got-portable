/*
 * Copyright (c) 2019 Stefan Sperling <stsp@openbsd.org>
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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sha1.h>
#include <unistd.h>
#include <zlib.h>

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_opentemp.h"
#include "got_path.h"

#include "got_lib_sha1.h"
#include "got_lib_deflate.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_lockfile.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

static const struct got_error *
create_object_file(struct got_object_id *id, FILE *content,
    struct got_repository *repo)
{
	const struct got_error *err = NULL, *unlock_err = NULL;
	char *objpath = NULL, *tmppath = NULL;
	FILE *tmpfile = NULL;
	struct got_lockfile *lf = NULL;
	size_t tmplen = 0;

	err = got_object_get_path(&objpath, id, repo);
	if (err)
		return err;

	err = got_opentemp_named(&tmppath, &tmpfile, objpath);
	if (err) {
		char *parent_path;
		if (!(err->code == GOT_ERR_ERRNO && errno == ENOENT))
			goto done;
		err = got_path_dirname(&parent_path, objpath);
		if (err)
			goto done;
		err = got_path_mkdir(parent_path);
		free(parent_path);
		if (err)
			goto done;
		err = got_opentemp_named(&tmppath, &tmpfile, objpath);
		if (err)
			goto done;
	}

	err = got_deflate_to_file(&tmplen, content, tmpfile);
	if (err)
		goto done;

	err = got_lockfile_lock(&lf, objpath);
	if (err)
		goto done;

	if (rename(tmppath, objpath) != 0) {
		err = got_error_from_errno3("rename", tmppath, objpath);
		goto done;
	}
	free(tmppath);
	tmppath = NULL;

	if (chmod(objpath, GOT_DEFAULT_FILE_MODE) != 0) {
		err = got_error_from_errno2("chmod", objpath);
		goto done;
	}
done:
	free(objpath);
	if (tmppath) {
		if (unlink(tmppath) != 0 && err == NULL)
			err = got_error_from_errno2("unlink", tmppath);
		free(tmppath);
	}
	if (tmpfile && fclose(tmpfile) != 0 && err == NULL)
		err = got_error_from_errno("fclose");
	if (lf)
		unlock_err = got_lockfile_unlock(lf);
	return err ? err : unlock_err;
}

const struct got_error *
got_object_blob_create(struct got_object_id **id, const char *ondisk_path,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *header = NULL;
	FILE *blobfile = NULL;
	int fd = -1;
	struct stat sb;
	SHA1_CTX sha1_ctx;
	size_t headerlen = 0, n;

	*id = NULL;

	SHA1Init(&sha1_ctx);

	fd = open(ondisk_path, O_RDONLY | O_NOFOLLOW);
	if (fd == -1)
		return got_error_from_errno2("open", ondisk_path);

	if (fstat(fd, &sb) == -1) {
		err = got_error_from_errno2("fstat", ondisk_path);
		goto done;
	}

	if (asprintf(&header, "%s %lld", GOT_OBJ_LABEL_BLOB,
		sb.st_size) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	headerlen = strlen(header) + 1;
	SHA1Update(&sha1_ctx, header, headerlen);

	blobfile = got_opentemp();
	if (blobfile == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	n = fwrite(header, 1, headerlen, blobfile);
	if (n != headerlen) {
		err = got_ferror(blobfile, GOT_ERR_IO);
		goto done;
	}
	for (;;) {
		char buf[8192];
		ssize_t inlen;

		inlen = read(fd, buf, sizeof(buf));
		if (inlen == -1) {
			err = got_error_from_errno("read");
			goto done;
		}
		if (inlen == 0)
			break; /* EOF */
		SHA1Update(&sha1_ctx, buf, inlen);
		n = fwrite(buf, 1, inlen, blobfile);
		if (n != inlen) {
			err = got_ferror(blobfile, GOT_ERR_IO);
			goto done;
		}
	}

	*id = malloc(sizeof(**id));
	if (*id == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}
	SHA1Final((*id)->sha1, &sha1_ctx);

	if (fflush(blobfile) != 0) {
		err = got_error_from_errno("fflush");
		goto done;
	}
	rewind(blobfile);

	err = create_object_file(*id, blobfile, repo);
done:
	free(header);
	if (fd != -1 && close(fd) != 0 && err == NULL)
		err = got_error_from_errno("close");
	if (blobfile && fclose(blobfile) != 0 && err == NULL)
		err = got_error_from_errno("fclose");
	if (err) {
		free(*id);
		*id = NULL;
	}
	return err;
}

static const struct got_error *
mode2str(char *buf, size_t len, mode_t mode)
{
	int ret;
	ret = snprintf(buf, len, "%o ", mode);
	if (ret == -1 || ret >= len)
		return got_error(GOT_ERR_NO_SPACE);
	return NULL;
}

const struct got_error *
got_object_tree_create(struct got_object_id **id,
    struct got_tree_entries *entries, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char modebuf[sizeof("100644 ")];
	SHA1_CTX sha1_ctx;
	char *header = NULL;
	size_t headerlen, len = 0, n;
	FILE *treefile = NULL;
	struct got_tree_entry *te;

	*id = NULL;

	SHA1Init(&sha1_ctx);

	SIMPLEQ_FOREACH(te, &entries->head, entry) {
		err = mode2str(modebuf, sizeof(modebuf), te->mode);
		if (err)
			return err;
		len += strlen(modebuf) + strlen(te->name) + 1 +
		    SHA1_DIGEST_LENGTH;
	}

	if (asprintf(&header, "%s %zd", GOT_OBJ_LABEL_TREE, len) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	headerlen = strlen(header) + 1;
	SHA1Update(&sha1_ctx, header, headerlen);

	treefile = got_opentemp();
	if (treefile == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	n = fwrite(header, 1, headerlen, treefile);
	if (n != headerlen) {
		err = got_ferror(treefile, GOT_ERR_IO);
		goto done;
	}

	SIMPLEQ_FOREACH(te, &entries->head, entry) {
		err = mode2str(modebuf, sizeof(modebuf), te->mode);
		if (err)
			goto done;
		len = strlen(modebuf);
		n = fwrite(modebuf, 1, len, treefile);
		if (n != len) {
			err = got_ferror(treefile, GOT_ERR_IO);
			goto done;
		}
		SHA1Update(&sha1_ctx, modebuf, len);

		len = strlen(te->name) + 1; /* must include NUL */
		n = fwrite(te->name, 1, len, treefile);
		if (n != len) {
			err = got_ferror(treefile, GOT_ERR_IO);
			goto done;
		}
		SHA1Update(&sha1_ctx, te->name, len);

		len = SHA1_DIGEST_LENGTH;
		n = fwrite(te->id->sha1, 1, len, treefile);
		if (n != len) {
			err = got_ferror(treefile, GOT_ERR_IO);
			goto done;
		}
		SHA1Update(&sha1_ctx, te->id->sha1, len);
	}

	*id = malloc(sizeof(**id));
	if (*id == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}
	SHA1Final((*id)->sha1, &sha1_ctx);

	if (fflush(treefile) != 0) {
		err = got_error_from_errno("fflush");
		goto done;
	}
	rewind(treefile);

	err = create_object_file(*id, treefile, repo);
done:
	free(header);
	if (treefile && fclose(treefile) != 0 && err == NULL)
		err = got_error_from_errno("fclose");
	if (err) {
		free(*id);
		*id = NULL;
	}
	return err;
}

const struct got_error *
got_object_commit_create(struct got_object_id **id,
    struct got_object_id *tree_id, struct got_object_id_queue *parent_ids,
    int nparents, const char *author, time_t author_time,
    const char *committer, time_t committer_time,
    const char *logmsg, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	SHA1_CTX sha1_ctx;
	char *header = NULL, *tree_str = NULL;
	char *author_str = NULL, *committer_str = NULL;
	char *id_str = NULL;
	size_t headerlen, len = 0, n;
	FILE *commitfile = NULL;
	struct got_object_qid *qid;
	char *msg0, *msg;

	*id = NULL;

	SHA1Init(&sha1_ctx);

	msg0 = strdup(logmsg);
	if (msg0 == NULL)
		return got_error_from_errno("strdup");
	msg = msg0;

	while (isspace((unsigned char)msg[0]))
		msg++;
	len = strlen(msg);
	while (len > 0 && isspace((unsigned char)msg[len - 1])) {
		msg[len - 1] = '\0';
		len--;
	}

	if (asprintf(&author_str, "%s%s %lld +0000\n",
	    GOT_COMMIT_LABEL_AUTHOR, author, author_time) == -1)
		return got_error_from_errno("asprintf");

	if (asprintf(&committer_str, "%s%s %lld +0000\n",
	    GOT_COMMIT_LABEL_COMMITTER, committer ? committer : author,
	    committer ? committer_time : author_time)
	    == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	len = strlen(GOT_COMMIT_LABEL_TREE) + SHA1_DIGEST_STRING_LENGTH +
	    nparents *
	    (strlen(GOT_COMMIT_LABEL_PARENT) + SHA1_DIGEST_STRING_LENGTH) +
	    + strlen(author_str) + strlen(committer_str) + 2 + strlen(msg);

	if (asprintf(&header, "%s %zd", GOT_OBJ_LABEL_COMMIT, len) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	headerlen = strlen(header) + 1;
	SHA1Update(&sha1_ctx, header, headerlen);

	commitfile = got_opentemp();
	if (commitfile == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	n = fwrite(header, 1, headerlen, commitfile);
	if (n != headerlen) {
		err = got_ferror(commitfile, GOT_ERR_IO);
		goto done;
	}

	err = got_object_id_str(&id_str, tree_id);
	if (err)
		goto done;
	if (asprintf(&tree_str, "%s%s\n", GOT_COMMIT_LABEL_TREE, id_str)
	    == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	len = strlen(tree_str);
	SHA1Update(&sha1_ctx, tree_str, len);
	n = fwrite(tree_str, 1, len, commitfile);
	if (n != len) {
		err = got_ferror(commitfile, GOT_ERR_IO);
		goto done;
	}

	if (parent_ids) {
		SIMPLEQ_FOREACH(qid, parent_ids, entry) {
			char *parent_str = NULL;

			free(id_str);

			err = got_object_id_str(&id_str, qid->id);
			if (err)
				goto done;
			if (asprintf(&parent_str, "%s%s\n",
			    GOT_COMMIT_LABEL_PARENT, id_str) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
			len = strlen(parent_str);
			SHA1Update(&sha1_ctx, parent_str, len);
			n = fwrite(parent_str, 1, len, commitfile);
			if (n != len) {
				err = got_ferror(commitfile, GOT_ERR_IO);
				free(parent_str);
				goto done;
			}
			free(parent_str);
		}
	}

	len = strlen(author_str);
	SHA1Update(&sha1_ctx, author_str, len);
	n = fwrite(author_str, 1, len, commitfile);
	if (n != len) {
		err = got_ferror(commitfile, GOT_ERR_IO);
		goto done;
	}

	len = strlen(committer_str);
	SHA1Update(&sha1_ctx, committer_str, len);
	n = fwrite(committer_str, 1, len, commitfile);
	if (n != len) {
		err = got_ferror(commitfile, GOT_ERR_IO);
		goto done;
	}

	SHA1Update(&sha1_ctx, "\n", 1);
	n = fwrite("\n", 1, 1, commitfile);
	if (n != 1) {
		err = got_ferror(commitfile, GOT_ERR_IO);
		goto done;
	}

	len = strlen(msg);
	SHA1Update(&sha1_ctx, msg, len);
	n = fwrite(msg, 1, len, commitfile);
	if (n != len) {
		err = got_ferror(commitfile, GOT_ERR_IO);
		goto done;
	}

	SHA1Update(&sha1_ctx, "\n", 1);
	n = fwrite("\n", 1, 1, commitfile);
	if (n != 1) {
		err = got_ferror(commitfile, GOT_ERR_IO);
		goto done;
	}

	*id = malloc(sizeof(**id));
	if (*id == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}
	SHA1Final((*id)->sha1, &sha1_ctx);

	if (fflush(commitfile) != 0) {
		err = got_error_from_errno("fflush");
		goto done;
	}
	rewind(commitfile);

	err = create_object_file(*id, commitfile, repo);
done:
	free(msg0);
	free(header);
	free(tree_str);
	free(author_str);
	free(committer_str);
	if (commitfile && fclose(commitfile) != 0 && err == NULL)
		err = got_error_from_errno("fclose");
	if (err) {
		free(*id);
		*id = NULL;
	}
	return err;
}
