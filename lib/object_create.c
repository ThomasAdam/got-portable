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
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
#include "got_sigs.h"

#include "got_lib_sha1.h"
#include "got_lib_deflate.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_lockfile.h"

#include "got_lib_object_create.h"

#include "buf.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

static const struct got_error *
create_object_file(struct got_object_id *id, FILE *content,
    off_t content_len, struct got_repository *repo)
{
	const struct got_error *err = NULL, *unlock_err = NULL;
	char *objpath = NULL, *tmppath = NULL;
	FILE *tmpfile = NULL;
	struct got_lockfile *lf = NULL;
	off_t tmplen = 0;

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

	if (fchmod(fileno(tmpfile), GOT_DEFAULT_FILE_MODE) != 0) {
		err = got_error_from_errno2("fchmod", tmppath);
		goto done;
	}

	err = got_deflate_to_file(&tmplen, content, content_len, tmpfile, NULL);
	if (err)
		goto done;

	err = got_lockfile_lock(&lf, objpath, -1);
	if (err)
		goto done;

	if (rename(tmppath, objpath) != 0) {
		err = got_error_from_errno3("rename", tmppath, objpath);
		goto done;
	}
	free(tmppath);
	tmppath = NULL;
done:
	free(objpath);
	if (tmppath) {
		if (unlink(tmppath) != 0 && err == NULL)
			err = got_error_from_errno2("unlink", tmppath);
		free(tmppath);
	}
	if (tmpfile && fclose(tmpfile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (lf)
		unlock_err = got_lockfile_unlock(lf, -1);
	return err ? err : unlock_err;
}

const struct got_error *
got_object_blob_file_create(struct got_object_id **id, FILE **blobfile,
    off_t *blobsize, const char *ondisk_path)
{
	const struct got_error *err = NULL;
	char *header = NULL;
	int fd = -1;
	struct stat sb;
	SHA1_CTX sha1_ctx;
	size_t headerlen = 0, n;

	*id = NULL;
	*blobfile = NULL;
	*blobsize = 0;

	SHA1Init(&sha1_ctx);

	fd = open(ondisk_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd == -1) {
		if (!got_err_open_nofollow_on_symlink())
			return got_error_from_errno2("open", ondisk_path);

		if (lstat(ondisk_path, &sb) == -1) {
			err = got_error_from_errno2("lstat", ondisk_path);
			goto done;
		}
	} else if (fstat(fd, &sb) == -1) {
		err = got_error_from_errno2("fstat", ondisk_path);
		goto done;
	}

	if (asprintf(&header, "%s %lld", GOT_OBJ_LABEL_BLOB,
		(long long)sb.st_size) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	headerlen = strlen(header) + 1;
	SHA1Update(&sha1_ctx, header, headerlen);

	*blobfile = got_opentemp();
	if (*blobfile == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	n = fwrite(header, 1, headerlen, *blobfile);
	if (n != headerlen) {
		err = got_ferror(*blobfile, GOT_ERR_IO);
		goto done;
	}
	*blobsize += headerlen;
	for (;;) {
		char buf[PATH_MAX * 8];
		ssize_t inlen;

		if (S_ISLNK(sb.st_mode)) {
			inlen = readlink(ondisk_path, buf, sizeof(buf));
			if (inlen == -1) {
				err = got_error_from_errno("readlink");
				goto done;
			}
		} else {
			inlen = read(fd, buf, sizeof(buf));
			if (inlen == -1) {
				err = got_error_from_errno("read");
				goto done;
			}
		}
		if (inlen == 0)
			break; /* EOF */
		SHA1Update(&sha1_ctx, buf, inlen);
		n = fwrite(buf, 1, inlen, *blobfile);
		if (n != inlen) {
			err = got_ferror(*blobfile, GOT_ERR_IO);
			goto done;
		}
		*blobsize += n;
		if (S_ISLNK(sb.st_mode))
			break;
	}

	*id = malloc(sizeof(**id));
	if (*id == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}
	SHA1Final((*id)->sha1, &sha1_ctx);

	if (fflush(*blobfile) != 0) {
		err = got_error_from_errno("fflush");
		goto done;
	}
	rewind(*blobfile);
done:
	free(header);
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (err) {
		free(*id);
		*id = NULL;
		if (*blobfile) {
			fclose(*blobfile);
			*blobfile = NULL;
		}
	}
	return err;
}

const struct got_error *
got_object_blob_create(struct got_object_id **id, const char *ondisk_path,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	FILE *blobfile = NULL;
	off_t blobsize;

	err = got_object_blob_file_create(id, &blobfile, &blobsize,
	    ondisk_path);
	if (err)
		return err;

	err = create_object_file(*id, blobfile, blobsize, repo);
	if (fclose(blobfile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (err) {
		free(*id);
		*id = NULL;
	}
	return err;
}

static const struct got_error *
te_mode2str(char *buf, size_t len, struct got_tree_entry *te)
{
	int ret;
	mode_t mode;

	/*
	 * Some Git implementations are picky about modes seen in tree entries.
	 * For best compatibility we normalize the file/directory mode here.
	 */
	if (S_ISREG(te->mode)) {
		mode = GOT_DEFAULT_FILE_MODE;
		if (te->mode & (S_IXUSR | S_IXGRP | S_IXOTH))
			mode |= S_IXUSR | S_IXGRP | S_IXOTH;
	} else if (got_object_tree_entry_is_submodule(te))
		mode = S_IFDIR | S_IFLNK;
	else if (S_ISLNK(te->mode))
		mode = S_IFLNK; /* Git leaves all the other bits unset. */
	else if (S_ISDIR(te->mode))
		mode = S_IFDIR; /* Git leaves all the other bits unset. */
	else
		return got_error(GOT_ERR_BAD_FILETYPE);

	ret = snprintf(buf, len, "%o ", mode);
	if (ret == -1 || ret >= len)
		return got_error(GOT_ERR_NO_SPACE);
	return NULL;
}

/*
 * Git expects directory tree entries to be sorted with an imaginary slash
 * appended to their name, and will break otherwise. Let's be nice.
 * This function is intended to be used with mergesort(3) to sort an
 * array of pointers to struct got_tree_entry objects.
 */
static int
sort_tree_entries_the_way_git_likes_it(const void *arg1, const void *arg2)
{
	struct got_tree_entry * const *te1 = arg1;
	struct got_tree_entry * const *te2 = arg2;
	char name1[NAME_MAX + 2];
	char name2[NAME_MAX + 2];

	strlcpy(name1, (*te1)->name, sizeof(name1));
	strlcpy(name2, (*te2)->name, sizeof(name2));
	if (S_ISDIR((*te1)->mode))
		strlcat(name1, "/", sizeof(name1));
	if (S_ISDIR((*te2)->mode))
		strlcat(name2, "/", sizeof(name2));
	return strcmp(name1, name2);
}

const struct got_error *
got_object_tree_create(struct got_object_id **id,
    struct got_pathlist_head *paths, int nentries, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char modebuf[sizeof("100644 ")];
	SHA1_CTX sha1_ctx;
	char *header = NULL;
	size_t headerlen, len = 0, n;
	FILE *treefile = NULL;
	off_t treesize = 0;
	struct got_pathlist_entry *pe;
	struct got_tree_entry **sorted_entries;
	struct got_tree_entry *te;
	int i;

	*id = NULL;

	SHA1Init(&sha1_ctx);

	sorted_entries = calloc(nentries, sizeof(struct got_tree_entry *));
	if (sorted_entries == NULL)
		return got_error_from_errno("calloc");

	i = 0;
	TAILQ_FOREACH(pe, paths, entry)
		sorted_entries[i++] = pe->data;
	mergesort(sorted_entries, nentries, sizeof(struct got_tree_entry *),
	    sort_tree_entries_the_way_git_likes_it);

	for (i = 0; i < nentries; i++) {
		te = sorted_entries[i];
		err = te_mode2str(modebuf, sizeof(modebuf), te);
		if (err)
			goto done;
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
	treesize += headerlen;

	for (i = 0; i < nentries; i++) {
		te = sorted_entries[i];
		err = te_mode2str(modebuf, sizeof(modebuf), te);
		if (err)
			goto done;
		len = strlen(modebuf);
		n = fwrite(modebuf, 1, len, treefile);
		if (n != len) {
			err = got_ferror(treefile, GOT_ERR_IO);
			goto done;
		}
		SHA1Update(&sha1_ctx, modebuf, len);
		treesize += n;

		len = strlen(te->name) + 1; /* must include NUL */
		n = fwrite(te->name, 1, len, treefile);
		if (n != len) {
			err = got_ferror(treefile, GOT_ERR_IO);
			goto done;
		}
		SHA1Update(&sha1_ctx, te->name, len);
		treesize += n;

		len = SHA1_DIGEST_LENGTH;
		n = fwrite(te->id.sha1, 1, len, treefile);
		if (n != len) {
			err = got_ferror(treefile, GOT_ERR_IO);
			goto done;
		}
		SHA1Update(&sha1_ctx, te->id.sha1, len);
		treesize += n;
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

	err = create_object_file(*id, treefile, treesize, repo);
done:
	free(header);
	free(sorted_entries);
	if (treefile && fclose(treefile) == EOF && err == NULL)
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
	off_t commitsize = 0;
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
	    GOT_COMMIT_LABEL_AUTHOR, author, (long long)author_time) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (asprintf(&committer_str, "%s%s %lld +0000\n",
	    GOT_COMMIT_LABEL_COMMITTER, committer ? committer : author,
	    (long long)(committer ? committer_time : author_time))
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
	commitsize += headerlen;

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
	commitsize += n;

	if (parent_ids) {
		free(id_str);
		id_str = NULL;
		STAILQ_FOREACH(qid, parent_ids, entry) {
			char *parent_str = NULL;

			err = got_object_id_str(&id_str, &qid->id);
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
			commitsize += n;
			free(parent_str);
			free(id_str);
			id_str = NULL;
		}
	}

	len = strlen(author_str);
	SHA1Update(&sha1_ctx, author_str, len);
	n = fwrite(author_str, 1, len, commitfile);
	if (n != len) {
		err = got_ferror(commitfile, GOT_ERR_IO);
		goto done;
	}
	commitsize += n;

	len = strlen(committer_str);
	SHA1Update(&sha1_ctx, committer_str, len);
	n = fwrite(committer_str, 1, len, commitfile);
	if (n != len) {
		err = got_ferror(commitfile, GOT_ERR_IO);
		goto done;
	}
	commitsize += n;

	SHA1Update(&sha1_ctx, "\n", 1);
	n = fwrite("\n", 1, 1, commitfile);
	if (n != 1) {
		err = got_ferror(commitfile, GOT_ERR_IO);
		goto done;
	}
	commitsize += n;

	len = strlen(msg);
	SHA1Update(&sha1_ctx, msg, len);
	n = fwrite(msg, 1, len, commitfile);
	if (n != len) {
		err = got_ferror(commitfile, GOT_ERR_IO);
		goto done;
	}
	commitsize += n;

	SHA1Update(&sha1_ctx, "\n", 1);
	n = fwrite("\n", 1, 1, commitfile);
	if (n != 1) {
		err = got_ferror(commitfile, GOT_ERR_IO);
		goto done;
	}
	commitsize += n;

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

	err = create_object_file(*id, commitfile, commitsize, repo);
done:
	free(id_str);
	free(msg0);
	free(header);
	free(tree_str);
	free(author_str);
	free(committer_str);
	if (commitfile && fclose(commitfile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (err) {
		free(*id);
		*id = NULL;
	}
	return err;
}

const struct got_error *
got_object_tag_create(struct got_object_id **id,
    const char *tag_name, struct got_object_id *object_id, const char *tagger,
    time_t tagger_time, const char *tagmsg, const char *signer_id,
    struct got_repository *repo, int verbosity)
{
	const struct got_error *err = NULL;
	SHA1_CTX sha1_ctx;
	char *header = NULL;
	char *tag_str = NULL, *tagger_str = NULL;
	char *id_str = NULL, *obj_str = NULL, *type_str = NULL;
	size_t headerlen, len = 0, sig_len = 0, n;
	FILE *tagfile = NULL;
	off_t tagsize = 0;
	char *msg0 = NULL, *msg;
	const char *obj_type_str;
	int obj_type;
	BUF *buf = NULL;

	*id = NULL;

	SHA1Init(&sha1_ctx);

	err = got_object_id_str(&id_str, object_id);
	if (err)
		goto done;
	if (asprintf(&obj_str, "%s%s\n", GOT_TAG_LABEL_OBJECT, id_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_object_get_type(&obj_type, repo, object_id);
	if (err)
		goto done;

	switch (obj_type) {
	case GOT_OBJ_TYPE_BLOB:
		obj_type_str = GOT_OBJ_LABEL_BLOB;
		break;
	case GOT_OBJ_TYPE_TREE:
		obj_type_str = GOT_OBJ_LABEL_TREE;
		break;
	case GOT_OBJ_TYPE_COMMIT:
		obj_type_str = GOT_OBJ_LABEL_COMMIT;
		break;
	case GOT_OBJ_TYPE_TAG:
		obj_type_str = GOT_OBJ_LABEL_TAG;
		break;
	default:
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	if (asprintf(&type_str, "%s%s\n", GOT_TAG_LABEL_TYPE,
	    obj_type_str) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (asprintf(&tag_str, "%s%s\n", GOT_TAG_LABEL_TAG, tag_name) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (asprintf(&tagger_str, "%s%s %lld +0000\n",
	    GOT_TAG_LABEL_TAGGER, tagger, (long long)tagger_time) == -1)
		return got_error_from_errno("asprintf");

	msg0 = strdup(tagmsg);
	if (msg0 == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}
	msg = msg0;

	while (isspace((unsigned char)msg[0]))
		msg++;

	if (signer_id) {
		pid_t pid;
		size_t len;
		int in_fd, out_fd;
		int status;

		err = buf_alloc(&buf, 0);
		if (err)
			goto done;

		/* signed message */
		err = buf_puts(&len, buf, obj_str);
		if (err)
			goto done;
		err = buf_puts(&len, buf, type_str);
		if (err)
			goto done;
		err = buf_puts(&len, buf, tag_str);
		if (err)
			goto done;
		err = buf_puts(&len, buf, tagger_str);
		if (err)
			goto done;
		err = buf_putc(buf, '\n');
		if (err)
			goto done;
		err = buf_puts(&len, buf, msg);
		if (err)
			goto done;
		err = buf_putc(buf, '\n');
		if (err)
			goto done;

		err = got_sigs_sign_tag_ssh(&pid, &in_fd, &out_fd, signer_id,
		    verbosity);
		if (err)
			goto done;
		if (buf_write_fd(buf, in_fd) == -1) {
			err = got_error_from_errno("write");
			goto done;
		}
		if (close(in_fd) == -1) {
			err = got_error_from_errno("close");
			goto done;
		}

		if (waitpid(pid, &status, 0) == -1) {
			err = got_error_from_errno("waitpid");
			goto done;
		}
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			err = got_error(GOT_ERR_SIGNING_TAG);
			goto done;
		}

		buf_empty(buf);
		err = buf_load_fd(&buf, out_fd);
		if (err)
			goto done;
		sig_len = buf_len(buf) + 1;
		err = buf_putc(buf, '\0');
		if (err)
			goto done;
		if (close(out_fd) == -1) {
			err = got_error_from_errno("close");
			goto done;
		}
	}

	len = strlen(obj_str) + strlen(type_str) + strlen(tag_str) +
	    strlen(tagger_str) + 1 + strlen(msg) + 1 + sig_len;
	if (asprintf(&header, "%s %zd", GOT_OBJ_LABEL_TAG, len) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	headerlen = strlen(header) + 1;
	SHA1Update(&sha1_ctx, header, headerlen);

	tagfile = got_opentemp();
	if (tagfile == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	n = fwrite(header, 1, headerlen, tagfile);
	if (n != headerlen) {
		err = got_ferror(tagfile, GOT_ERR_IO);
		goto done;
	}
	tagsize += headerlen;
	len = strlen(obj_str);
	SHA1Update(&sha1_ctx, obj_str, len);
	n = fwrite(obj_str, 1, len, tagfile);
	if (n != len) {
		err = got_ferror(tagfile, GOT_ERR_IO);
		goto done;
	}
	tagsize += n;
	len = strlen(type_str);
	SHA1Update(&sha1_ctx, type_str, len);
	n = fwrite(type_str, 1, len, tagfile);
	if (n != len) {
		err = got_ferror(tagfile, GOT_ERR_IO);
		goto done;
	}
	tagsize += n;

	len = strlen(tag_str);
	SHA1Update(&sha1_ctx, tag_str, len);
	n = fwrite(tag_str, 1, len, tagfile);
	if (n != len) {
		err = got_ferror(tagfile, GOT_ERR_IO);
		goto done;
	}
	tagsize += n;

	len = strlen(tagger_str);
	SHA1Update(&sha1_ctx, tagger_str, len);
	n = fwrite(tagger_str, 1, len, tagfile);
	if (n != len) {
		err = got_ferror(tagfile, GOT_ERR_IO);
		goto done;
	}
	tagsize += n;

	SHA1Update(&sha1_ctx, "\n", 1);
	n = fwrite("\n", 1, 1, tagfile);
	if (n != 1) {
		err = got_ferror(tagfile, GOT_ERR_IO);
		goto done;
	}
	tagsize += n;

	len = strlen(msg);
	SHA1Update(&sha1_ctx, msg, len);
	n = fwrite(msg, 1, len, tagfile);
	if (n != len) {
		err = got_ferror(tagfile, GOT_ERR_IO);
		goto done;
	}
	tagsize += n;

	SHA1Update(&sha1_ctx, "\n", 1);
	n = fwrite("\n", 1, 1, tagfile);
	if (n != 1) {
		err = got_ferror(tagfile, GOT_ERR_IO);
		goto done;
	}
	tagsize += n;

	if (signer_id && buf_len(buf) > 0) {
		len = buf_len(buf);
		SHA1Update(&sha1_ctx, buf_get(buf), len);
		n = fwrite(buf_get(buf), 1, len, tagfile);
		if (n != len) {
			err = got_ferror(tagfile, GOT_ERR_IO);
			goto done;
		}
		tagsize += n;
	}

	*id = malloc(sizeof(**id));
	if (*id == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}
	SHA1Final((*id)->sha1, &sha1_ctx);

	if (fflush(tagfile) != 0) {
		err = got_error_from_errno("fflush");
		goto done;
	}
	rewind(tagfile);

	err = create_object_file(*id, tagfile, tagsize, repo);
done:
	free(msg0);
	free(header);
	free(obj_str);
	free(tagger_str);
	if (buf)
		buf_release(buf);
	if (tagfile && fclose(tagfile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (err) {
		free(*id);
		*id = NULL;
	}
	return err;
}
