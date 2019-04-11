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

#include "got_lib_sha1.h"
#include "got_lib_deflate.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_lockfile.h"
#include "got_lib_path.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

const struct got_error *
got_object_blob_create(struct got_object_id **id, struct got_repository *repo,
    const char *ondisk_path)
{
	const struct got_error *err = NULL, *unlock_err = NULL;
	char *header = NULL, *blobpath = NULL, *objpath = NULL, *outpath = NULL;
	FILE *blobfile = NULL, *outfile = NULL;
	int fd = -1;
	struct stat sb;
	SHA1_CTX sha1_ctx;
	uint8_t digest[SHA1_DIGEST_LENGTH];
	struct got_lockfile *lf = NULL;
	size_t outlen = 0;

	*id = NULL;

	SHA1Init(&sha1_ctx);

	fd = open(ondisk_path, O_RDONLY | O_NOFOLLOW);
	if (fd == -1)
		return got_error_from_errno();

	if (fstat(fd, &sb) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	if (asprintf(&header, "%s %lld", GOT_OBJ_LABEL_BLOB,
		sb.st_size) == -1) {
		err = got_error_from_errno();
		goto done;
	}
	SHA1Update(&sha1_ctx, header, strlen(header) + 1);

	err = got_opentemp_named(&blobpath, &blobfile, "/tmp/got-blob-create");
	if (err)
		goto done;

	while (1) {
		char buf[8192];
		ssize_t inlen;
		size_t outlen;

		inlen = read(fd, buf, sizeof(buf));
		if (inlen == -1) {
			err = got_error_from_errno();
			goto done;
		}
		if (inlen == 0)
			break; /* EOF */
		SHA1Update(&sha1_ctx, buf, inlen);
		outlen = fwrite(buf, 1, inlen, blobfile);
		if (outlen != inlen) {
			err = got_ferror(blobfile, GOT_ERR_IO);
			goto done;
		}
	}

	SHA1Final(digest, &sha1_ctx);
	*id = malloc(sizeof(**id));
	if (*id == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	memcpy((*id)->sha1, digest, SHA1_DIGEST_LENGTH);

	if (fflush(blobfile) != 0) {
		err = got_error_from_errno();
		goto done;
	}
	rewind(blobfile);

	err = got_object_get_path(&objpath, *id, repo);
	if (err)
		goto done;

	err = got_opentemp_named(&outpath, &outfile, objpath);
	if (err)
		goto done;

	err = got_deflate_to_file(&outlen, blobfile, outfile);
	if (err)
		goto done;

	err = got_lockfile_lock(&lf, objpath);
	if (err)
		goto done;

	if (rename(outpath, objpath) != 0) {
		err = got_error_from_errno();
		goto done;
	}
	free(outpath);
	outpath = NULL;

	if (chmod(objpath, GOT_DEFAULT_FILE_MODE) != 0) {
		err = got_error_from_errno();
		goto done;
	}
done:
	free(header);
	free(blobpath);
	if (outpath) {
		if (unlink(outpath) != 0 && err == NULL)
			err = got_error_from_errno();
		free(outpath);
	}
	if (fd != -1 && close(fd) != 0 && err == NULL)
		err = got_error_from_errno();
	if (blobfile && fclose(blobfile) != 0 && err == NULL)
		err = got_error_from_errno();
	if (outfile && fclose(outfile) != 0 && err == NULL)
		err = got_error_from_errno();
	if (err) {
		free(*id);
		*id = NULL;
	}
	if (lf)
		unlock_err = got_lockfile_unlock(lf);
	return err ? err : unlock_err;
}
