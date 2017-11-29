/*
 * Copyright (c) 2017 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <zlib.h>

#include "got_repository.h"
#include "got_object.h"
#include "got_error.h"

#include "diff.h"

static const struct got_error *
open_tempfile(FILE **sfp, char **sfn)
{
	static const int sfnlen = 20;
	int fd;

	*sfn = calloc(sfnlen, sizeof(char));
	if (*sfn == NULL)
		return got_error(GOT_ERR_NO_MEM);
	strlcpy(*sfn, "/tmp/got.XXXXXXXXXX", sfnlen);
	if ((fd = mkstemp(*sfn)) == -1 ||
	    ((*sfp) = fdopen(fd, "w+")) == NULL) {
		if (fd != -1) {
			unlink(*sfn);
			close(fd);
		}
		free(*sfn);
		return got_error(GOT_ERR_FILE_OPEN);
	}
	return NULL;
}

const struct got_error *
got_diff_blob(struct got_blob_object *blob1, struct got_blob_object *blob2,
    FILE *outfile)
{
	struct got_diff_state ds;
	struct got_diff_args args;
	const struct got_error *err = NULL;
	FILE *f1, *f2;
	char *n1, *n2;
	size_t len, hdrlen;
	int res;

	err = open_tempfile(&f1, &n1);
	if (err != NULL)
		return err;

	err = open_tempfile(&f2, &n2);
	if (err != NULL) {
		fclose(f1);
		free(n1);
		return err;
	}


	hdrlen = blob1->hdrlen;
	do {
		err = got_object_blob_read_block(blob1, &len);
		if (err)
			goto done;
		/* Skip blob object header first time around. */
		fwrite(blob1->zb.outbuf + hdrlen, len - hdrlen, 1, f1);
		hdrlen = 0;
	} while (len != 0);

	hdrlen = blob2->hdrlen;
	do {
		err = got_object_blob_read_block(blob2, &len);
		if (err)
			goto done;
		/* Skip blob object header first time around. */
		fwrite(blob2->zb.outbuf + hdrlen, len - hdrlen, 1, f2);
		hdrlen = 0;
	} while (len != 0);

	fflush(f1);
	fflush(f2);

	memset(&ds, 0, sizeof(ds));
	memset(&args, 0, sizeof(args));

	args.diff_format = D_UNIFIED;
	err = got_diffreg(&res, n1, n2, 0, &args, &ds);
done:
	unlink(n1);
	unlink(n2);
	fclose(f1);
	fclose(f2);
	free(n1);
	free(n2);
	return err;
}
