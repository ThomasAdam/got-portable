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

#include <sys/queue.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <zlib.h>

#include "got_error.h"
#include "got_object.h"

#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_sha1.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

const struct got_error *
got_error(int code)
{
	int i;

	for (i = 0; i < nitems(got_errors); i++) {
		if (code == got_errors[i].code)
			return &got_errors[i];
	}

	abort();
}

const struct got_error *
got_error_msg(int code, const char *msg)
{
	static struct got_error err;
	int i;

	for (i = 0; i < nitems(got_errors); i++) {
		if (code == got_errors[i].code) {
			err.code = code;
			err.msg = msg;
			return (const struct got_error *)&err;
		}
	}

	abort();
}

const struct got_error *
got_error_from_errno()
{
	static struct got_error err;

	err.code = GOT_ERR_ERRNO;
	err.msg = strerror(errno);
	return &err;
}

const struct got_error *
got_error_set_errno(int code)
{
	errno = code;
	return got_error_from_errno();
}

const struct got_error *
got_ferror(FILE *f, int code)
{
	if (ferror(f))
		return got_error_from_errno();
	return got_error(code);
}

const struct got_error *
got_error_no_obj(struct got_object_id *id)
{
	static char msg[sizeof("object   not found") +
	    SHA1_DIGEST_STRING_LENGTH];
	char id_str[SHA1_DIGEST_STRING_LENGTH];
	int ret;

	if (!got_sha1_digest_to_str(id->sha1, id_str, sizeof(id_str)))
		return got_error(GOT_ERR_NO_OBJ);

	ret = snprintf(msg, sizeof(msg), "object %s not found", id_str);
	if (ret == -1 || ret >= sizeof(msg))
		return got_error(GOT_ERR_NO_OBJ);

	return got_error_msg(GOT_ERR_NO_OBJ, msg);
}
