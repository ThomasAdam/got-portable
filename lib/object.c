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

#include <stdio.h>
#include <sha1.h>

#include "got_object.h"

const char *
got_object_id_str(struct got_object_id *id, char *buf, size_t size)
{
	char *p = buf;
	char hex[3];
	int i;

	if (size < SHA1_DIGEST_STRING_LENGTH)
		return NULL;

	for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
		snprintf(hex, sizeof(hex), "%.2x", id->sha1[i]);
		p[0] = hex[0];
		p[1] = hex[1];
		p += 2;
	}
	p[0] = '\0';

	return buf;
}
