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

#include <sys/types.h>
#include <sha1.h>
#include <sha2.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "got_compat.h"

#include "got_lib_sha1.h"

int
got_parse_xdigit(uint8_t *val, const char *hex)
{
	char *ep;
	long lval;

	errno = 0;
	lval = strtol(hex, &ep, 16);
	if (hex[0] == '\0' || *ep != '\0')
		return 0;
	if (errno == ERANGE && (lval == LONG_MAX || lval == LONG_MIN))
		return 0;

	*val = (uint8_t)lval;
	return 1;
}

int
got_parse_sha1_digest(uint8_t *digest, const char *line)
{
	uint8_t b = 0;
	char hex[3] = {'\0', '\0', '\0'};
	int i, j;

	for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
		if (line[0] == '\0' || line[1] == '\0')
			return 0;
		for (j = 0; j < 2; j++) {
			hex[j] = *line;
			line++;
		}
		if (!got_parse_xdigit(&b, hex))
			return 0;
		digest[i] = b;
	}

	return 1;
}

char *
got_sha1_digest_to_str(const uint8_t *digest, char *buf, size_t size)
{
	char *p = buf;
	char hex[3];
	int i;

	if (size < SHA1_DIGEST_STRING_LENGTH)
		return NULL;

	for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
		snprintf(hex, sizeof(hex), "%.2x", digest[i]);
		p[0] = hex[0];
		p[1] = hex[1];
		p += 2;
	}
	p[0] = '\0';

	return buf;
}
