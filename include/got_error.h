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

/* Error codes */
#define GOT_ERR_UNKNOWN		0x0000
#define GOT_ERR_NO_MEM		0x0001
#define GOT_ERR_NOT_GIT_REPO	0x0002
#define GOT_ERR_NOT_ABSPATH	0x0003
#define GOT_ERR_BAD_PATH	0x0004
#define GOT_ERR_NOT_REF		0x0005

static const struct got_error {
	int code;
	const char *msg;
} got_errors[] = {
	{ GOT_ERR_UNKNOWN,	"unknown error" },
	{ GOT_ERR_NO_MEM,	"out of memory" },
	{ GOT_ERR_NOT_GIT_REPO, "no git repository found" },
	{ GOT_ERR_NOT_ABSPATH,	"absolute path expected" },
	{ GOT_ERR_BAD_PATH,	"bad path" },
	{ GOT_ERR_NOT_REF,	"no such reference found" },
};

const struct got_error * got_error(int code);
