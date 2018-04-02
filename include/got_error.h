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

/* Error codes */
#define GOT_ERR_OK		0
#define GOT_ERR_ERRNO		1
#define GOT_ERR_NOT_GIT_REPO	2
#define GOT_ERR_NOT_ABSPATH	3
#define GOT_ERR_BAD_PATH	4
#define GOT_ERR_NOT_REF		5
#define GOT_ERR_IO		6
#define GOT_ERR_EOF		7
#define GOT_ERR_DECOMPRESSION	8
#define GOT_ERR_NO_SPACE	9
#define GOT_ERR_BAD_OBJ_HDR	10
#define GOT_ERR_OBJ_TYPE	11
#define GOT_ERR_BAD_OBJ_DATA	12
#define GOT_ERR_FILE_OPEN	13
#define GOT_ERR_BAD_PACKIDX	14
#define GOT_ERR_PACKIDX_CSUM	15
#define GOT_ERR_BAD_PACKFILE	16
#define GOT_ERR_NO_OBJ		17
#define GOT_ERR_NOT_IMPL	18
#define GOT_ERR_OBJ_NOT_PACKED	19
#define GOT_ERR_BAD_DELTA_CHAIN	20
#define GOT_ERR_BAD_DELTA	21
#define GOT_ERR_COMPRESSION	22
#define GOT_ERR_BAD_OBJ_ID_STR	23
#define GOT_ERR_WORKTREE_EXISTS	26
#define GOT_ERR_WORKTREE_META	27
#define GOT_ERR_WORKTREE_VERS	28
#define GOT_ERR_WORKTREE_BUSY	29
#define GOT_ERR_DIR_OBSTRUCTED	30
#define GOT_ERR_FILE_OBSTRUCTED	31

static const struct got_error {
	int code;
	const char *msg;
} got_errors[] = {
	{ GOT_ERR_OK,		"no error occured?!?" },
	{ GOT_ERR_ERRNO,	"see errno" },
	{ GOT_ERR_NOT_GIT_REPO, "no git repository found" },
	{ GOT_ERR_NOT_ABSPATH,	"absolute path expected" },
	{ GOT_ERR_BAD_PATH,	"bad path" },
	{ GOT_ERR_NOT_REF,	"no such reference found" },
	{ GOT_ERR_IO,		"input/output error" },
	{ GOT_ERR_EOF,		"unexpected end of file" },
	{ GOT_ERR_DECOMPRESSION,"decompression failed" },
	{ GOT_ERR_NO_SPACE,	"buffer too small" },
	{ GOT_ERR_BAD_OBJ_HDR,	"bad object header" },
	{ GOT_ERR_OBJ_TYPE,	"wrong type of object" },
	{ GOT_ERR_BAD_OBJ_DATA,	"bad object data" },
	{ GOT_ERR_FILE_OPEN,	"could not open file" },
	{ GOT_ERR_BAD_PACKIDX,	"bad pack index file" },
	{ GOT_ERR_PACKIDX_CSUM, "pack index file checksum error" },
	{ GOT_ERR_BAD_PACKFILE,	"bad pack file" },
	{ GOT_ERR_NO_OBJ,	"object not found" },
	{ GOT_ERR_NOT_IMPL,	"feature not implemented" },
	{ GOT_ERR_OBJ_NOT_PACKED,"object is not packed" },
	{ GOT_ERR_BAD_DELTA_CHAIN,"bad delta chain" },
	{ GOT_ERR_BAD_DELTA,	"bad delta" },
	{ GOT_ERR_COMPRESSION,	"compression failed" },
	{ GOT_ERR_BAD_OBJ_ID_STR,"bad object id string" },
	{ GOT_ERR_WORKTREE_EXISTS,"worktree already exists" },
	{ GOT_ERR_WORKTREE_META,"bad worktree meta data" },
	{ GOT_ERR_WORKTREE_VERS,"unsupported worktree format version" },
	{ GOT_ERR_WORKTREE_BUSY,"worktree already locked" },
};

/*
 * Get an error object from the above list, for a given error code.
 * The error message is fixed.
 */
const struct got_error *got_error(int);

/*
 * Get a statically allocated error object with code GOT_ERR_ERRNO
 * and an error message obtained from strerror(3).
 */
const struct got_error *got_error_from_errno(void);

/*
 * If ferror(3) indicates an error status for the FILE, obtain an error
 * from got_error_from_errno(). Else, obtain the error via got_error()
 * with the error code provided in the second argument.
 */
const struct got_error *got_ferror(FILE *, int);
