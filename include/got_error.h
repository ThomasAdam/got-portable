/*
 * Copyright (c) 2018, 2019 Stefan Sperling <stsp@openbsd.org>
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
/* 13 is currently free for re-use */
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
#define GOT_ERR_RECURSION	32
#define GOT_ERR_TIMEOUT		33
#define GOT_ERR_INTERRUPT	34
#define GOT_ERR_PRIVSEP_READ	35
#define GOT_ERR_PRIVSEP_LEN	36
#define GOT_ERR_PRIVSEP_PIPE	37
#define GOT_ERR_PRIVSEP_NO_FD	38
#define GOT_ERR_PRIVSEP_MSG	39
#define GOT_ERR_PRIVSEP_DIED	40
#define GOT_ERR_PRIVSEP_EXIT	41
#define GOT_ERR_PACK_OFFSET	42
#define GOT_ERR_OBJ_EXISTS	43
#define GOT_ERR_BAD_OBJ_ID	44
#define GOT_ERR_ITER_NEED_MORE	45
#define GOT_ERR_ITER_COMPLETED	46
#define GOT_ERR_RANGE		47
#define GOT_ERR_EXPECTED	48 /* for use in regress tests only */
#define GOT_ERR_CANCELLED	49
#define GOT_ERR_NO_TREE_ENTRY	50
#define GOT_ERR_FILEIDX_SIG	51
#define GOT_ERR_FILEIDX_VER	52
#define GOT_ERR_FILEIDX_CSUM	53
#define GOT_ERR_PATH_PREFIX	54
#define GOT_ERR_ANCESTRY	55
#define GOT_ERR_FILEIDX_BAD	56
#define GOT_ERR_BAD_REF_DATA	57
#define GOT_ERR_TREE_DUP_ENTRY	58
#define GOT_ERR_DIR_DUP_ENTRY	59
#define GOT_ERR_NOT_WORKTREE	60
#define GOT_ERR_UUID_VERSION	61
#define GOT_ERR_UUID_INVALID	62
#define GOT_ERR_UUID		63
#define GOT_ERR_LOCKFILE_TIMEOUT 64
#define GOT_ERR_BAD_REF_NAME	65
#define GOT_ERR_WORKTREE_REPO	66
#define GOT_ERR_FILE_MODIFIED	67
#define GOT_ERR_FILE_STATUS	68
#define GOT_ERR_COMMIT_CONFLICT	69
#define GOT_ERR_BAD_REF_TYPE	70

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
	{ 13,			"unused error code" },
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
	{ GOT_ERR_FILE_OBSTRUCTED,"file is obstructed" },
	{ GOT_ERR_RECURSION,	"recursion limit reached" },
	{ GOT_ERR_TIMEOUT,	"operation timed out" },
	{ GOT_ERR_INTERRUPT,	"operation interrupted" },
	{ GOT_ERR_PRIVSEP_READ,	"no data received in imsg" },
	{ GOT_ERR_PRIVSEP_LEN,	"unexpected amount of data received in imsg" },
	{ GOT_ERR_PRIVSEP_PIPE,	"privsep peer process closed pipe" },
	{ GOT_ERR_PRIVSEP_NO_FD,"privsep file descriptor unavailable" },
	{ GOT_ERR_PRIVSEP_MSG,	"received unexpected privsep message" },
	{ GOT_ERR_PRIVSEP_DIED,	"unprivileged process died unexpectedly" },
	{ GOT_ERR_PRIVSEP_EXIT,	"bad exit code from unprivileged process" },
	{ GOT_ERR_PACK_OFFSET,	"bad offset in pack file" },
	{ GOT_ERR_OBJ_EXISTS,	"object already exists" },
	{ GOT_ERR_BAD_OBJ_ID,	"bad object id" },
	{ GOT_ERR_ITER_NEED_MORE,"more items needed to continue iteration" },
	{ GOT_ERR_ITER_COMPLETED,"iteration completed" },
	{ GOT_ERR_RANGE,	"value out of range" },
	{ GOT_ERR_EXPECTED,	"expected an error but have no error" },
	{ GOT_ERR_CANCELLED,	"operation in progress has been cancelled" },
	{ GOT_ERR_NO_TREE_ENTRY,"no such entry found in tree" },
	{ GOT_ERR_FILEIDX_SIG,	"bad file index signature" },
	{ GOT_ERR_FILEIDX_VER,	"unknown file index format version" },
	{ GOT_ERR_FILEIDX_CSUM,	"bad file index checksum" },
	{ GOT_ERR_PATH_PREFIX,	"worktree already contains items from a "
				"different path prefix" },
	{ GOT_ERR_ANCESTRY,	"specified commit does not share ancestry with "
				"the current branch" },
	{ GOT_ERR_FILEIDX_BAD,	"file index is corrupt" },
	{ GOT_ERR_BAD_REF_DATA,	"could not parse reference data" },
	{ GOT_ERR_TREE_DUP_ENTRY,"duplicate entry in tree object" },
	{ GOT_ERR_DIR_DUP_ENTRY,"duplicate entry in directory" },
	{ GOT_ERR_NOT_WORKTREE, "no got work tree found" },
	{ GOT_ERR_UUID_VERSION, "bad uuid version" },
	{ GOT_ERR_UUID_INVALID, "uuid invalid" },
	{ GOT_ERR_UUID,		"uuid error" },
	{ GOT_ERR_LOCKFILE_TIMEOUT,"lockfile timeout" },
	{ GOT_ERR_BAD_REF_NAME,	"bad reference name" },
	{ GOT_ERR_WORKTREE_REPO,"cannot create worktree inside a git repository" },
	{ GOT_ERR_FILE_MODIFIED,"file contains modifications" },
	{ GOT_ERR_FILE_STATUS,	"file has unexpected status" },
	{ GOT_ERR_COMMIT_CONFLICT,"cannot commit file in conflicted status" },
	{ GOT_ERR_BAD_REF_TYPE,	"bad reference type" },
};

/*
 * Get an error object from the above list, for a given error code.
 * The error message is fixed.
 */
const struct got_error *got_error(int);

/*
 * Get an error object from the above list, for a given error code.
 * Use the specified error message instead of the default one.
 * Caution: If the message buffer lives in dynamically allocated memory,
 * then this memory likely won't be freed.
 */
const struct got_error *got_error_msg(int, const char *);

/*
 * Get a statically allocated error object with code GOT_ERR_ERRNO
 * and an error message obtained from strerror(3).
 */
const struct got_error *got_error_from_errno(void);

/*
 * Set errno to the specified error code and return a statically
 * allocated error object with code GOT_ERR_ERRNO and an error
 * message obtained from strerror(3).
 */
const struct got_error *got_error_set_errno(int);

/*
 * If ferror(3) indicates an error status for the FILE, obtain an error
 * from got_error_from_errno(). Else, obtain the error via got_error()
 * with the error code provided in the second argument.
 */
const struct got_error *got_ferror(FILE *, int);

/*
 * Obtain an error with code GOT_ERR_NO_OBJ and an error message which
 * contains the specified object ID. The message buffer is statically
 * allocated; future invocations of this function will overwrite the
 * message set during earlier invocations.
 */
struct got_object_id; /* forward declaration */
const struct got_error *got_error_no_obj(struct got_object_id *);

/*
 * Obtain an error with code GOT_ERR_NOT_REF and an error message which
 * contains the specified reference name. The message buffer is statically
 * allocated; future invocations of this function will overwrite the
 * message set during earlier invocations.
 */
const struct got_error *got_error_not_ref(const char *);

/* Return an error based on a uuid(3) status code. */
const struct got_error *got_error_uuid(uint32_t);
