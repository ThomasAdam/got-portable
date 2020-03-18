/*
 * Copyright (c) 2018, 2019 Ori Bernstein <ori@eigenstate.org>
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
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syslimits.h>
#include <sys/resource.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sha1.h>
#include <zlib.h>
#include <ctype.h>
#include <limits.h>
#include <imsg.h>
#include <time.h>
#include <uuid.h>

#include "got_error.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_path.h"
#include "got_cancel.h"
#include "got_worktree.h"
#include "got_object.h"

#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_object_create.h"
#include "got_lib_pack.h"
#include "got_lib_sha1.h"
#include "got_lib_privsep.h"
#include "got_lib_object_cache.h"
#include "got_lib_repository.h"

static int
hassuffix(char *base, char *suf)
{
	int nb, ns;

	nb = strlen(base);
	ns = strlen(suf);
	if(ns <= nb && strcmp(base + (nb - ns), suf) == 0)
		return 1;
	return 0;
}

static int
got_make_index_path(char *idxpath, size_t idxpathsz, char *path)
{
	size_t len;

	len = strlen(path);
	if(hassuffix(path, ".pack"))
		len -= strlen(".pack");
	if (strlcpy(idxpath, path, idxpathsz) >= idxpathsz)
		return -1;
	if (strlcpy(idxpath + len, ".idx", idxpathsz - len) >= idxpathsz - len)
		return -1;
	return 0;
}

const struct got_error*
got_index_pack(char *path)
{
	int packfd, idxfd;
	char idxpath[PATH_MAX];

	got_make_index_path(idxpath, sizeof(idxpath), path);
	printf("index path %s\n", idxpath);
	if ((fd = open(path)) == -1)
		return got_error_from_errno("open pack");

	pid = fork();
	if (pid == -1)
		return got_error_from_errno("fork");
	else if (pid == 0)
		got_privsep_exec_child(imsg_fds, GOT_PATH_PROG_INDEX_PACK, ".");

	if (close(imsg_fds[1]) != 0)
		return got_error_from_errno("close");
	err = got_privsep_send_index_pack_req(&ibuf, fetchfd);
	if (err != NULL)
		return err;
}
