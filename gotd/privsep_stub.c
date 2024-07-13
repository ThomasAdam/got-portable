/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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

#include "got_compat.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <imsg.h>
#include <limits.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"

#include "got_lib_delta.h"
#include "got_lib_hash.h"
#include "got_lib_object.h"
#include "got_lib_object_cache.h"
#include "got_lib_pack.h"
#include "got_lib_repository.h"
#include "got_lib_privsep.h"

const struct got_error *
got_privsep_send_stop(int fd)
{
	return got_error(GOT_ERR_NOT_IMPL);
}

const struct got_error *
got_privsep_wait_for_child(pid_t pid)
{
	return got_error(GOT_ERR_NOT_IMPL);
}

void
got_privsep_exec_child(int imsg_fds[2], const char *path, const char *repo_path)
{
	fprintf(stderr, "%s: cannot run libexec helpers\n", getprogname());
	exit(1);
}

const struct got_error *
got_privsep_init_pack_child(struct imsgbuf *ibuf, struct got_pack *pack,
    struct got_packidx *packidx)
{
	return got_error(GOT_ERR_NOT_IMPL);
}

const struct got_error *
got_traverse_packed_commits(struct got_object_id_queue *traversed_commits,
    struct got_object_id *commit_id, const char *path,
    struct got_repository *repo)
{
	return NULL;
}
