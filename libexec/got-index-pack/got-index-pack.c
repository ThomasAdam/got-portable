/*
 * Copyright (c) 2019 Ori Bernstein <ori@openbsd.org>
 * Copyright (c) 2020 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/queue.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include <sha1.h>
#include <sha2.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <imsg.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"

#include "got_lib_delta.h"
#include "got_lib_delta_cache.h"
#include "got_lib_hash.h"
#include "got_lib_object.h"
#include "got_lib_object_qid.h"
#include "got_lib_privsep.h"
#include "got_lib_ratelimit.h"
#include "got_lib_pack.h"
#include "got_lib_pack_index.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static const struct got_error *
send_index_pack_progress(void *arg, uint32_t nobj_total, uint32_t nobj_indexed,
    uint32_t nobj_loose, uint32_t nobj_resolved)
{
	struct imsgbuf *ibuf = arg;
	struct got_imsg_index_pack_progress iprogress;

	iprogress.nobj_total = nobj_total;
	iprogress.nobj_indexed = nobj_indexed;
	iprogress.nobj_loose = nobj_loose;
	iprogress.nobj_resolved = nobj_resolved;

	if (imsg_compose(ibuf, GOT_IMSG_IDXPACK_PROGRESS, 0, 0, -1,
	    &iprogress, sizeof(iprogress)) == -1)
		return got_error_from_errno("imsg_compose IDXPACK_PROGRESS");

	return got_privsep_flush_imsg(ibuf);
}

static const struct got_error *
send_index_pack_done(struct imsgbuf *ibuf)
{
	if (imsg_compose(ibuf, GOT_IMSG_IDXPACK_DONE, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose FETCH");
	return got_privsep_flush_imsg(ibuf);
}


int
main(int argc, char **argv)
{
	const struct got_error *err = NULL, *close_err;
	struct imsgbuf ibuf;
	struct imsg imsg;
	size_t i;
	int idxfd = -1, tmpfd = -1;
	FILE *tmpfiles[3];
	struct got_pack pack;
	uint8_t pack_hash[SHA1_DIGEST_LENGTH];
	off_t packfile_size;
	struct got_ratelimit rl;
#if 0
	static int attached;
	while (!attached)
		sleep(1);
#endif

	got_ratelimit_init(&rl, 0, 500);

	for (i = 0; i < nitems(tmpfiles); i++)
		tmpfiles[i] = NULL;

	memset(&pack, 0, sizeof(pack));
	pack.fd = -1;
	err = got_delta_cache_alloc(&pack.delta_cache);
	if (err)
		goto done;

	imsg_init(&ibuf, GOT_IMSG_FD_CHILD);
#ifndef PROFILE
	/* revoke access to most system calls */
	if (pledge("stdio recvfd", NULL) == -1) {
		err = got_error_from_errno("pledge");
		got_privsep_send_error(&ibuf, err);
		return 1;
	}
#endif
	err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
	if (err)
		goto done;
	if (imsg.hdr.type == GOT_IMSG_STOP)
		goto done;
	if (imsg.hdr.type != GOT_IMSG_IDXPACK_REQUEST) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}
	if (imsg.hdr.len - IMSG_HEADER_SIZE != sizeof(pack_hash)) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	memcpy(pack_hash, imsg.data, sizeof(pack_hash));
	pack.fd = imsg.fd;

	err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
	if (err)
		goto done;
	if (imsg.hdr.type == GOT_IMSG_STOP)
		goto done;
	if (imsg.hdr.type != GOT_IMSG_IDXPACK_OUTFD) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}
	if (imsg.hdr.len - IMSG_HEADER_SIZE != 0) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	idxfd = imsg.fd;

	for (i = 0; i < nitems(tmpfiles); i++) {
		err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
		if (err)
			goto done;
		if (imsg.hdr.type == GOT_IMSG_STOP)
			goto done;
		if (imsg.hdr.type != GOT_IMSG_TMPFD) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			goto done;
		}
		if (imsg.hdr.len - IMSG_HEADER_SIZE != 0) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
		tmpfd = imsg.fd;
		tmpfiles[i] = fdopen(tmpfd, "w+");
		if (tmpfiles[i] == NULL) {
			err = got_error_from_errno("fdopen");
			goto done;
		}
		tmpfd = -1;
	}

	if (lseek(pack.fd, 0, SEEK_END) == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}
	packfile_size = lseek(pack.fd, 0, SEEK_CUR);
	if (packfile_size == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}
	pack.filesize = packfile_size;

	if (lseek(pack.fd, 0, SEEK_SET) == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}

#ifndef GOT_PACK_NO_MMAP
	if (pack.filesize > 0 && pack.filesize <= SIZE_MAX) {
		pack.map = mmap(NULL, pack.filesize, PROT_READ, MAP_PRIVATE,
		    pack.fd, 0);
		if (pack.map == MAP_FAILED)
			pack.map = NULL; /* fall back to read(2) */
	}
#endif
	err = got_pack_index(&pack, idxfd, tmpfiles[0], tmpfiles[1],
	    tmpfiles[2], pack_hash, send_index_pack_progress, &ibuf, &rl);
done:
	close_err = got_pack_close(&pack);
	if (close_err && err == NULL)
		err = close_err;
	if (idxfd != -1 && close(idxfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (tmpfd != -1 && close(tmpfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	for (i = 0; i < nitems(tmpfiles); i++) {
		if (tmpfiles[i] != NULL && fclose(tmpfiles[i]) == EOF &&
		    err == NULL)
			err = got_error_from_errno("fclose");
	}

	if (err == NULL)
		err = send_index_pack_done(&ibuf);
	if (err) {
		got_privsep_send_error(&ibuf, err);
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
		got_privsep_send_error(&ibuf, err);
		exit(1);
	}

	exit(0);
}
