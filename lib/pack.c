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

#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sha1.h>
#include <endian.h>

#include "got_error.h"
#include "pack.h"

static const struct got_error *
verify_fanout_table(uint32_t *fanout_table)
{
	int i;

	for (i = 0; i < 0xff - 1; i++) {
		if (fanout_table[i] > fanout_table[i + 1])
			return got_error(GOT_ERR_BAD_PACKIDX);
	}

	return NULL;
}

const struct got_error *
get_packfile_size(size_t *size, const char *path_idx)
{
	struct stat sb;
	char *path_pack;
	char base_path[PATH_MAX];
	char *dot;

	if (strlcpy(base_path, path_idx, PATH_MAX) > PATH_MAX)
		return got_error(GOT_ERR_NO_SPACE);

	dot = strrchr(base_path, '.');
	if (dot == NULL)
		return got_error(GOT_ERR_BAD_PATH);
	*dot = '\0';
	if (asprintf(&path_pack, "%s.pack", base_path) == -1)
		return got_error(GOT_ERR_NO_MEM);

	if (stat(path_pack, &sb) != 0) {
		free(path_pack);
		return got_error(GOT_ERR_IO);

	}

	free(path_pack);
	*size = sb.st_size;
	return 0;
}

const struct got_error *
got_packidx_open(struct got_packidx_v2_hdr **packidx, const char *path)
{
	struct got_packidx_v2_hdr *p;
	FILE *f;
	const struct got_error *err = NULL;
	size_t n, nobj, packfile_size;
	SHA1_CTX ctx;
	uint8_t sha1[SHA1_DIGEST_LENGTH];

	SHA1Init(&ctx);

	f = fopen(path, "rb");
	if (f == NULL)
		return got_error(GOT_ERR_BAD_PATH);

	err = get_packfile_size(&packfile_size, path);
	if (err)
		return err;

	p = calloc(1, sizeof(*p));
	if (p == NULL) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}

	n = fread(&p->magic, sizeof(p->magic), 1, f);
	if (n != 1) {
		err = got_error(ferror(f) ? GOT_ERR_IO : GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	if (betoh32(p->magic) != GOT_PACKIDX_V2_MAGIC) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t *)&p->magic, sizeof(p->magic));

	n = fread(&p->version, sizeof(p->version), 1, f);
	if (n != 1) {
		err = got_error(ferror(f) ? GOT_ERR_IO : GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	if (betoh32(p->version) != GOT_PACKIDX_VERSION) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t *)&p->version, sizeof(p->version));

	n = fread(&p->fanout_table, sizeof(p->fanout_table), 1, f);
	if (n != 1) {
		err = got_error(ferror(f) ? GOT_ERR_IO : GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	err = verify_fanout_table(p->fanout_table);
	if (err)
		goto done;

	SHA1Update(&ctx, (uint8_t *)p->fanout_table, sizeof(p->fanout_table));

	nobj = betoh32(p->fanout_table[0xff]);

	p->sorted_ids = calloc(nobj, sizeof(*p->sorted_ids));
	if (p->sorted_ids == NULL) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}

	n = fread(p->sorted_ids, sizeof(*p->sorted_ids), nobj, f);
	if (n != nobj) {
		err = got_error(ferror(f) ? GOT_ERR_IO : GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t *)p->sorted_ids,
	    nobj * sizeof(*p->sorted_ids));

	p->offsets = calloc(nobj, sizeof(*p->offsets));
	if (p->offsets == NULL) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}

	n = fread(p->offsets, sizeof(*p->offsets), nobj, f);
	if (n != nobj) {
		err = got_error(ferror(f) ? GOT_ERR_IO : GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t *)p->offsets, nobj * sizeof(*p->offsets));

	p->crc32 = calloc(nobj, sizeof(*p->crc32));
	if (p->crc32 == NULL) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}

	n = fread(p->crc32, sizeof(*p->crc32), nobj, f);
	if (n != nobj) {
		err = got_error(ferror(f) ? GOT_ERR_IO : GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t *)p->crc32, nobj * sizeof(*p->crc32));

	/* Large file offsets are contained only in files > 2GB. */
	if (packfile_size <= 0x80000000)
		goto checksum;

	p->large_offsets = calloc(nobj, sizeof(*p->large_offsets));
	if (p->large_offsets == NULL) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}

	n = fread(p->large_offsets, sizeof(*p->large_offsets), nobj, f);
	if (n != nobj) {
		err = got_error(ferror(f) ? GOT_ERR_IO : GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t*)p->large_offsets,
	    nobj * sizeof(*p->large_offsets));

checksum:
	n = fread(&p->trailer, sizeof(p->trailer), 1, f);
	if (n != 1) {
		err = got_error(ferror(f) ? GOT_ERR_IO : GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, p->trailer.pack_file_sha1, SHA1_DIGEST_LENGTH);
	SHA1Final(sha1, &ctx);
	if (memcmp(p->trailer.pack_idx_sha1, sha1, SHA1_DIGEST_LENGTH) != 0)
		err = got_error(GOT_ERR_PACKIDX_CSUM);
done:
	fclose(f);
	if (err)
		got_packidx_close(p);
	else
		*packidx = p;
	return err;
}

void
got_packidx_close(struct got_packidx_v2_hdr *packidx)
{
	free(packidx->sorted_ids);
	free(packidx->offsets);
	free(packidx->crc32);
	free(packidx->large_offsets);
	free(packidx);
}
