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

#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/mman.h>

#include <stdint.h>
#include <errno.h>
#include <imsg.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sha1.h>
#include <endian.h>
#include <fcntl.h>
#include <unistd.h>
#include <zlib.h>
#include <err.h>
#include <assert.h>
#include <dirent.h>

#include "got_error.h"
#include "got_object.h"

#include "got_lib_sha1.h"
#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_object_idset.h"
#include "got_lib_privsep.h"
#include "got_lib_pack.h"
#include "got_lib_delta_cache.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct got_indexed_object {
	struct got_object_id id;

	/*
	 * Has this object been fully resolved?
	 * If so, we know its ID, otherwise we don't and 'id' is invalid.
	 */
	int valid;

	/* Offset of type+size field for this object in pack file. */
	off_t off;

	/* Type+size values parsed from pack file. */
	uint8_t type;
	uint64_t size;

	/* Length of on-disk type+size data. */
	size_t tslen; 

	/* Length of object data following type+size. */
	size_t len; 

	uint32_t crc;

	union {
		struct {
			/* For ref deltas. */
			struct got_object_id ref_id;
		} ref;
		struct {
			/* For offset deltas. */
			off_t base_offset;
			size_t base_offsetlen;
		} ofs;
	} delta;
};

static void
putbe32(char *b, uint32_t n)
{
	b[0] = n >> 24;
	b[1] = n >> 16;
	b[2] = n >> 8;
	b[3] = n >> 0;
}

static const struct got_error *
get_obj_type_label(const char **label, int obj_type)
{
	const struct got_error *err = NULL;

	switch (obj_type) {
	case GOT_OBJ_TYPE_BLOB:
		*label = GOT_OBJ_LABEL_BLOB;
		break;
	case GOT_OBJ_TYPE_TREE:
		*label = GOT_OBJ_LABEL_TREE;
		break;
	case GOT_OBJ_TYPE_COMMIT:
		*label = GOT_OBJ_LABEL_COMMIT;
		break;
	case GOT_OBJ_TYPE_TAG:
		*label = GOT_OBJ_LABEL_TAG;
		break;
	default:
		*label = NULL;
		err = got_error(GOT_ERR_OBJ_TYPE);
		break;
	}

	return err;
}

static const struct got_error *
read_checksum(uint32_t *crc, SHA1_CTX *sha1_ctx, int fd, size_t len)
{
	uint8_t buf[8192];
	size_t n;
	ssize_t r;

	for (n = len; n > 0; n -= r){
		r = read(fd, buf, n > sizeof(buf) ? sizeof(buf) : n);
		if (r == -1)
			return got_error_from_errno("read");
		if (r == 0)
			break;
		if (crc)
			*crc = crc32(*crc, buf, r);
		if (sha1_ctx)
			SHA1Update(sha1_ctx, buf, r);
	}

	return NULL;
}

static const struct got_error *
read_file_sha1(SHA1_CTX *ctx, FILE *f, size_t len)
{
	uint8_t buf[8192];
	size_t n, r;

	for (n = len; n > 0; n -= r) {
		r = fread(buf, 1, n > sizeof(buf) ? sizeof(buf) : n, f);
		if (r == 0) {
			if (feof(f))
				return NULL;
			return got_ferror(f, GOT_ERR_IO);
		}
		SHA1Update(ctx, buf, r);
	}

	return NULL;
}

static const struct got_error *
read_packed_object(struct got_pack *pack, struct got_indexed_object *obj,
    FILE *tmpfile, SHA1_CTX *pack_sha1_ctx)
{
	const struct got_error *err = NULL;
	SHA1_CTX ctx;
	uint8_t *data = NULL;
	size_t datalen = 0;
	ssize_t n;
	char *header;
	size_t headerlen;
	const char *obj_label;
	size_t mapoff = obj->off;
	struct got_inflate_checksum csum;

	csum.input_sha1 = pack_sha1_ctx;
	csum.input_crc = &obj->crc;

	err = got_pack_parse_object_type_and_size(&obj->type, &obj->size,
	    &obj->tslen, pack, obj->off);
	if (err)
		return err;

	if (pack->map) {
		obj->crc = crc32(obj->crc, pack->map + mapoff, obj->tslen);
		SHA1Update(pack_sha1_ctx, pack->map + mapoff, obj->tslen);
		mapoff += obj->tslen;
	} else {
		/* XXX Seek back and get the CRC of on-disk type+size bytes. */
		if (lseek(pack->fd, obj->off, SEEK_SET) == -1)
			return got_error_from_errno("lseek");
		err = read_checksum(&obj->crc, pack_sha1_ctx,
		    pack->fd, obj->tslen);
		if (err)
			return err;
	}

	switch (obj->type) {
	case GOT_OBJ_TYPE_BLOB:
	case GOT_OBJ_TYPE_COMMIT:
	case GOT_OBJ_TYPE_TREE:
	case GOT_OBJ_TYPE_TAG:
		if (obj->size > GOT_DELTA_RESULT_SIZE_CACHED_MAX) {
			if (fseek(tmpfile, 0L, SEEK_SET) == -1) {
				err = got_error_from_errno("fseek");
				break;
			}
			if (pack->map) {
				err = got_inflate_to_file_mmap(&datalen,
				    &obj->len, &csum, pack->map, mapoff,
				    pack->filesize - mapoff, tmpfile);
			} else {
				err = got_inflate_to_file_fd(&datalen,
				    &obj->len, &csum, pack->fd, tmpfile);
			}
		} else {
			if (pack->map) {
				err = got_inflate_to_mem_mmap(&data, &datalen,
				    &obj->len, &csum, pack->map, mapoff,
				    pack->filesize - mapoff);
			} else {
				err = got_inflate_to_mem_fd(&data, &datalen,
				    &obj->len, &csum, obj->size, pack->fd);
			}
		}
		if (err)
			break;
		SHA1Init(&ctx);
		err = get_obj_type_label(&obj_label, obj->type);
		if (err) {
			free(data);
			break;
		}
		if (asprintf(&header, "%s %lld", obj_label,
		    (long long)obj->size) == -1) {
			err = got_error_from_errno("asprintf");
			free(data);
			break;
		}
		headerlen = strlen(header) + 1;
		SHA1Update(&ctx, header, headerlen);
		if (obj->size > GOT_DELTA_RESULT_SIZE_CACHED_MAX) {
			err = read_file_sha1(&ctx, tmpfile, datalen);
			if (err)
				break;
		} else
			SHA1Update(&ctx, data, datalen);
		SHA1Final(obj->id.sha1, &ctx);
		free(header);
		free(data);
		break;
	case GOT_OBJ_TYPE_REF_DELTA:
		memset(obj->id.sha1, 0xff, SHA1_DIGEST_LENGTH);
		if (pack->map) {
			if (mapoff + SHA1_DIGEST_LENGTH >= pack->filesize) {
				err = got_error(GOT_ERR_BAD_PACKFILE);
				break;
			}
			memcpy(obj->delta.ref.ref_id.sha1, pack->map + mapoff,
			    SHA1_DIGEST_LENGTH);
			obj->crc = crc32(obj->crc, pack->map + mapoff,
			    SHA1_DIGEST_LENGTH);
			SHA1Update(pack_sha1_ctx, pack->map + mapoff,
			    SHA1_DIGEST_LENGTH);
			mapoff += SHA1_DIGEST_LENGTH;
			err = got_inflate_to_mem_mmap(NULL, &datalen,
			    &obj->len, &csum, pack->map, mapoff,
			    pack->filesize - mapoff);
			if (err)
				break;
		} else {
			n = read(pack->fd, obj->delta.ref.ref_id.sha1,
			    SHA1_DIGEST_LENGTH);
			if (n == -1) {
				err = got_error_from_errno("read");
				break;
			}
			if (n < sizeof(obj->id)) {
				err = got_error(GOT_ERR_BAD_PACKFILE);
				break;
			}
			obj->crc = crc32(obj->crc, obj->delta.ref.ref_id.sha1,
			    SHA1_DIGEST_LENGTH);
			SHA1Update(pack_sha1_ctx, obj->delta.ref.ref_id.sha1,
			    SHA1_DIGEST_LENGTH);
			err = got_inflate_to_mem_fd(NULL, &datalen, &obj->len,
			    &csum, obj->size, pack->fd);
			if (err)
				break;
		}
		obj->len += SHA1_DIGEST_LENGTH;
		break;
	case GOT_OBJ_TYPE_OFFSET_DELTA:
		memset(obj->id.sha1, 0xff, SHA1_DIGEST_LENGTH);
		err = got_pack_parse_offset_delta(&obj->delta.ofs.base_offset,
		    &obj->delta.ofs.base_offsetlen, pack, obj->off,
		    obj->tslen);
		if (err)
			break;

		if (pack->map) {
			obj->crc = crc32(obj->crc, pack->map + mapoff,
			    obj->delta.ofs.base_offsetlen);
			SHA1Update(pack_sha1_ctx, pack->map + mapoff,
			    obj->delta.ofs.base_offsetlen);
			mapoff += obj->delta.ofs.base_offsetlen;
			err = got_inflate_to_mem_mmap(NULL, &datalen,
			    &obj->len, &csum, pack->map, mapoff,
			    pack->filesize - mapoff);
			if (err)
				break;
		} else {
			/*
			 * XXX Seek back and get CRC and SHA1 of on-disk
			 * offset bytes.
			 */
			if (lseek(pack->fd, obj->off + obj->tslen, SEEK_SET)
			    == -1) {
				err = got_error_from_errno("lseek");
				break;
			}
			err = read_checksum(&obj->crc, pack_sha1_ctx,
			    pack->fd, obj->delta.ofs.base_offsetlen);
			if (err)
				break;

			err = got_inflate_to_mem_fd(NULL, &datalen, &obj->len,
			    &csum, obj->size, pack->fd);
			if (err)
				break;
		}
		obj->len += obj->delta.ofs.base_offsetlen;
		break;
	default:
		err = got_error(GOT_ERR_OBJ_TYPE);
		break;
	}

	return err;
}

static const struct got_error *
hwrite(int fd, void *buf, int len, SHA1_CTX *ctx)
{
	ssize_t w;

	SHA1Update(ctx, buf, len);

	w = write(fd, buf, len);
	if (w == -1)
		return got_error_from_errno("write");
	if (w != len)
		return got_error(GOT_ERR_IO);

	return NULL;
}

static const struct got_error *
resolve_deltified_object(struct got_pack *pack, struct got_packidx *packidx,
    struct got_indexed_object *obj, FILE *tmpfile, FILE *delta_base_file,
    FILE *delta_accum_file)
{
	const struct got_error *err = NULL;
	struct got_delta_chain deltas;
	struct got_delta *delta;
	uint8_t *buf = NULL;
	size_t len = 0;
	SHA1_CTX ctx;
	char *header = NULL;
	size_t headerlen;
	uint64_t max_size;
	int base_obj_type;
	const char *obj_label;

	deltas.nentries = 0;
	SIMPLEQ_INIT(&deltas.entries);

	err = got_pack_resolve_delta_chain(&deltas, packidx, pack,
	    obj->off, obj->tslen, obj->type, obj->size,
	    GOT_DELTA_CHAIN_RECURSION_MAX);
	if (err)
		goto done;

	err = got_pack_get_delta_chain_max_size(&max_size, &deltas, pack);
	if (err)
		goto done;
	if (max_size > GOT_DELTA_RESULT_SIZE_CACHED_MAX) {
		rewind(tmpfile);
		rewind(delta_base_file);
		rewind(delta_accum_file);
		err = got_pack_dump_delta_chain_to_file(&len, &deltas,
		    pack, tmpfile, delta_base_file, delta_accum_file);
		if (err)
			goto done;
	} else {
		err = got_pack_dump_delta_chain_to_mem(&buf, &len,
		    &deltas, pack);
	}
	if (err)
		goto done;

	err = got_delta_chain_get_base_type(&base_obj_type, &deltas);
	if (err)
		goto done;
	err = get_obj_type_label(&obj_label, base_obj_type);
	if (err)
		goto done;
	if (asprintf(&header, "%s %zd", obj_label, len) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	headerlen = strlen(header) + 1;
	SHA1Init(&ctx);
	SHA1Update(&ctx, header, headerlen);
	if (max_size > GOT_DELTA_RESULT_SIZE_CACHED_MAX) {
		err = read_file_sha1(&ctx, tmpfile, len);
		if (err)
			goto done;
	} else
		SHA1Update(&ctx, buf, len);
	SHA1Final(obj->id.sha1, &ctx);
done:
	free(buf);
	free(header);
	while (!SIMPLEQ_EMPTY(&deltas.entries)) {
		delta = SIMPLEQ_FIRST(&deltas.entries);
		SIMPLEQ_REMOVE_HEAD(&deltas.entries, entry);
		free(delta);
	}
	return err;
}

/* Determine the slot in the pack index a given object ID should use. */
static int
find_object_idx(struct got_packidx *packidx, uint8_t *sha1)
{
	u_int8_t id0 = sha1[0];
	uint32_t nindexed = be32toh(packidx->hdr.fanout_table[0xff]);
	int left = 0, right = nindexed - 1;
	int cmp = 0, i = 0;

	if (id0 > 0)
		left = be32toh(packidx->hdr.fanout_table[id0 - 1]);

	while (left <= right) {
		struct got_packidx_object_id *oid;

		i = ((left + right) / 2);
		oid = &packidx->hdr.sorted_ids[i];

		cmp = memcmp(sha1, oid->sha1, SHA1_DIGEST_LENGTH);
		if (cmp == 0)
			return -1; /* object already indexed */
		else if (cmp > 0)
			left = i + 1;
		else if (cmp < 0)
			right = i - 1;
	}

	return left;
}

#if 0
static void
print_packidx(struct got_packidx *packidx)
{
	uint32_t nindexed = be32toh(packidx->hdr.fanout_table[0xff]);
	int i;

	fprintf(stderr, "object IDs:\n");
	for (i = 0; i < nindexed; i++) {
		char hex[SHA1_DIGEST_STRING_LENGTH];
		got_sha1_digest_to_str(packidx->hdr.sorted_ids[i].sha1,
		    hex, sizeof(hex));
		fprintf(stderr, "%s\n", hex);
	}
	fprintf(stderr, "\n");

	fprintf(stderr, "object offsets:\n");
	for (i = 0; i < nindexed; i++) {
		uint32_t offset = be32toh(packidx->hdr.offsets[i]);
		if (offset & GOT_PACKIDX_OFFSET_VAL_IS_LARGE_IDX) {
			int j = offset & GOT_PACKIDX_OFFSET_VAL_MASK;
			fprintf(stderr, "%u -> %llu\n", offset, 
			    be64toh(packidx->hdr.large_offsets[j]));
		} else
			fprintf(stderr, "%u\n", offset);
	}
	fprintf(stderr, "\n");

	fprintf(stderr, "fanout table:");
	for (i = 0; i <= 0xff; i++)
		fprintf(stderr, " %u", be32toh(packidx->hdr.fanout_table[i]));
	fprintf(stderr, "\n");
}
#endif

static void
add_indexed_object(struct got_packidx *packidx, uint32_t idx,
    struct got_indexed_object *obj)
{
	int i;

	memcpy(packidx->hdr.sorted_ids[idx].sha1, obj->id.sha1,
	    SHA1_DIGEST_LENGTH);
	packidx->hdr.crc32[idx] = htobe32(obj->crc);
	if (obj->off < GOT_PACKIDX_OFFSET_VAL_IS_LARGE_IDX)
		packidx->hdr.offsets[idx] = htobe32(obj->off);
	else {
		packidx->hdr.offsets[idx] = htobe32(packidx->nlargeobj |
		    GOT_PACKIDX_OFFSET_VAL_IS_LARGE_IDX);
		packidx->hdr.large_offsets[packidx->nlargeobj] =
		    htobe64(obj->off);
		packidx->nlargeobj++;
	}

	for (i = obj->id.sha1[0]; i <= 0xff; i++) {
		uint32_t n = be32toh(packidx->hdr.fanout_table[i]);
		packidx->hdr.fanout_table[i] = htobe32(n + 1);
	}
}

static int
indexed_obj_cmp(const void *pa, const void *pb)
{
	struct got_indexed_object *a, *b;

	a = (struct got_indexed_object *)pa;
	b = (struct got_indexed_object *)pb;
	return got_object_id_cmp(&a->id, &b->id);
}

static void
make_packidx(struct got_packidx *packidx, int nobj,
    struct got_indexed_object *objects)
{
	struct got_indexed_object *obj;
	int i;
	uint32_t idx = 0;

	qsort(objects, nobj, sizeof(struct got_indexed_object),
	    indexed_obj_cmp);

	memset(packidx->hdr.fanout_table, 0,
	    GOT_PACKIDX_V2_FANOUT_TABLE_ITEMS * sizeof(uint32_t));
	packidx->nlargeobj = 0;

	for (i = 0; i < nobj; i++) {
		obj = &objects[i];
		if (obj->valid)
			add_indexed_object(packidx, idx++, obj);
	}
}

static void
update_packidx(struct got_packidx *packidx, int nobj,
    struct got_indexed_object *obj)
{
	uint32_t idx;
	uint32_t nindexed = be32toh(packidx->hdr.fanout_table[0xff]);

	idx = find_object_idx(packidx, obj->id.sha1);
	if (idx == -1) {
		char hex[SHA1_DIGEST_STRING_LENGTH];
		got_sha1_digest_to_str(obj->id.sha1, hex, sizeof(hex));
		return; /* object already indexed */
	}

	memmove(&packidx->hdr.sorted_ids[idx + 1],
	    &packidx->hdr.sorted_ids[idx],
	    sizeof(struct got_packidx_object_id) * (nindexed - idx));
	memmove(&packidx->hdr.offsets[idx + 1], &packidx->hdr.offsets[idx],
	    sizeof(uint32_t) * (nindexed - idx));

	add_indexed_object(packidx, idx, obj);
}

static const struct got_error *
send_index_pack_progress(struct imsgbuf *ibuf, int nobj_total,
    int nobj_indexed, int nobj_loose, int nobj_resolved)
{
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


static const struct got_error *
index_pack(struct got_pack *pack, int idxfd, FILE *tmpfile,
    FILE *delta_base_file, FILE *delta_accum_file, uint8_t *pack_sha1_expected,
    struct imsgbuf *ibuf)
{
	const struct got_error *err;
	struct got_packfile_hdr hdr;
	struct got_packidx packidx;
	char buf[8];
	char pack_sha1[SHA1_DIGEST_LENGTH];
	int nobj, nvalid, nloose, nresolved = 0, i;
	struct got_indexed_object *objects = NULL, *obj;
	SHA1_CTX ctx;
	uint8_t packidx_hash[SHA1_DIGEST_LENGTH];
	ssize_t r, w;
	int pass, have_ref_deltas = 0, first_delta_idx = -1;
	size_t mapoff = 0;
	int p_indexed = 0, last_p_indexed = -1;
	int p_resolved = 0, last_p_resolved = -1;

	/* Require that pack file header and SHA1 trailer are present. */
	if (pack->filesize < sizeof(hdr) + SHA1_DIGEST_LENGTH)
		return got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "short pack file");

	if (pack->map) {
		memcpy(&hdr, pack->map, sizeof(hdr));
		mapoff += sizeof(hdr);
	} else {
		r = read(pack->fd, &hdr, sizeof(hdr));
		if (r == -1)
			return got_error_from_errno("read");
		if (r < sizeof(hdr))
			return got_error_msg(GOT_ERR_BAD_PACKFILE,
			    "short pack file");
	}

	if (hdr.signature != htobe32(GOT_PACKFILE_SIGNATURE))
		return got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "bad packfile signature");
	if (hdr.version != htobe32(GOT_PACKFILE_VERSION))
		return got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "bad packfile version");
	nobj = be32toh(hdr.nobjects);
	if (nobj == 0)
		return got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "bad packfile with zero objects");

	/* We compute the SHA1 of pack file contents and verify later on. */
	SHA1Init(&ctx);
	SHA1Update(&ctx, (void *)&hdr, sizeof(hdr));

	/*
	 * Create an in-memory pack index which will grow as objects
	 * IDs in the pack file are discovered. Only fields used to
	 * read deltified objects will be needed by the pack.c library
	 * code, so setting up just a pack index header is sufficient.
	 */
	memset(&packidx, 0, sizeof(packidx));
	packidx.hdr.magic = malloc(sizeof(uint32_t));
	if (packidx.hdr.magic == NULL)
		return got_error_from_errno("calloc");
	*packidx.hdr.magic = htobe32(GOT_PACKIDX_V2_MAGIC);
	packidx.hdr.version = malloc(sizeof(uint32_t));
	if (packidx.hdr.version == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}
	*packidx.hdr.version = htobe32(GOT_PACKIDX_VERSION);
	packidx.hdr.fanout_table = calloc(GOT_PACKIDX_V2_FANOUT_TABLE_ITEMS,
	    sizeof(uint32_t));
	if (packidx.hdr.fanout_table == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}
	packidx.hdr.sorted_ids = calloc(nobj,
	    sizeof(struct got_packidx_object_id));
	if (packidx.hdr.sorted_ids == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}
	packidx.hdr.crc32 = calloc(nobj, sizeof(uint32_t));
	if (packidx.hdr.crc32 == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}
	packidx.hdr.offsets = calloc(nobj, sizeof(uint32_t));
	if (packidx.hdr.offsets == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}
	/* Large offsets table is empty for pack files < 2 GB. */
	if (pack->filesize >= GOT_PACKIDX_OFFSET_VAL_IS_LARGE_IDX) {
		packidx.hdr.large_offsets = calloc(nobj, sizeof(uint64_t));
		if (packidx.hdr.large_offsets == NULL) {
			err = got_error_from_errno("calloc");
			goto done;
		}
	}

	nvalid = 0;
	nloose = 0;
	objects = calloc(nobj, sizeof(struct got_indexed_object));
	if (objects == NULL)
		return got_error_from_errno("calloc");

	/*
	 * First pass: locate all objects and identify un-deltified objects.
	 *
	 * When this pass has completed we will know offset, type, size, and
	 * CRC information for all objects in this pack file. We won't know
	 * any of the actual object IDs of deltified objects yet since we
	 * will not yet attempt to combine deltas.
	 */
	pass = 1;
	for (i = 0; i < nobj; i++) {
		/* Don't send too many progress privsep messages. */
		p_indexed = ((i + 1) * 100) / nobj;
		if (p_indexed != last_p_indexed) {
			err = send_index_pack_progress(ibuf, nobj, i + 1,
			    nloose, 0);
			if (err)
				goto done;
			last_p_indexed = p_indexed;
		}

		obj = &objects[i];
		obj->crc = crc32(0L, NULL, 0);

		/* Store offset to type+size information for this object. */
		if (pack->map) {
			obj->off = mapoff;
		} else {
			obj->off = lseek(pack->fd, 0, SEEK_CUR);
			if (obj->off == -1) {
				err = got_error_from_errno("lseek");
				goto done;
			}
		}

		err = read_packed_object(pack, obj, tmpfile, &ctx);
		if (err)
			goto done;

		if (pack->map) {
			mapoff += obj->tslen + obj->len;
		} else {
			if (lseek(pack->fd, obj->off + obj->tslen + obj->len,
			    SEEK_SET) == -1) {
				err = got_error_from_errno("lseek");
				goto done;
			}
		}

		if (obj->type == GOT_OBJ_TYPE_BLOB ||
		    obj->type == GOT_OBJ_TYPE_TREE ||
		    obj->type == GOT_OBJ_TYPE_COMMIT ||
		    obj->type == GOT_OBJ_TYPE_TAG) {
			obj->valid = 1;
			nloose++;
		} else {
			if (first_delta_idx == -1)
				first_delta_idx = i;
			if (obj->type == GOT_OBJ_TYPE_REF_DELTA)
				have_ref_deltas = 1;
		}
	}
	nvalid = nloose;

	/*
	 * Having done a full pass over the pack file and can now
	 * verify its checksum.
	 */
	SHA1Final(pack_sha1, &ctx);
	if (memcmp(pack_sha1_expected, pack_sha1, SHA1_DIGEST_LENGTH) != 0) {
		err = got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "pack file checksum mismatch");
		goto done;
	}

	/* Verify the SHA1 checksum stored at the end of the pack file. */
	if (pack->map) {
		memcpy(pack_sha1_expected, pack->map +
		    pack->filesize - SHA1_DIGEST_LENGTH,
		    SHA1_DIGEST_LENGTH);
	} else {
		ssize_t n;
		if (lseek(pack->fd, -SHA1_DIGEST_LENGTH, SEEK_END) == -1) {
			err = got_error_from_errno("lseek");
			goto done;
		}
		n = read(pack->fd, pack_sha1_expected, SHA1_DIGEST_LENGTH);
		if (n == -1) {
			err = got_error_from_errno("read");
			goto done;
		}
		if (n != SHA1_DIGEST_LENGTH) {
			err = got_error(GOT_ERR_IO);
			goto done;
		}
	}
	if (memcmp(pack_sha1, pack_sha1_expected, SHA1_DIGEST_LENGTH) != 0) {
		err = got_error_msg(GOT_ERR_BAD_PACKFILE,
		    "bad checksum in pack file trailer");
		goto done;
	}

	if (first_delta_idx == -1)
		first_delta_idx = 0;

	/* In order to resolve ref deltas we need an in-progress pack index. */
	if (have_ref_deltas)
		make_packidx(&packidx, nobj, objects);

	/*
	 * Second pass: We can now resolve deltas to compute the IDs of
	 * objects which appear in deltified form. Because deltas can be
	 * chained this pass may require a couple of iterations until all
	 * IDs of deltified objects have been discovered.
	 */
	pass++;
	while (nvalid != nobj) {
		int n = 0;
		/*
		 * This loop will only run once unless the pack file
		 * contains ref deltas which refer to objects located
		 * later in the pack file, which is unusual.
		 * Offset deltas can always be resolved in one pass
		 * unless the packfile is corrupt.
		 */
		for (i = first_delta_idx; i < nobj; i++) {
			obj = &objects[i];
			if (obj->type != GOT_OBJ_TYPE_REF_DELTA &&
			    obj->type != GOT_OBJ_TYPE_OFFSET_DELTA)
				continue;

			if (obj->valid)
				continue;

			if (pack->map == NULL && lseek(pack->fd,
			    obj->off + obj->tslen, SEEK_SET) == -1) {
				err = got_error_from_errno("lseek");
				goto done;
			}

			err = resolve_deltified_object(pack, &packidx, obj,
			    tmpfile, delta_base_file, delta_accum_file);
			if (err) {
				if (err->code != GOT_ERR_NO_OBJ)
					goto done;
				/*
				 * We cannot resolve this object yet because
				 * a delta base is unknown. Try again later.
				 */
				continue;
			}

			obj->valid = 1;
			n++;
			if (have_ref_deltas)
				update_packidx(&packidx, nobj, obj);
			/* Don't send too many progress privsep messages. */
			p_resolved = ((nresolved + n) * 100) / nobj;
			if (p_resolved != last_p_resolved) {
				err = send_index_pack_progress(ibuf, nobj,
				    nobj, nloose, nresolved + n);
				if (err)
					goto done;
				last_p_resolved = p_resolved;
			}

		}
		if (pass++ > 3 && n == 0) {
			static char msg[64];
			snprintf(msg, sizeof(msg), "could not resolve "
			    "any of deltas; packfile could be corrupt");
			err = got_error_msg(GOT_ERR_BAD_PACKFILE, msg);
			goto done;

		}
		nresolved += n;
		nvalid += nresolved;
	}

	if (nloose + nresolved != nobj) {
		static char msg[64];
		snprintf(msg, sizeof(msg), "discovered only %d of %d objects",
		    nloose + nresolved, nobj);
		err = got_error_msg(GOT_ERR_BAD_PACKFILE, msg);
		goto done;
	}

	err = send_index_pack_progress(ibuf, nobj, nobj, nloose, nresolved);
	if (err)
		goto done;

	make_packidx(&packidx, nobj, objects);

	free(objects);
	objects = NULL;

	SHA1Init(&ctx);
	putbe32(buf, GOT_PACKIDX_V2_MAGIC);
	putbe32(buf + 4, GOT_PACKIDX_VERSION);
	err = hwrite(idxfd, buf, 8, &ctx);
	if (err)
		goto done;
	err = hwrite(idxfd, packidx.hdr.fanout_table,
	    GOT_PACKIDX_V2_FANOUT_TABLE_ITEMS * sizeof(uint32_t), &ctx);
	if (err)
		goto done;
	err = hwrite(idxfd, packidx.hdr.sorted_ids,
	    nobj * SHA1_DIGEST_LENGTH, &ctx);
	if (err)
		goto done;
	err = hwrite(idxfd, packidx.hdr.crc32, nobj * sizeof(uint32_t), &ctx);
	if (err)
		goto done;
	err = hwrite(idxfd, packidx.hdr.offsets, nobj * sizeof(uint32_t),
	    &ctx);
	if (err)
		goto done;
	if (packidx.nlargeobj > 0) {
		err = hwrite(idxfd, packidx.hdr.large_offsets,
		    packidx.nlargeobj * sizeof(uint64_t), &ctx);
		if (err)
			goto done;
	}
	err = hwrite(idxfd, pack_sha1, SHA1_DIGEST_LENGTH, &ctx);
	if (err)
		goto done;

	SHA1Final(packidx_hash, &ctx);
	w = write(idxfd, packidx_hash, sizeof(packidx_hash));
	if (w == -1) {
		err = got_error_from_errno("write");
		goto done;
	}
	if (w != sizeof(packidx_hash)) {
		err = got_error(GOT_ERR_IO);
		goto done;
	}
done:
	free(objects);
	free(packidx.hdr.magic);
	free(packidx.hdr.version);
	free(packidx.hdr.fanout_table);
	free(packidx.hdr.sorted_ids);
	free(packidx.hdr.offsets);
	free(packidx.hdr.large_offsets);
	return err;
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
#if 0
	static int attached;
	while (!attached)
		sleep(1);
#endif

	for (i = 0; i < nitems(tmpfiles); i++)
		tmpfiles[i] = NULL;

	memset(&pack, 0, sizeof(pack));
	pack.fd = -1;
	pack.delta_cache = got_delta_cache_alloc(500,
	    GOT_DELTA_RESULT_SIZE_CACHED_MAX);
	if (pack.delta_cache == NULL) {
		err = got_error_from_errno("got_delta_cache_alloc");
		goto done;
	}

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
	pack.filesize = packfile_size; /* XXX off_t vs size_t */

	if (lseek(pack.fd, 0, SEEK_SET) == -1) {
		err = got_error_from_errno("lseek");
		goto done;
	}

#ifndef GOT_PACK_NO_MMAP
	pack.map = mmap(NULL, pack.filesize, PROT_READ, MAP_PRIVATE,
	    pack.fd, 0);
	if (pack.map == MAP_FAILED)
		pack.map = NULL; /* fall back to read(2) */
#endif
	err = index_pack(&pack, idxfd, tmpfiles[0], tmpfiles[1], tmpfiles[2],
	    pack_hash, &ibuf);
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
			err = got_error_from_errno("close");
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
