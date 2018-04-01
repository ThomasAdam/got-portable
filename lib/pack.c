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
#include <sys/stat.h>
#include <sys/queue.h>

#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sha1.h>
#include <endian.h>
#include <zlib.h>

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"

#include "got_lib_sha1.h"
#include "got_lib_pack.h"
#include "got_lib_path.h"
#include "got_lib_delta.h"
#include "got_lib_zbuf.h"
#include "got_lib_object.h"
#include "got_lib_repository.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

#define GOT_PACK_PREFIX		"pack-"
#define GOT_PACKFILE_SUFFIX	".pack"
#define GOT_PACKIDX_SUFFIX		".idx"
#define GOT_PACKFILE_NAMELEN	(strlen(GOT_PACK_PREFIX) + \
				SHA1_DIGEST_STRING_LENGTH - 1 + \
				strlen(GOT_PACKFILE_SUFFIX))
#define GOT_PACKIDX_NAMELEN	(strlen(GOT_PACK_PREFIX) + \
				SHA1_DIGEST_STRING_LENGTH - 1 + \
				strlen(GOT_PACKIDX_SUFFIX))

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

static const struct got_error *
verify_fanout_table(uint32_t *fanout_table)
{
	int i;

	for (i = 0; i < 0xff - 1; i++) {
		if (be32toh(fanout_table[i]) > be32toh(fanout_table[i + 1]))
			return got_error(GOT_ERR_BAD_PACKIDX);
	}

	return NULL;
}

static const struct got_error *
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
		return got_error_from_errno();

	if (stat(path_pack, &sb) != 0) {
		free(path_pack);
		return got_error_from_errno();
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
		return got_error_from_errno();

	err = get_packfile_size(&packfile_size, path);
	if (err)
		return err;

	p = calloc(1, sizeof(*p));
	if (p == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	n = fread(&p->magic, sizeof(p->magic), 1, f);
	if (n != 1) {
		err = got_ferror(f, GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	if (betoh32(p->magic) != GOT_PACKIDX_V2_MAGIC) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t *)&p->magic, sizeof(p->magic));

	n = fread(&p->version, sizeof(p->version), 1, f);
	if (n != 1) {
		err = got_ferror(f, GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	if (betoh32(p->version) != GOT_PACKIDX_VERSION) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t *)&p->version, sizeof(p->version));

	n = fread(&p->fanout_table, sizeof(p->fanout_table), 1, f);
	if (n != 1) {
		err = got_ferror(f, GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	err = verify_fanout_table(p->fanout_table);
	if (err)
		goto done;

	SHA1Update(&ctx, (uint8_t *)p->fanout_table, sizeof(p->fanout_table));

	nobj = betoh32(p->fanout_table[0xff]);

	p->sorted_ids = calloc(nobj, sizeof(*p->sorted_ids));
	if (p->sorted_ids == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	n = fread(p->sorted_ids, sizeof(*p->sorted_ids), nobj, f);
	if (n != nobj) {
		err = got_ferror(f, GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t *)p->sorted_ids,
	    nobj * sizeof(*p->sorted_ids));

	p->crc32 = calloc(nobj, sizeof(*p->crc32));
	if (p->crc32 == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	n = fread(p->crc32, sizeof(*p->crc32), nobj, f);
	if (n != nobj) {
		err = got_ferror(f, GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t *)p->crc32, nobj * sizeof(*p->crc32));

	p->offsets = calloc(nobj, sizeof(*p->offsets));
	if (p->offsets == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	n = fread(p->offsets, sizeof(*p->offsets), nobj, f);
	if (n != nobj) {
		err = got_ferror(f, GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t *)p->offsets, nobj * sizeof(*p->offsets));

	/* Large file offsets are contained only in files > 2GB. */
	if (packfile_size <= 0x80000000)
		goto checksum;

	p->large_offsets = calloc(nobj, sizeof(*p->large_offsets));
	if (p->large_offsets == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	n = fread(p->large_offsets, sizeof(*p->large_offsets), nobj, f);
	if (n != nobj) {
		err = got_ferror(f, GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t*)p->large_offsets,
	    nobj * sizeof(*p->large_offsets));

checksum:
	n = fread(&p->trailer, sizeof(p->trailer), 1, f);
	if (n != 1) {
		err = got_ferror(f, GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, p->trailer.packfile_sha1, SHA1_DIGEST_LENGTH);
	SHA1Final(sha1, &ctx);
	if (memcmp(p->trailer.packidx_sha1, sha1, SHA1_DIGEST_LENGTH) != 0)
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

static int
is_packidx_filename(const char *name, size_t len)
{
	if (len != GOT_PACKIDX_NAMELEN)
		return 0;

	if (strncmp(name, GOT_PACK_PREFIX, strlen(GOT_PACK_PREFIX)) != 0)
		return 0;

	if (strcmp(name + strlen(GOT_PACK_PREFIX) +
	    SHA1_DIGEST_STRING_LENGTH - 1, GOT_PACKIDX_SUFFIX) != 0)
		return 0;

	return 1;
}

static off_t
get_object_offset(struct got_packidx_v2_hdr *packidx, int idx)
{
	uint32_t totobj = betoh32(packidx->fanout_table[0xff]);
	uint32_t offset = betoh32(packidx->offsets[idx]);
	if (offset & GOT_PACKIDX_OFFSET_VAL_IS_LARGE_IDX) {
		uint64_t loffset;
		idx = offset & GOT_PACKIDX_OFFSET_VAL_MASK;
		if (idx < 0 || idx > totobj || packidx->large_offsets == NULL)
			return -1;
		loffset = betoh64(packidx->large_offsets[idx]);
		return (loffset > INT64_MAX ? -1 : (off_t)loffset);
	}
	return (off_t)(offset & GOT_PACKIDX_OFFSET_VAL_MASK);
}

static int
get_object_idx(struct got_packidx_v2_hdr *packidx, struct got_object_id *id)
{
	u_int8_t id0 = id->sha1[0];
	uint32_t totobj = betoh32(packidx->fanout_table[0xff]);
	int i = 0;

	if (id0 > 0)
		i = betoh32(packidx->fanout_table[id0 - 1]);

	while (i < totobj) {
		struct got_object_id *oid = &packidx->sorted_ids[i];
		int cmp = got_object_id_cmp(id, oid);

		if (cmp == 0)
			return i;
		i++;
	}

	return -1;
}

static struct got_packidx_v2_hdr *
dup_packidx(struct got_packidx_v2_hdr *packidx)
{
	struct got_packidx_v2_hdr *p;
	size_t nobj;

	p = calloc(1, sizeof(*p));
	if (p == NULL)
		return NULL;

	memcpy(p, packidx, sizeof(*p));
	p->sorted_ids = NULL;
	p->crc32 = NULL;
	p->offsets = NULL;
	p->large_offsets = NULL;

	nobj = betoh32(p->fanout_table[0xff]);

	p->sorted_ids = calloc(nobj, sizeof(*p->sorted_ids));
	if (p->sorted_ids == NULL)
		goto err;
	memcpy(p->sorted_ids, packidx->sorted_ids, nobj * sizeof(*p->sorted_ids));

	p->crc32 = calloc(nobj, sizeof(*p->crc32));
	if (p->crc32 == NULL)
		goto err;
	memcpy(p->crc32, packidx->crc32, nobj * sizeof(*p->crc32));

	p->offsets = calloc(nobj, sizeof(*p->offsets));
	if (p->offsets == NULL)
		goto err;
	memcpy(p->offsets, packidx->offsets, nobj * sizeof(*p->offsets));

	if (p->large_offsets) {
		p->large_offsets = calloc(nobj, sizeof(*p->large_offsets));
		if (p->large_offsets == NULL)
			goto err;
		memcpy(p->large_offsets, packidx->large_offsets,
		    nobj * sizeof(*p->large_offsets));
	}

	return p;

err:
	free(p->large_offsets);
	free(p->offsets);
	free(p->crc32);
	free(p->sorted_ids);
	free(p);
	return NULL;
}

static void
cache_packidx(struct got_packidx_v2_hdr *packidx, struct got_repository *repo)
{
	int i;

	for (i = 0; i < nitems(repo->packidx_cache); i++) {
		if (repo->packidx_cache[i] == NULL)
			break;
	}

	if (i == nitems(repo->packidx_cache)) {
		got_packidx_close(repo->packidx_cache[i - 1]);
		memmove(&repo->packidx_cache[1], &repo->packidx_cache[0],
		    sizeof(repo->packidx_cache) -
		    sizeof(repo->packidx_cache[0]));
		i = 0;
	}

	repo->packidx_cache[i] = dup_packidx(packidx);
}

static const struct got_error *
search_packidx(struct got_packidx_v2_hdr **packidx, int *idx,
    struct got_repository *repo, struct got_object_id *id)
{
	const struct got_error *err;
	char *path_packdir;
	DIR *packdir;
	struct dirent *dent;
	char *path_packidx;
	int i;

	/* Search pack index cache. */
	for (i = 0; i < nitems(repo->packidx_cache); i++) {
		if (repo->packidx_cache[i] == NULL)
			break;
		*idx = get_object_idx(repo->packidx_cache[i], id);
		if (*idx != -1) {
			*packidx = repo->packidx_cache[i];
			return NULL;
		}
	}
	/* No luck. Search the filesystem. */

	path_packdir = got_repo_get_path_objects_pack(repo);
	if (path_packdir == NULL)
		return got_error_from_errno();

	packdir = opendir(path_packdir);
	if (packdir == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	while ((dent = readdir(packdir)) != NULL) {
		if (!is_packidx_filename(dent->d_name, dent->d_namlen))
			continue;

		if (asprintf(&path_packidx, "%s/%s", path_packdir,
		    dent->d_name) == -1) {
			err = got_error_from_errno();
			goto done;
		}

		err = got_packidx_open(packidx, path_packidx);
		free(path_packidx);
		if (err)
			goto done;

		*idx = get_object_idx(*packidx, id);
		if (*idx != -1) {
			err = NULL; /* found the object */
			cache_packidx(*packidx, repo);
			goto done;
		}

		got_packidx_close(*packidx);
		*packidx = NULL;
	}

	err = got_error(GOT_ERR_NO_OBJ);
done:
	free(path_packdir);
	if (packdir && closedir(packdir) != 0 && err == 0)
		err = got_error_from_errno();
	return err;
}

static const struct got_error *
get_packfile_path(char **path_packfile, struct got_repository *repo,
    struct got_packidx_v2_hdr *packidx)
{
	char *path_packdir;
	char hex[SHA1_DIGEST_STRING_LENGTH];
	char *sha1str;

	path_packdir = got_repo_get_path_objects_pack(repo);
	if (path_packdir == NULL)
		return got_error_from_errno();

	sha1str = got_sha1_digest_to_str(packidx->trailer.packfile_sha1,
	    hex, sizeof(hex));
	if (sha1str == NULL)
		return got_error(GOT_ERR_PACKIDX_CSUM);

	if (asprintf(path_packfile, "%s/%s%s%s", path_packdir,
	    GOT_PACK_PREFIX, sha1str, GOT_PACKFILE_SUFFIX) == -1) {
		*path_packfile = NULL;
		return got_error_from_errno();
	}

	return NULL;
}

const struct got_error *
read_packfile_hdr(FILE *f, struct got_packidx_v2_hdr *packidx)
{
	const struct got_error *err = NULL;
	uint32_t totobj = betoh32(packidx->fanout_table[0xff]);
	struct got_packfile_hdr hdr;
	size_t n;

	n = fread(&hdr, sizeof(hdr), 1, f);
	if (n != 1)
		return got_ferror(f, GOT_ERR_BAD_PACKIDX);

	if (betoh32(hdr.signature) != GOT_PACKFILE_SIGNATURE ||
	    betoh32(hdr.version) != GOT_PACKFILE_VERSION ||
	    betoh32(hdr.nobjects) != totobj)
		err = got_error(GOT_ERR_BAD_PACKFILE);

	return err;
}

static const struct got_error *
open_packfile(FILE **packfile, const char *path_packfile,
    struct got_repository *repo, struct got_packidx_v2_hdr *packidx)
{
	const struct got_error *err = NULL;

	*packfile = NULL;

	*packfile = fopen(path_packfile, "rb");
	if (*packfile == NULL) {
		err = got_error_from_errno();
		return err;
	}

	if (packidx) {
		err = read_packfile_hdr(*packfile, packidx);
		if (err) {
			fclose(*packfile);
			*packfile = NULL;
		}
	}
	return err;
}

void
got_pack_close(struct got_pack *pack)
{
	fclose(pack->packfile);
	pack->packfile = NULL;
	free(pack->path_packfile);
	pack->path_packfile = NULL;
	pack->filesize = 0;
}

static const struct got_error *
cache_pack(struct got_pack **packp, const char *path_packfile,
    struct got_packidx_v2_hdr *packidx, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_pack *pack = NULL;
	int i;

	if (packp)
		*packp = NULL;

	for (i = 0; i < nitems(repo->packs); i++) {
		pack = &repo->packs[i];
		if (pack->path_packfile == NULL)
			break;
		if (strcmp(pack->path_packfile, path_packfile) == 0)
			return NULL;
	}

	if (i == nitems(repo->packs) - 1) {
		got_pack_close(&repo->packs[i - 1]);
		memmove(&repo->packs[1], &repo->packs[0],
		    sizeof(repo->packs) - sizeof(repo->packs[0]));
		i = 0;
	}

	pack = &repo->packs[i];

	pack->path_packfile = strdup(path_packfile);
	if (pack->path_packfile == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	err = open_packfile(&pack->packfile, path_packfile, repo, packidx);
	if (err)
		goto done;

	err = get_packfile_size(&pack->filesize, path_packfile);
done:
	if (err) {
		if (pack)
			free(pack->path_packfile);
		free(pack);
	} else if (packp)
		*packp = pack;
	return err;
}

struct got_pack *
get_cached_pack(const char *path_packfile, struct got_repository *repo)
{
	struct got_pack *pack = NULL;
	int i;

	for (i = 0; i < nitems(repo->packs); i++) {
		pack = &repo->packs[i];
		if (pack->path_packfile == NULL)
			break;
		if (strcmp(pack->path_packfile, path_packfile) == 0)
			return pack;
	}

	return NULL;
}

static const struct got_error *
parse_object_type_and_size(uint8_t *type, uint64_t *size, size_t *len,
    FILE *packfile)
{
	uint8_t t = 0;
	uint64_t s = 0;
	uint8_t sizeN;
	size_t n;
	int i = 0;

	do {
		/* We do not support size values which don't fit in 64 bit. */
		if (i > 9)
			return got_error(GOT_ERR_NO_SPACE);

		n = fread(&sizeN, sizeof(sizeN), 1, packfile);
		if (n != 1)
			return got_ferror(packfile, GOT_ERR_BAD_PACKIDX);

		if (i == 0) {
			t = (sizeN & GOT_PACK_OBJ_SIZE0_TYPE_MASK) >>
			    GOT_PACK_OBJ_SIZE0_TYPE_MASK_SHIFT;
			s = (sizeN & GOT_PACK_OBJ_SIZE0_VAL_MASK);
		} else {
			size_t shift = 4 + 7 * (i - 1);
			s |= ((sizeN & GOT_PACK_OBJ_SIZE_VAL_MASK) << shift);
		}
		i++;
	} while (sizeN & GOT_PACK_OBJ_SIZE_MORE);

	*type = t;
	*size = s;
	*len = i * sizeof(sizeN);
	return NULL;
}

static const struct got_error *
open_plain_object(struct got_object **obj, const char *path_packfile,
    struct got_object_id *id, uint8_t type, off_t offset, size_t size)
{
	*obj = calloc(1, sizeof(**obj));
	if (*obj == NULL)
		return got_error_from_errno();

	(*obj)->path_packfile = strdup(path_packfile);
	if ((*obj)->path_packfile == NULL) {
		const struct got_error *err = got_error_from_errno();
		free(*obj);
		*obj = NULL;
		return err;
	}

	(*obj)->type = type;
	(*obj)->flags = GOT_OBJ_FLAG_PACKED;
	(*obj)->hdrlen = 0;
	(*obj)->size = size;
	memcpy(&(*obj)->id, id, sizeof((*obj)->id));
	(*obj)->pack_offset = offset;

	return NULL;
}

static const struct got_error *
parse_negative_offset(int64_t *offset, size_t *len, FILE *packfile)
{
	int64_t o = 0;
	uint8_t offN;
	size_t n;
	int i = 0;

	do {
		/* We do not support offset values which don't fit in 64 bit. */
		if (i > 8)
			return got_error(GOT_ERR_NO_SPACE);

		n = fread(&offN, sizeof(offN), 1, packfile);
		if (n != 1)
			return got_ferror(packfile, GOT_ERR_BAD_PACKIDX);

		if (i == 0)
			o = (offN & GOT_PACK_OBJ_DELTA_OFF_VAL_MASK);
		else {
			o++;
			o <<= 7;
			o += (offN & GOT_PACK_OBJ_DELTA_OFF_VAL_MASK);
		}
		i++;
	} while (offN & GOT_PACK_OBJ_DELTA_OFF_MORE);

	*offset = o;
	*len = i * sizeof(offN);
	return NULL;
}

static const struct got_error *
parse_offset_delta(off_t *base_offset, FILE *packfile, off_t offset)
{
	const struct got_error *err;
	int64_t negoffset;
	size_t negofflen;

	err = parse_negative_offset(&negoffset, &negofflen, packfile);
	if (err)
		return err;

	/* Compute the base object's offset (must be in the same pack file). */
	*base_offset = (offset - negoffset);
	if (*base_offset <= 0)
		return got_error(GOT_ERR_BAD_PACKFILE);

	return NULL;
}

static const struct got_error *
resolve_delta_chain(struct got_delta_chain *, struct got_repository *,
    FILE *, const char *, off_t, size_t, int, size_t);

static const struct got_error *
add_delta(struct got_delta_chain *deltas, const char *path_packfile,
    off_t delta_offset, size_t tslen, int delta_type, size_t delta_size,
    size_t delta_data_offset, uint8_t *delta_buf, size_t delta_len)
{
	struct got_delta *delta;

	delta = got_delta_open(path_packfile, delta_offset, tslen,
	    delta_type, delta_size, delta_data_offset, delta_buf,
	    delta_len);
	if (delta == NULL)
		return got_error_from_errno();
	/* delta is freed in got_object_close() */
	deltas->nentries++;
	SIMPLEQ_INSERT_HEAD(&deltas->entries, delta, entry);
	return NULL;
}

static const struct got_error *
resolve_offset_delta(struct got_delta_chain *deltas,
    struct got_repository *repo, FILE *packfile, const char *path_packfile,
    off_t delta_offset,size_t tslen, int delta_type, size_t delta_size)

{
	const struct got_error *err;
	off_t base_offset;
	uint8_t base_type;
	uint64_t base_size;
	size_t base_tslen;
	off_t delta_data_offset;
	uint8_t *delta_buf;
	size_t delta_len;

	err = parse_offset_delta(&base_offset, packfile, delta_offset);
	if (err)
		return err;

	delta_data_offset = ftello(packfile);
	if (delta_data_offset == -1)
		return got_error_from_errno();

	err = got_inflate_to_mem(&delta_buf, &delta_len, packfile);
	if (err)
		return err;

	err = add_delta(deltas, path_packfile, delta_offset, tslen,
	    delta_type, delta_size, delta_data_offset, delta_buf, delta_len);
	if (err)
		return err;

	/* An offset delta must be in the same packfile. */
	if (fseeko(packfile, base_offset, SEEK_SET) != 0)
		return got_error_from_errno();

	err = parse_object_type_and_size(&base_type, &base_size, &base_tslen,
	    packfile);
	if (err)
		return err;

	return resolve_delta_chain(deltas, repo, packfile, path_packfile,
	    base_offset, base_tslen, base_type, base_size);
}

static const struct got_error *
resolve_ref_delta(struct got_delta_chain *deltas, struct got_repository *repo,
    FILE *packfile, const char *path_packfile, off_t delta_offset,
    size_t tslen, int delta_type, size_t delta_size)
{
	const struct got_error *err;
	struct got_object_id id;
	struct got_packidx_v2_hdr *packidx;
	int idx;
	off_t base_offset;
	uint8_t base_type;
	uint64_t base_size;
	size_t base_tslen;
	size_t n;
	char *path_base_packfile;
	struct got_pack *base_pack;
	off_t delta_data_offset;
	uint8_t *delta_buf;
	size_t delta_len;

	n = fread(&id, sizeof(id), 1, packfile);
	if (n != 1)
		return got_ferror(packfile, GOT_ERR_IO);

	delta_data_offset = ftello(packfile);
	if (delta_data_offset == -1)
		return got_error_from_errno();

	err = got_inflate_to_mem(&delta_buf, &delta_len, packfile);
	if (err)
		return err;

	err = add_delta(deltas, path_packfile, delta_offset, tslen,
	    delta_type, delta_size, delta_data_offset, delta_buf, delta_len);
	if (err)
		return err;

	err = search_packidx(&packidx, &idx, repo, &id);
	if (err)
		return err;

	base_offset = get_object_offset(packidx, idx);
	if (base_offset == (uint64_t)-1) {
		return got_error(GOT_ERR_BAD_PACKIDX);
	}

	err = get_packfile_path(&path_base_packfile, repo, packidx);
	if (err)
		return err;

	base_pack = get_cached_pack(path_base_packfile, repo);
	if (base_pack == NULL) {
		err = cache_pack(&base_pack, path_base_packfile, NULL, repo);
		if (err)
			goto done;
	}

	if (fseeko(base_pack->packfile, base_offset, SEEK_SET) != 0) {
		err = got_error_from_errno();
		goto done;
	}

	err = parse_object_type_and_size(&base_type, &base_size, &base_tslen,
	    base_pack->packfile);
	if (err)
		goto done;

	err = resolve_delta_chain(deltas, repo, base_pack->packfile,
	    path_base_packfile, base_offset, base_tslen, base_type,
	    base_size);
done:
	free(path_base_packfile);
	return err;
}

static const struct got_error *
resolve_delta_chain(struct got_delta_chain *deltas, struct got_repository *repo,
    FILE *packfile, const char *path_packfile, off_t delta_offset, size_t tslen,
    int delta_type, size_t delta_size)
{
	const struct got_error *err = NULL;

	switch (delta_type) {
	case GOT_OBJ_TYPE_COMMIT:
	case GOT_OBJ_TYPE_TREE:
	case GOT_OBJ_TYPE_BLOB:
	case GOT_OBJ_TYPE_TAG:
		/* Plain types are the final delta base. Recursion ends. */
		err = add_delta(deltas, path_packfile, delta_offset, tslen,
		    delta_type, delta_size, 0, NULL, 0);
		break;
	case GOT_OBJ_TYPE_OFFSET_DELTA:
		err = resolve_offset_delta(deltas, repo, packfile,
		    path_packfile, delta_offset, tslen, delta_type,
		    delta_size);
		break;
	case GOT_OBJ_TYPE_REF_DELTA:
		err = resolve_ref_delta(deltas, repo, packfile,
		    path_packfile, delta_offset, tslen, delta_type,
		    delta_size);
		break;
	default:
		return got_error(GOT_ERR_NOT_IMPL);
	}

	return err;
}

static const struct got_error *
open_delta_object(struct got_object **obj, struct got_repository *repo,
    struct got_packidx_v2_hdr *packidx, const char *path_packfile,
    FILE *packfile, struct got_object_id *id, off_t offset, size_t tslen,
    int delta_type, size_t delta_size)
{
	const struct got_error *err = NULL;
	int resolved_type;

	*obj = calloc(1, sizeof(**obj));
	if (*obj == NULL)
		return got_error_from_errno();

	(*obj)->flags = 0;
	(*obj)->hdrlen = 0;
	(*obj)->size = 0; /* Not known because deltas aren't applied yet. */
	memcpy(&(*obj)->id, id, sizeof((*obj)->id));
	(*obj)->pack_offset = offset + tslen;

	(*obj)->path_packfile = strdup(path_packfile);
	if ((*obj)->path_packfile == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	(*obj)->flags |= GOT_OBJ_FLAG_PACKED;

	SIMPLEQ_INIT(&(*obj)->deltas.entries);
	(*obj)->flags |= GOT_OBJ_FLAG_DELTIFIED;

	err = resolve_delta_chain(&(*obj)->deltas, repo, packfile,
	    path_packfile, offset, tslen, delta_type, delta_size);
	if (err)
		goto done;

	err = got_delta_chain_get_base_type(&resolved_type, &(*obj)->deltas);
	if (err)
		goto done;
	(*obj)->type = resolved_type;

done:
	if (err) {
		got_object_close(*obj);
		*obj = NULL;
	}
	return err;
}

static const struct got_error *
open_packed_object(struct got_object **obj, struct got_repository *repo,
    struct got_packidx_v2_hdr *packidx, int idx, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	off_t offset;
	char *path_packfile;
	struct got_pack *pack;
	uint8_t type;
	uint64_t size;
	size_t tslen;

	*obj = NULL;

	offset = get_object_offset(packidx, idx);
	if (offset == (uint64_t)-1)
		return got_error(GOT_ERR_BAD_PACKIDX);

	err = get_packfile_path(&path_packfile, repo, packidx);
	if (err)
		return err;

	pack = get_cached_pack(path_packfile, repo);
	if (pack == NULL) {
		err = cache_pack(&pack, path_packfile, packidx, repo);
		if (err)
			goto done;
	}

	if (fseeko(pack->packfile, offset, SEEK_SET) != 0) {
		err = got_error_from_errno();
		goto done;
	}

	err = parse_object_type_and_size(&type, &size, &tslen, pack->packfile);
	if (err)
		goto done;

	switch (type) {
	case GOT_OBJ_TYPE_COMMIT:
	case GOT_OBJ_TYPE_TREE:
	case GOT_OBJ_TYPE_BLOB:
	case GOT_OBJ_TYPE_TAG:
		err = open_plain_object(obj, path_packfile, id, type,
		    offset + tslen, size);
		break;

	case GOT_OBJ_TYPE_OFFSET_DELTA:
	case GOT_OBJ_TYPE_REF_DELTA:
		err = open_delta_object(obj, repo, packidx, path_packfile,
		    pack->packfile, id, offset, tslen, type, size);
		break;

	default:
		err = got_error(GOT_ERR_NOT_IMPL);
		goto done;
	}
done:
	free(path_packfile);
	return err;
}

const struct got_error *
got_packfile_open_object(struct got_object **obj, struct got_object_id *id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_packidx_v2_hdr *packidx = NULL;
	int idx;

	err = search_packidx(&packidx, &idx, repo, id);
	if (err)
		return err;

	err = open_packed_object(obj, repo, packidx, idx, id);
	if (err)
		return err;

	err = cache_pack(NULL, (*obj)->path_packfile, packidx, repo);
	return err;
}

static const struct got_error *
get_delta_chain_max_size(uint64_t *max_size, struct got_delta_chain *deltas)
{
	struct got_delta *delta;
	uint64_t base_size = 0, result_size = 0;

	*max_size = 0;
	SIMPLEQ_FOREACH(delta, &deltas->entries, entry) {
		/* Plain object types are the delta base. */
		if (delta->type != GOT_OBJ_TYPE_COMMIT &&
		    delta->type != GOT_OBJ_TYPE_TREE &&
		    delta->type != GOT_OBJ_TYPE_BLOB &&
		    delta->type != GOT_OBJ_TYPE_TAG) {
			const struct got_error *err;
			err = got_delta_get_sizes(&base_size, &result_size,
			    delta->delta_buf, delta->delta_len);
			if (err)
				return err;
		} else
			base_size = delta->size;
		if (base_size > *max_size)
			*max_size = base_size;
		if (result_size > *max_size)
			*max_size = result_size;
	}

	return NULL;
}

static const struct got_error *
dump_delta_chain_to_file(size_t *result_size, struct got_delta_chain *deltas,
    FILE *outfile, struct got_pack *pack, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_delta *delta;
	FILE *base_file = NULL, *accum_file = NULL;
	uint8_t *base_buf = NULL, *accum_buf = NULL;
	size_t accum_size = 0;
	uint64_t max_size;
	int n = 0;

	*result_size = 0;

	if (SIMPLEQ_EMPTY(&deltas->entries))
		return got_error(GOT_ERR_BAD_DELTA_CHAIN);

	/* We process small enough files entirely in memory for speed. */
	err = get_delta_chain_max_size(&max_size, deltas);
	if (err)
		return err;
	if (max_size < GOT_DELTA_RESULT_SIZE_CACHED_MAX) {
		accum_buf = malloc(max_size);
		if (accum_buf == NULL)
			return got_error_from_errno();
	} else {
		base_file = got_opentemp();
		if (base_file == NULL)
			return got_error_from_errno();

		accum_file = got_opentemp();
		if (accum_file == NULL) {
			err = got_error_from_errno();
			fclose(base_file);
			return err;
		}
	}

	/* Deltas are ordered in ascending order. */
	SIMPLEQ_FOREACH(delta, &deltas->entries, entry) {
		if (n == 0) {
			size_t base_len;

			/* Plain object types are the delta base. */
			if (delta->type != GOT_OBJ_TYPE_COMMIT &&
			    delta->type != GOT_OBJ_TYPE_TREE &&
			    delta->type != GOT_OBJ_TYPE_BLOB &&
			    delta->type != GOT_OBJ_TYPE_TAG) {
				err = got_error(GOT_ERR_BAD_DELTA_CHAIN);
				goto done;
			}

			if (fseeko(pack->packfile, delta->offset + delta->tslen,
			    SEEK_SET) != 0) {
				err = got_error_from_errno();
				goto done;
			}
			if (base_file)
				err = got_inflate_to_file(&base_len,
				    pack->packfile, base_file);
			else {
				err = got_inflate_to_mem(&base_buf, &base_len,
				    pack->packfile);
				if (base_len < max_size) {
					uint8_t *p;
					p = reallocarray(base_buf, 1, max_size);
					if (p == NULL) {
						err = got_error_from_errno();
						goto done;
					}
					base_buf = p;
				}
			}
			if (err)
				goto done;
			n++;
			if (base_file)
				rewind(base_file);
			continue;
		}

		if (base_buf) {
			err = got_delta_apply_in_mem(base_buf, delta->delta_buf,
			    delta->delta_len, accum_buf, &accum_size);
			n++;
		} else {
			err = got_delta_apply(base_file, delta->delta_buf,
			    delta->delta_len,
			    /* Final delta application writes to output file. */
			    ++n < deltas->nentries ? accum_file : outfile,
			    &accum_size);
		}
		if (err)
			goto done;

		if (n < deltas->nentries) {
			/* Accumulated delta becomes the new base. */
			if (base_buf) {
				uint8_t *tmp = accum_buf;
				accum_buf = base_buf;
				base_buf = tmp;
			} else {
				FILE *tmp = accum_file;
				accum_file = base_file;
				base_file = tmp;
				rewind(base_file);
				rewind(accum_file);
			}
		}
	}

done:
	free(base_buf);
	if (accum_buf) {
		size_t len = fwrite(accum_buf, 1, accum_size, outfile);
		free(accum_buf);
		if (len != accum_size)
			return got_ferror(outfile, GOT_ERR_IO);
	}
	if (base_file)
		fclose(base_file);
	if (accum_file)
		fclose(accum_file);
	rewind(outfile);
	if (err == NULL)
		*result_size = accum_size;
	return err;
}

static const struct got_error *
dump_delta_chain_to_mem(uint8_t **outbuf, size_t *outlen,
    struct got_delta_chain *deltas, struct got_pack *pack,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_delta *delta;
	uint8_t *base_buf = NULL, *accum_buf = NULL;
	size_t accum_size;
	uint64_t max_size;
	int n = 0;

	*outbuf = NULL;
	*outlen = 0;

	if (SIMPLEQ_EMPTY(&deltas->entries))
		return got_error(GOT_ERR_BAD_DELTA_CHAIN);

	err = get_delta_chain_max_size(&max_size, deltas);
	if (err)
		return err;
	accum_buf = malloc(max_size);
	if (accum_buf == NULL)
		return got_error_from_errno();

	/* Deltas are ordered in ascending order. */
	SIMPLEQ_FOREACH(delta, &deltas->entries, entry) {
		if (n == 0) {
			size_t base_len;

			/* Plain object types are the delta base. */
			if (delta->type != GOT_OBJ_TYPE_COMMIT &&
			    delta->type != GOT_OBJ_TYPE_TREE &&
			    delta->type != GOT_OBJ_TYPE_BLOB &&
			    delta->type != GOT_OBJ_TYPE_TAG) {
				err = got_error(GOT_ERR_BAD_DELTA_CHAIN);
				goto done;
			}

			if (fseeko(pack->packfile, delta->offset + delta->tslen,
			    SEEK_SET) != 0) {
				err = got_error_from_errno();
				goto done;
			}
			err = got_inflate_to_mem(&base_buf, &base_len,
			    pack->packfile);
			if (base_len < max_size) {
				uint8_t *p;
				p = reallocarray(base_buf, 1, max_size);
				if (p == NULL) {
					err = got_error_from_errno();
					goto done;
				}
				base_buf = p;
			}
			if (err)
				goto done;
			n++;
			continue;
		}

		err = got_delta_apply_in_mem(base_buf, delta->delta_buf,
		    delta->delta_len, accum_buf, &accum_size);
		n++;
		if (err)
			goto done;

		if (n < deltas->nentries) {
			/* Accumulated delta becomes the new base. */
			uint8_t *tmp = accum_buf;
			accum_buf = base_buf;
			base_buf = tmp;
		}
	}

done:
	free(base_buf);
	if (err) {
		free(accum_buf);
		*outbuf = NULL;
		*outlen = 0;
	} else {
		*outbuf = accum_buf;
		*outlen = accum_size;
	}
	return err;
}

const struct got_error *
got_packfile_extract_object(FILE **f, struct got_object *obj,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_pack *pack;

	if ((obj->flags & GOT_OBJ_FLAG_PACKED) == 0)
		return got_error(GOT_ERR_OBJ_NOT_PACKED);

	pack = get_cached_pack(obj->path_packfile, repo);
	if (pack == NULL) {
		err = cache_pack(&pack, obj->path_packfile, NULL, repo);
		if (err)
			goto done;
	}

	*f = got_opentemp();
	if (*f == NULL) {
		err = got_error(GOT_ERR_FILE_OPEN);
		goto done;
	}

	if ((obj->flags & GOT_OBJ_FLAG_DELTIFIED) == 0) {
		if (fseeko(pack->packfile, obj->pack_offset, SEEK_SET) != 0) {
			err = got_error_from_errno();
			goto done;
		}
		err = got_inflate_to_file(&obj->size, pack->packfile, *f);
	} else
		err = dump_delta_chain_to_file(&obj->size, &obj->deltas, *f,
		    pack, repo);
done:
	if (err && *f) {
		fclose(*f);
		*f = NULL;
	}
	return err;
}

const struct got_error *
got_packfile_extract_object_to_mem(uint8_t **buf, size_t *len,
    struct got_object *obj, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	FILE *packfile = NULL;
	struct got_pack *pack;

	if ((obj->flags & GOT_OBJ_FLAG_PACKED) == 0)
		return got_error(GOT_ERR_OBJ_NOT_PACKED);

	pack = get_cached_pack(obj->path_packfile, repo);
	if (pack == NULL) {
		err = cache_pack(&pack, obj->path_packfile, NULL, repo);
		if (err)
			goto done;
	}

	if ((obj->flags & GOT_OBJ_FLAG_DELTIFIED) == 0) {
		if (fseeko(pack->packfile, obj->pack_offset, SEEK_SET) != 0) {
			err = got_error_from_errno();
			goto done;
		}

		err = got_inflate_to_mem(buf, len, pack->packfile);
	} else
		err = dump_delta_chain_to_mem(buf, len, &obj->deltas, pack,
		    repo);
done:
	if (packfile)
		fclose(packfile);
	return err;
}
