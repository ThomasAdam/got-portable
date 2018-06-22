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
#include "got_opentemp.h"

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
get_packfile_size(size_t *size, const char *path)
{
	struct stat sb;
	char *dot;

	*size = 0;

	dot = strrchr(path, '.');
	if (dot == NULL)
		return got_error(GOT_ERR_BAD_PATH);

	/* Path must point to a pack index or to a pack file. */
	if (strcmp(dot, GOT_PACKIDX_SUFFIX) == 0) {
		const struct got_error *err = NULL;
		char *path_pack;
		char base_path[PATH_MAX];

		/* Convert pack index path to pack file path. */
		if (strlcpy(base_path, path, PATH_MAX) > PATH_MAX)
			return got_error(GOT_ERR_NO_SPACE);
		dot = strrchr(base_path, '.');
		if (dot == NULL)
			return got_error(GOT_ERR_BAD_PATH);
		*dot = '\0';
		if (asprintf(&path_pack, "%s.pack", base_path) == -1)
			return got_error_from_errno();

		if (stat(path_pack, &sb) != 0)
			err = got_error_from_errno();
		free(path_pack);
		if (err)
			return err;
	} else if (strcmp(dot, GOT_PACKFILE_SUFFIX) == 0) {
		if (stat(path, &sb) != 0)
			return got_error_from_errno();
	} else
		return got_error(GOT_ERR_BAD_PATH);

	*size = sb.st_size;
	return 0;
}

const struct got_error *
got_packidx_open(struct got_packidx **packidx, const char *path)
{
	struct got_packidx *p;
	struct got_packidx_v2_hdr *h;
	FILE *f;
	const struct got_error *err = NULL;
	size_t n, nobj, packfile_size;
	SHA1_CTX ctx;
	uint8_t sha1[SHA1_DIGEST_LENGTH];

	*packidx = NULL;

	SHA1Init(&ctx);

	f = fopen(path, "rb");
	if (f == NULL)
		return got_error_from_errno();

	err = get_packfile_size(&packfile_size, path);
	if (err)
		return err;

	p = calloc(1, sizeof(*p));
	if (p == NULL)
		return got_error_from_errno();
	p->path_packidx = strdup(path);
	if (p->path_packidx == NULL) {
		err = got_error_from_errno();
		free(p->path_packidx);
		free(p);
		return err;
	}

	h = &p->hdr;
	n = fread(&h->magic, sizeof(h->magic), 1, f);
	if (n != 1) {
		err = got_ferror(f, GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	if (betoh32(h->magic) != GOT_PACKIDX_V2_MAGIC) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t *)&h->magic, sizeof(h->magic));

	n = fread(&h->version, sizeof(h->version), 1, f);
	if (n != 1) {
		err = got_ferror(f, GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	if (betoh32(h->version) != GOT_PACKIDX_VERSION) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t *)&h->version, sizeof(h->version));

	n = fread(&h->fanout_table, sizeof(h->fanout_table), 1, f);
	if (n != 1) {
		err = got_ferror(f, GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	err = verify_fanout_table(h->fanout_table);
	if (err)
		goto done;

	SHA1Update(&ctx, (uint8_t *)h->fanout_table, sizeof(h->fanout_table));

	nobj = betoh32(h->fanout_table[0xff]);

	h->sorted_ids = calloc(nobj, sizeof(*h->sorted_ids));
	if (h->sorted_ids == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	n = fread(h->sorted_ids, sizeof(*h->sorted_ids), nobj, f);
	if (n != nobj) {
		err = got_ferror(f, GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t *)h->sorted_ids,
	    nobj * sizeof(*h->sorted_ids));

	h->crc32 = calloc(nobj, sizeof(*h->crc32));
	if (h->crc32 == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	n = fread(h->crc32, sizeof(*h->crc32), nobj, f);
	if (n != nobj) {
		err = got_ferror(f, GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t *)h->crc32, nobj * sizeof(*h->crc32));

	h->offsets = calloc(nobj, sizeof(*h->offsets));
	if (h->offsets == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	n = fread(h->offsets, sizeof(*h->offsets), nobj, f);
	if (n != nobj) {
		err = got_ferror(f, GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t *)h->offsets, nobj * sizeof(*h->offsets));

	/* Large file offsets are contained only in files > 2GB. */
	if (packfile_size <= 0x80000000)
		goto checksum;

	h->large_offsets = calloc(nobj, sizeof(*h->large_offsets));
	if (h->large_offsets == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	n = fread(h->large_offsets, sizeof(*h->large_offsets), nobj, f);
	if (n != nobj) {
		err = got_ferror(f, GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, (uint8_t*)h->large_offsets,
	    nobj * sizeof(*h->large_offsets));

checksum:
	n = fread(&h->trailer, sizeof(h->trailer), 1, f);
	if (n != 1) {
		err = got_ferror(f, GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	SHA1Update(&ctx, h->trailer.packfile_sha1, SHA1_DIGEST_LENGTH);
	SHA1Final(sha1, &ctx);
	if (memcmp(h->trailer.packidx_sha1, sha1, SHA1_DIGEST_LENGTH) != 0)
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
got_packidx_close(struct got_packidx *packidx)
{
	free(packidx->hdr.sorted_ids);
	free(packidx->hdr.offsets);
	free(packidx->hdr.crc32);
	free(packidx->hdr.large_offsets);
	free(packidx->path_packidx);
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
get_object_offset(struct got_packidx *packidx, int idx)
{
	uint32_t totobj = betoh32(packidx->hdr.fanout_table[0xff]);
	uint32_t offset = betoh32(packidx->hdr.offsets[idx]);
	if (offset & GOT_PACKIDX_OFFSET_VAL_IS_LARGE_IDX) {
		uint64_t loffset;
		idx = offset & GOT_PACKIDX_OFFSET_VAL_MASK;
		if (idx < 0 || idx > totobj ||
		    packidx->hdr.large_offsets == NULL)
			return -1;
		loffset = betoh64(packidx->hdr.large_offsets[idx]);
		return (loffset > INT64_MAX ? -1 : (off_t)loffset);
	}
	return (off_t)(offset & GOT_PACKIDX_OFFSET_VAL_MASK);
}

static int
get_object_idx(struct got_packidx *packidx, struct got_object_id *id,
    struct got_repository *repo)
{
	u_int8_t id0 = id->sha1[0];
	uint32_t totobj = betoh32(packidx->hdr.fanout_table[0xff]);
	int left = 0, right = totobj - 1;

	if (id0 > 0)
		left = betoh32(packidx->hdr.fanout_table[id0 - 1]);

	while (left <= right) {
		struct got_object_id *oid;
		int i, cmp;

		i = ((left + right) / 2);
		oid = &packidx->hdr.sorted_ids[i];
		cmp = got_object_id_cmp(id, oid);
		if (cmp == 0)
			return i;
		else if (cmp > 0)
			left = i + 1;
		else if (cmp < 0)
			right = i - 1;
	}

	return -1;
}

static struct got_packidx *
dup_packidx(struct got_packidx *packidx)
{
	struct got_packidx *p;
	size_t nobj;

	p = calloc(1, sizeof(*p));
	if (p == NULL)
		return NULL;

	p->path_packidx = strdup(packidx->path_packidx);
	if (p->path_packidx == NULL) {
		free(p);
		return NULL;
	}
	memcpy(&p->hdr, &packidx->hdr, sizeof(p->hdr));
	p->hdr.sorted_ids = NULL;
	p->hdr.crc32 = NULL;
	p->hdr.offsets = NULL;
	p->hdr.large_offsets = NULL;

	nobj = betoh32(p->hdr.fanout_table[0xff]);

	p->hdr.sorted_ids = calloc(nobj, sizeof(*p->hdr.sorted_ids));
	if (p->hdr.sorted_ids == NULL)
		goto err;
	memcpy(p->hdr.sorted_ids, packidx->hdr.sorted_ids,
	    nobj * sizeof(*p->hdr.sorted_ids));

	p->hdr.crc32 = calloc(nobj, sizeof(*p->hdr.crc32));
	if (p->hdr.crc32 == NULL)
		goto err;
	memcpy(p->hdr.crc32, packidx->hdr.crc32, nobj * sizeof(*p->hdr.crc32));

	p->hdr.offsets = calloc(nobj, sizeof(*p->hdr.offsets));
	if (p->hdr.offsets == NULL)
		goto err;
	memcpy(p->hdr.offsets, packidx->hdr.offsets,
	    nobj * sizeof(*p->hdr.offsets));

	if (p->hdr.large_offsets) {
		p->hdr.large_offsets = calloc(nobj,
		    sizeof(*p->hdr.large_offsets));
		if (p->hdr.large_offsets == NULL)
			goto err;
		memcpy(p->hdr.large_offsets, packidx->hdr.large_offsets,
		    nobj * sizeof(*p->hdr.large_offsets));
	}

	return p;

err:
	free(p->hdr.large_offsets);
	free(p->hdr.offsets);
	free(p->hdr.crc32);
	free(p->hdr.sorted_ids);
	free(p->path_packidx);
	free(p);
	return NULL;
}

static void
cache_packidx(struct got_packidx *packidx, struct got_repository *repo)
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
search_packidx(struct got_packidx **packidx, int *idx,
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
		*idx = get_object_idx(repo->packidx_cache[i], id, repo);
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

		*idx = get_object_idx(*packidx, id, repo);
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
    struct got_packidx *packidx)
{
	size_t size;

	/* Packfile path contains ".pack" instead of ".idx", so add one byte. */
	size = strlen(packidx->path_packidx) + 2;
	if (size < GOT_PACKFILE_NAMELEN + 1)
		return got_error(GOT_ERR_BAD_PATH);

	*path_packfile = calloc(size, sizeof(**path_packfile));
	if (*path_packfile == NULL)
		return got_error_from_errno();

	/* Copy up to and excluding ".idx". */
	if (strlcpy(*path_packfile, packidx->path_packidx,
	    size - strlen(GOT_PACKIDX_SUFFIX) - 1) >= size)
		return got_error(GOT_ERR_NO_SPACE);

	if (strlcat(*path_packfile, GOT_PACKFILE_SUFFIX, size) >= size)
		return got_error(GOT_ERR_NO_SPACE);

	return NULL;
}

const struct got_error *
read_packfile_hdr(int fd, struct got_packidx *packidx)
{
	const struct got_error *err = NULL;
	uint32_t totobj = betoh32(packidx->hdr.fanout_table[0xff]);
	struct got_packfile_hdr hdr;
	ssize_t n;

	n = read(fd, &hdr, sizeof(hdr));
	if (n < 0)
		return got_error_from_errno();
	if (n != sizeof(hdr))
		return got_error(GOT_ERR_BAD_PACKFILE);

	if (betoh32(hdr.signature) != GOT_PACKFILE_SIGNATURE ||
	    betoh32(hdr.version) != GOT_PACKFILE_VERSION ||
	    betoh32(hdr.nobjects) != totobj)
		err = got_error(GOT_ERR_BAD_PACKFILE);

	return err;
}

static const struct got_error *
open_packfile(int *fd, const char *path_packfile,
    struct got_repository *repo, struct got_packidx *packidx)
{
	const struct got_error *err = NULL;

	*fd = open(path_packfile, O_RDONLY | O_NOFOLLOW, GOT_DEFAULT_FILE_MODE);
	if (*fd == -1)
		return got_error_from_errno();

	if (packidx) {
		err = read_packfile_hdr(*fd, packidx);
		if (err) {
			close(*fd);
			*fd = -1;
		}
	}
	return err;
}

void
got_pack_close(struct got_pack *pack)
{
	close(pack->fd);
	pack->fd = -1;
	free(pack->path_packfile);
	pack->path_packfile = NULL;
	pack->filesize = 0;
}

static const struct got_error *
cache_pack(struct got_pack **packp, const char *path_packfile,
    struct got_packidx *packidx, struct got_repository *repo)
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

	err = open_packfile(&pack->fd, path_packfile, repo, packidx);
	if (err)
		goto done;

	err = get_packfile_size(&pack->filesize, path_packfile);
done:
	if (err) {
		if (pack) {
			free(pack->path_packfile);
			memset(pack, 0, sizeof(*pack));
		}
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
parse_object_type_and_size(uint8_t *type, uint64_t *size, size_t *len, int fd)
{
	uint8_t t = 0;
	uint64_t s = 0;
	uint8_t sizeN;
	ssize_t n;
	int i = 0;

	do {
		/* We do not support size values which don't fit in 64 bit. */
		if (i > 9)
			return got_error(GOT_ERR_NO_SPACE);

		n = read(fd, &sizeN, sizeof(sizeN));
		if (n < 0)
			return got_error_from_errno();
		if (n != sizeof(sizeN))
			return got_error(GOT_ERR_BAD_PACKFILE);

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
parse_negative_offset(int64_t *offset, size_t *len, int fd)
{
	int64_t o = 0;
	uint8_t offN;
	ssize_t n;
	int i = 0;

	do {
		/* We do not support offset values which don't fit in 64 bit. */
		if (i > 8)
			return got_error(GOT_ERR_NO_SPACE);

		n = read(fd, &offN, sizeof(offN));
		if (n < 0)
			return got_error_from_errno();
		if (n != sizeof(offN))
			return got_error(GOT_ERR_BAD_PACKFILE);

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
parse_offset_delta(off_t *base_offset, int fd, off_t offset)
{
	const struct got_error *err;
	int64_t negoffset;
	size_t negofflen;

	err = parse_negative_offset(&negoffset, &negofflen, fd);
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
    int, size_t, const char *, off_t, size_t, int, size_t, unsigned int);

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
    struct got_repository *repo, int fd, size_t packfile_size,
    const char *path_packfile, off_t delta_offset, size_t tslen,
    int delta_type, size_t delta_size, unsigned int recursion)

{
	const struct got_error *err;
	off_t base_offset;
	uint8_t base_type;
	uint64_t base_size;
	size_t base_tslen;
	off_t delta_data_offset;
	uint8_t *delta_buf;
	size_t delta_len;

	err = parse_offset_delta(&base_offset, fd, delta_offset);
	if (err)
		return err;

	delta_data_offset = lseek(fd, 0, SEEK_CUR);
	if (delta_data_offset == -1)
		return got_error_from_errno();

	err = got_inflate_to_mem_fd(&delta_buf, &delta_len, fd);
	if (err)
		return err;

	err = add_delta(deltas, path_packfile, delta_offset, tslen,
	    delta_type, delta_size, delta_data_offset, delta_buf, delta_len);
	if (err)
		return err;

	/* An offset delta must be in the same packfile. */
	if (base_offset >= packfile_size)
		return got_error(GOT_ERR_PACK_OFFSET);
	if (lseek(fd, base_offset, SEEK_SET) == -1)
		return got_error_from_errno();

	err = parse_object_type_and_size(&base_type, &base_size, &base_tslen,
	    fd);
	if (err)
		return err;

	return resolve_delta_chain(deltas, repo, fd, packfile_size,
	    path_packfile, base_offset, base_tslen, base_type, base_size,
	    recursion - 1);
}

static const struct got_error *
resolve_ref_delta(struct got_delta_chain *deltas, struct got_repository *repo,
    int fd, const char *path_packfile, off_t delta_offset,
    size_t tslen, int delta_type, size_t delta_size, unsigned int recursion)
{
	const struct got_error *err;
	struct got_object_id id;
	struct got_packidx *packidx;
	int idx;
	off_t base_offset;
	uint8_t base_type;
	uint64_t base_size;
	size_t base_tslen;
	ssize_t n;
	char *path_base_packfile;
	struct got_pack *base_pack;
	off_t delta_data_offset;
	uint8_t *delta_buf;
	size_t delta_len;

	n = read(fd, &id, sizeof(id));
	if (n < 0)
		return got_error_from_errno();
	if (n != sizeof(id))
		return got_error(GOT_ERR_BAD_PACKFILE);

	delta_data_offset = lseek(fd, 0, SEEK_CUR);
	if (delta_data_offset == -1)
		return got_error_from_errno();

	err = got_inflate_to_mem_fd(&delta_buf, &delta_len, fd);
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

	if (base_offset >= base_pack->filesize) {
		err = got_error(GOT_ERR_PACK_OFFSET);
		goto done;
	}
	if (lseek(base_pack->fd, base_offset, SEEK_SET) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	err = parse_object_type_and_size(&base_type, &base_size, &base_tslen,
	    base_pack->fd);
	if (err)
		goto done;

	err = resolve_delta_chain(deltas, repo, base_pack->fd,
	    base_pack->filesize, path_base_packfile, base_offset,
	    base_tslen, base_type, base_size, recursion - 1);
done:
	free(path_base_packfile);
	return err;
}

static const struct got_error *
resolve_delta_chain(struct got_delta_chain *deltas, struct got_repository *repo,
    int fd, size_t packfile_size, const char *path_packfile, off_t delta_offset,
    size_t tslen, int delta_type, size_t delta_size, unsigned int recursion)
{
	const struct got_error *err = NULL;

	if (--recursion == 0)
		return got_error(GOT_ERR_RECURSION);

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
		err = resolve_offset_delta(deltas, repo, fd, packfile_size,
		    path_packfile, delta_offset, tslen, delta_type, delta_size,
		    recursion - 1);
		break;
	case GOT_OBJ_TYPE_REF_DELTA:
		err = resolve_ref_delta(deltas, repo, fd, path_packfile,
		    delta_offset, tslen, delta_type, delta_size, recursion - 1);
		break;
	default:
		return got_error(GOT_ERR_OBJ_TYPE);
	}

	return err;
}

static const struct got_error *
open_delta_object(struct got_object **obj, struct got_repository *repo,
    const char *path_packfile, int fd, size_t packfile_size,
    struct got_object_id *id, off_t offset, size_t tslen,
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

	err = resolve_delta_chain(&(*obj)->deltas, repo, fd, packfile_size,
	    path_packfile, offset, tslen, delta_type, delta_size,
	    GOT_DELTA_CHAIN_RECURSION_MAX);
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
    struct got_packidx *packidx, int idx, struct got_object_id *id)
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

	if (offset >= pack->filesize) {
		err = got_error(GOT_ERR_PACK_OFFSET);
		goto done;
	}
	if (lseek(pack->fd, offset, SEEK_SET) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	err = parse_object_type_and_size(&type, &size, &tslen, pack->fd);
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
		err = open_delta_object(obj, repo, path_packfile, pack->fd,
		    pack->filesize, id, offset, tslen, type, size);
		break;

	default:
		err = got_error(GOT_ERR_OBJ_TYPE);
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
	struct got_packidx *packidx = NULL;
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
    FILE *outfile, struct got_repository *repo)
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
			struct got_pack *pack;
			size_t base_len;
			off_t delta_data_offset;

			/* Plain object types are the delta base. */
			if (delta->type != GOT_OBJ_TYPE_COMMIT &&
			    delta->type != GOT_OBJ_TYPE_TREE &&
			    delta->type != GOT_OBJ_TYPE_BLOB &&
			    delta->type != GOT_OBJ_TYPE_TAG) {
				err = got_error(GOT_ERR_BAD_DELTA_CHAIN);
				goto done;
			}

			pack = get_cached_pack(delta->path_packfile, repo);
			if (pack == NULL) {
				err = got_error(GOT_ERR_BAD_DELTA_CHAIN);
				goto done;
			}

			delta_data_offset = delta->offset + delta->tslen;
			if (delta_data_offset >= pack->filesize) {
				err = got_error(GOT_ERR_PACK_OFFSET);
				goto done;
			}
			if (lseek(pack->fd, delta_data_offset, SEEK_SET) == -1) {
				err = got_error_from_errno();
				goto done;
			}
			if (base_file)
				err = got_inflate_to_file_fd(&base_len,
				    pack->fd, base_file);
			else {
				err = got_inflate_to_mem_fd(&base_buf,
				    &base_len, pack->fd);
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
    struct got_delta_chain *deltas, struct got_repository *repo)
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
			struct got_pack *pack;
			size_t base_len;
			size_t delta_data_offset;

			/* Plain object types are the delta base. */
			if (delta->type != GOT_OBJ_TYPE_COMMIT &&
			    delta->type != GOT_OBJ_TYPE_TREE &&
			    delta->type != GOT_OBJ_TYPE_BLOB &&
			    delta->type != GOT_OBJ_TYPE_TAG) {
				err = got_error(GOT_ERR_BAD_DELTA_CHAIN);
				goto done;
			}

			pack = get_cached_pack(delta->path_packfile, repo);
			if (pack == NULL) {
				err = got_error(GOT_ERR_BAD_DELTA_CHAIN);
				goto done;
			}

			delta_data_offset = delta->offset + delta->tslen;
			if (delta_data_offset >= pack->filesize) {
				err = got_error(GOT_ERR_PACK_OFFSET);
				goto done;
			}
			if (lseek(pack->fd, delta_data_offset, SEEK_SET) == -1) {
				err = got_error_from_errno();
				goto done;
			}
			err = got_inflate_to_mem_fd(&base_buf, &base_len,
			    pack->fd);
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

	*f = NULL;

	if ((obj->flags & GOT_OBJ_FLAG_PACKED) == 0)
		return got_error(GOT_ERR_OBJ_NOT_PACKED);

	*f = got_opentemp();
	if (*f == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	if ((obj->flags & GOT_OBJ_FLAG_DELTIFIED) == 0) {
		struct got_pack *pack;

		pack = get_cached_pack(obj->path_packfile, repo);
		if (pack == NULL) {
			err = cache_pack(&pack, obj->path_packfile, NULL, repo);
			if (err)
				goto done;
		}

		if (obj->pack_offset >= pack->filesize) {
			err = got_error(GOT_ERR_PACK_OFFSET);
			goto done;
		}
		if (lseek(pack->fd, obj->pack_offset, SEEK_SET) == -1) {
			err = got_error_from_errno();
			goto done;
		}

		err = got_inflate_to_file_fd(&obj->size, pack->fd, *f);
	} else
		err = dump_delta_chain_to_file(&obj->size,
		    &obj->deltas, *f, repo);
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

	if ((obj->flags & GOT_OBJ_FLAG_PACKED) == 0)
		return got_error(GOT_ERR_OBJ_NOT_PACKED);

	if ((obj->flags & GOT_OBJ_FLAG_DELTIFIED) == 0) {
		struct got_pack *pack;

		pack = get_cached_pack(obj->path_packfile, repo);
		if (pack == NULL) {
			err = cache_pack(&pack, obj->path_packfile, NULL, repo);
			if (err)
				goto done;
		}

		if (obj->pack_offset >= pack->filesize) {
			err = got_error(GOT_ERR_PACK_OFFSET);
			goto done;
		}
		if (lseek(pack->fd, obj->pack_offset, SEEK_SET) == -1) {
			err = got_error_from_errno();
			goto done;
		}

		err = got_inflate_to_mem_fd(buf, len, pack->fd);
	} else
		err = dump_delta_chain_to_mem(buf, len, &obj->deltas, repo);
done:
	return err;
}
