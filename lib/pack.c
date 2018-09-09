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
#include <sys/mman.h>

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
#include "got_lib_inflate.h"
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
got_packidx_init_hdr(struct got_packidx *p, int verify)
{
	const struct got_error *err = NULL;
	struct got_packidx_v2_hdr *h;
	SHA1_CTX ctx;
	uint8_t sha1[SHA1_DIGEST_LENGTH];
	size_t nobj, len_fanout, len_ids, offset, remain;
	ssize_t n;

	SHA1Init(&ctx);

	h = &p->hdr;
	offset = 0;
	remain = p->len;

	if (remain < sizeof(*h->magic)) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	if (p->map)
		h->magic = (uint32_t *)(p->map + offset);
	else {
		h->magic = malloc(sizeof(*h->magic));
		if (h->magic == NULL) {
			err = got_error_from_errno();
			goto done;
		}
		n = read(p->fd, h->magic, sizeof(*h->magic));
		if (n != sizeof(*h->magic)) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
	}
	if (betoh32(*h->magic) != GOT_PACKIDX_V2_MAGIC) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	offset += sizeof(*h->magic);
	remain -= sizeof(*h->magic);

	if (verify)
		SHA1Update(&ctx, (uint8_t *)h->magic, sizeof(*h->magic));

	if (remain < sizeof(*h->version)) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	if (p->map)
		h->version = (uint32_t *)(p->map + offset);
	else {
		h->version = malloc(sizeof(*h->version));
		if (h->version == NULL) {
			err = got_error_from_errno();
			goto done;
		}
		n = read(p->fd, h->version, sizeof(*h->version));
		if (n != sizeof(*h->version)) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
	}
	if (betoh32(*h->version) != GOT_PACKIDX_VERSION) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	offset += sizeof(*h->version);
	remain -= sizeof(*h->version);

	if (verify)
		SHA1Update(&ctx, (uint8_t *)h->version, sizeof(*h->version));

	len_fanout =
	    sizeof(*h->fanout_table) * GOT_PACKIDX_V2_FANOUT_TABLE_ITEMS;
	if (remain < len_fanout) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	if (p->map)
		h->fanout_table = (uint32_t *)(p->map + offset);
	else {
		h->fanout_table = malloc(len_fanout);
		if (h->fanout_table == NULL) {
			err = got_error_from_errno();
			goto done;
		}
		n = read(p->fd, h->fanout_table, len_fanout);
		if (n != len_fanout) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
	}
	err = verify_fanout_table(h->fanout_table);
	if (err)
		goto done;
	if (verify)
		SHA1Update(&ctx, (uint8_t *)h->fanout_table, len_fanout);
	offset += len_fanout;
	remain -= len_fanout;

	nobj = betoh32(h->fanout_table[0xff]);
	len_ids = nobj * sizeof(*h->sorted_ids);
	if (len_ids <= nobj || len_ids > remain) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	if (p->map)
		h->sorted_ids =
		    (struct got_packidx_object_id *)((uint8_t*)(p->map + offset));
	else {
		h->sorted_ids = malloc(len_ids);
		if (h->sorted_ids == NULL) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
		n = read(p->fd, h->sorted_ids, len_ids);
		if (n != len_ids) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
	}
	if (verify)
		SHA1Update(&ctx, (uint8_t *)h->sorted_ids, len_ids);
	offset += len_ids;
	remain -= len_ids;

	if (remain < nobj * sizeof(*h->crc32)) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	if (p->map)
		h->crc32 = (uint32_t *)((uint8_t*)(p->map + offset));
	else {
		h->crc32 = malloc(nobj * sizeof(*h->crc32));
		if (h->crc32 == NULL) {
			err = got_error_from_errno();
			goto done;
		}
		n = read(p->fd, h->crc32, nobj * sizeof(*h->crc32));
		if (n != nobj * sizeof(*h->crc32)) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
	}
	if (verify)
		SHA1Update(&ctx, (uint8_t *)h->crc32, nobj * sizeof(*h->crc32));
	remain -= nobj * sizeof(*h->crc32);
	offset += nobj * sizeof(*h->crc32);

	if (remain < nobj * sizeof(*h->offsets)) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	if (p->map)
		h->offsets = (uint32_t *)((uint8_t*)(p->map + offset));
	else {
		h->offsets = malloc(nobj * sizeof(*h->offsets));
		if (h->offsets == NULL) {
			err = got_error_from_errno();
			goto done;
		}
		n = read(p->fd, h->offsets, nobj * sizeof(*h->offsets));
		if (n != nobj * sizeof(*h->offsets)) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
	}
	if (verify)
		SHA1Update(&ctx, (uint8_t *)h->offsets,
		    nobj * sizeof(*h->offsets));
	remain -= nobj * sizeof(*h->offsets);
	offset += nobj * sizeof(*h->offsets);

	/* Large file offsets are contained only in files > 2GB. */
	if (p->len <= 0x80000000)
		goto checksum;

	if (remain < nobj * sizeof(*h->large_offsets)) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	if (p->map)
		h->large_offsets = (uint64_t *)((uint8_t*)(p->map + offset));
	else {
		h->offsets = malloc(nobj * sizeof(*h->large_offsets));
		if (h->offsets == NULL) {
			err = got_error_from_errno();
			goto done;
		}
		n = read(p->fd, h->large_offsets,
		    nobj * sizeof(*h->large_offsets));
		if (n != nobj * sizeof(*h->large_offsets)) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
	}
	if (verify)
		SHA1Update(&ctx, (uint8_t*)h->large_offsets,
		    nobj * sizeof(*h->large_offsets));
	remain -= nobj * sizeof(*h->large_offsets);
	offset += nobj * sizeof(*h->large_offsets);

checksum:
	if (remain < sizeof(*h->trailer)) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}
	if (p->map)
		h->trailer =
		    (struct got_packidx_trailer *)((uint8_t*)(p->map + offset));
	else {
		h->trailer = malloc(sizeof(*h->trailer));
		if (h->trailer == NULL) {
			err = got_error_from_errno();
			goto done;
		}
		n = read(p->fd, h->trailer, sizeof(*h->trailer));
		if (n != sizeof(*h->trailer)) {
			err = got_error(GOT_ERR_BAD_PACKIDX);
			goto done;
		}
	}
	if (verify) {
		SHA1Update(&ctx, h->trailer->packfile_sha1, SHA1_DIGEST_LENGTH);
		SHA1Final(sha1, &ctx);
		if (memcmp(h->trailer->packidx_sha1, sha1,
		    SHA1_DIGEST_LENGTH) != 0)
			err = got_error(GOT_ERR_PACKIDX_CSUM);
	}
done:
	return err;
}

const struct got_error *
got_packidx_open(struct got_packidx **packidx, const char *path, int verify)
{
	const struct got_error *err = NULL;
	struct got_packidx *p;

	*packidx = NULL;

	p = calloc(1, sizeof(*p));
	if (p == NULL)
		return got_error_from_errno();

	p->fd = open(path, O_RDONLY | O_NOFOLLOW, GOT_DEFAULT_FILE_MODE);
	if (p->fd == -1)
		return got_error_from_errno();

	err = get_packfile_size(&p->len, path);
	if (err) {
		close(p->fd);
		free(p);
		return err;
	}
	if (p->len < sizeof(p->hdr)) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		close(p->fd);
		free(p);
		return err;
	}

	p->path_packidx = strdup(path);
	if (p->path_packidx == NULL) {
		err = got_error_from_errno();
		goto done;
	}

#ifndef GOT_PACK_NO_MMAP
	p->map = mmap(NULL, p->len, PROT_READ, MAP_PRIVATE, p->fd, 0);
	if (p->map == MAP_FAILED)
		p->map = NULL; /* fall back to read(2) */
#endif

	err = got_packidx_init_hdr(p, verify);
done:
	if (err)
		got_packidx_close(p);
	else
		*packidx = p;

	return err;
}

const struct got_error *
got_packidx_close(struct got_packidx *packidx)
{
	const struct got_error *err = NULL;

	free(packidx->path_packidx);
	if (packidx->map) {
		if (munmap(packidx->map, packidx->len) == -1)
			err = got_error_from_errno();
	} else {
		free(packidx->hdr.magic);
		free(packidx->hdr.version);
		free(packidx->hdr.fanout_table);
		free(packidx->hdr.sorted_ids);
		free(packidx->hdr.crc32);
		free(packidx->hdr.offsets);
		free(packidx->hdr.large_offsets);
		free(packidx->hdr.trailer);
	}
	close(packidx->fd);
	free(packidx);

	return err;
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
get_object_idx(struct got_packidx *packidx, struct got_object_id *id)
{
	u_int8_t id0 = id->sha1[0];
	uint32_t totobj = betoh32(packidx->hdr.fanout_table[0xff]);
	int left = 0, right = totobj - 1;

	if (id0 > 0)
		left = betoh32(packidx->hdr.fanout_table[id0 - 1]);

	while (left <= right) {
		struct got_packidx_object_id *oid;
		int i, cmp;

		i = ((left + right) / 2);
		oid = &packidx->hdr.sorted_ids[i];
		cmp = memcmp(id->sha1, oid->sha1, SHA1_DIGEST_LENGTH);
		if (cmp == 0)
			return i;
		else if (cmp > 0)
			left = i + 1;
		else if (cmp < 0)
			right = i - 1;
	}

	return -1;
}

static const struct got_error *
cache_packidx(struct got_packidx *packidx, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	int i;

	for (i = 0; i < nitems(repo->packidx_cache); i++) {
		if (repo->packidx_cache[i] == NULL)
			break;
	}

	if (i == nitems(repo->packidx_cache)) {
		err = got_packidx_close(repo->packidx_cache[i - 1]);
		if (err)
			return err;
		memmove(&repo->packidx_cache[1], &repo->packidx_cache[0],
		    sizeof(repo->packidx_cache) -
		    sizeof(repo->packidx_cache[0]));
		i = 0;
	}

	repo->packidx_cache[i] = packidx;
	return NULL;
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

		err = got_packidx_open(packidx, path_packidx, 0);
		free(path_packidx);
		if (err)
			goto done;

		*idx = get_object_idx(*packidx, id);
		if (*idx != -1) {
			err = NULL; /* found the object */
			err = cache_packidx(*packidx, repo);
			goto done;
		}

		err = got_packidx_close(*packidx);
		*packidx = NULL;
		if (err)
			goto done;
	}

	err = got_error(GOT_ERR_NO_OBJ);
done:
	free(path_packdir);
	if (packdir && closedir(packdir) != 0 && err == 0)
		err = got_error_from_errno();
	return err;
}

static const struct got_error *
get_packfile_path(char **path_packfile, struct got_packidx *packidx)
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

static const struct got_error *
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
open_packfile(int *fd, const char *path_packfile, struct got_packidx *packidx)
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

const struct got_error *
got_pack_close(struct got_pack *pack)
{
	const struct got_error *err = NULL;

	if (pack->map && munmap(pack->map, pack->filesize) == -1)
		err = got_error_from_errno();
	close(pack->fd);
	pack->fd = -1;
	free(pack->path_packfile);
	pack->path_packfile = NULL;
	pack->filesize = 0;

	return err;
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
		err = got_pack_close(&repo->packs[i - 1]);
		if (err)
			return err;
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

	err = open_packfile(&pack->fd, path_packfile, packidx);
	if (err)
		goto done;

	err = get_packfile_size(&pack->filesize, path_packfile);
	if (err)
		goto done;

#ifndef GOT_PACK_NO_MMAP
	pack->map = mmap(NULL, pack->filesize, PROT_READ, MAP_PRIVATE,
	    pack->fd, 0);
	if (pack->map == MAP_FAILED)
		pack->map = NULL; /* fall back to read(2) */
#endif
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
parse_object_type_and_size(uint8_t *type, uint64_t *size, size_t *len,
    struct got_pack *pack, off_t offset)
{
	uint8_t t = 0;
	uint64_t s = 0;
	uint8_t sizeN;
	size_t mapoff = 0;
	int i = 0;

	*len = 0;

	if (offset >= pack->filesize)
		return got_error(GOT_ERR_PACK_OFFSET);

	if (pack->map) {
		mapoff = (size_t)offset;
	} else {
		if (lseek(pack->fd, offset, SEEK_SET) == -1)
			return got_error_from_errno();
	}

	do {
		/* We do not support size values which don't fit in 64 bit. */
		if (i > 9)
			return got_error(GOT_ERR_NO_SPACE);

		if (pack->map) {
			sizeN = *(pack->map + mapoff);
			mapoff += sizeof(sizeN);
		} else {
			ssize_t n = read(pack->fd, &sizeN, sizeof(sizeN));
			if (n < 0)
				return got_error_from_errno();
			if (n != sizeof(sizeN))
				return got_error(GOT_ERR_BAD_PACKFILE);
		}
		*len += sizeof(sizeN);

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
parse_negative_offset(int64_t *offset, size_t *len, struct got_pack *pack,
    off_t delta_offset)
{
	int64_t o = 0;
	uint8_t offN;
	int i = 0;

	*len = 0;

	do {
		/* We do not support offset values which don't fit in 64 bit. */
		if (i > 8)
			return got_error(GOT_ERR_NO_SPACE);

		if (pack->map) {
			size_t mapoff;
			if (delta_offset >= pack->filesize)
				return got_error(GOT_ERR_PACK_OFFSET);
			mapoff = (size_t)delta_offset + *len;
			offN = *(pack->map + mapoff);
		} else {
			ssize_t n;
			n = read(pack->fd, &offN, sizeof(offN));
			if (n < 0)
				return got_error_from_errno();
			if (n != sizeof(offN))
				return got_error(GOT_ERR_BAD_PACKFILE);
		}
		*len += sizeof(offN);

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
	return NULL;
}

static const struct got_error *
parse_offset_delta(off_t *base_offset, size_t *len, struct got_pack *pack,
    off_t offset, int tslen)
{
	const struct got_error *err;
	int64_t negoffset;
	size_t negofflen;

	*len = 0;

	err = parse_negative_offset(&negoffset, &negofflen, pack,
	    offset + tslen);
	if (err)
		return err;

	/* Compute the base object's offset (must be in the same pack file). */
	*base_offset = (offset - negoffset);
	if (*base_offset <= 0)
		return got_error(GOT_ERR_BAD_PACKFILE);

	*len = negofflen;
	return NULL;
}

static const struct got_error *
resolve_delta_chain(struct got_delta_chain *, struct got_packidx *,
    struct got_pack *, off_t, size_t, int, size_t, unsigned int);

static const struct got_error *
add_delta(struct got_delta_chain *deltas, off_t delta_offset, size_t tslen,
    int delta_type, size_t delta_size, size_t delta_data_offset,
    uint8_t *delta_buf, size_t delta_len)
{
	struct got_delta *delta;

	delta = got_delta_open(delta_offset, tslen, delta_type, delta_size,
	    delta_data_offset, delta_buf,
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
    struct got_packidx *packidx, struct got_pack *pack, off_t delta_offset,
    size_t tslen, int delta_type, size_t delta_size, unsigned int recursion)

{
	const struct got_error *err;
	off_t base_offset;
	uint8_t base_type;
	uint64_t base_size;
	size_t base_tslen;
	off_t delta_data_offset;
	uint8_t *delta_buf;
	size_t delta_len, consumed;

	err = parse_offset_delta(&base_offset, &consumed, pack,
	    delta_offset, tslen);
	if (err)
		return err;

	delta_data_offset = delta_offset + tslen + consumed;
	if (delta_data_offset >= pack->filesize)
		return got_error(GOT_ERR_PACK_OFFSET);

	if (pack->map == NULL) {
		delta_data_offset = lseek(pack->fd, 0, SEEK_CUR);
		if (delta_data_offset == -1)
			return got_error_from_errno();
	}

	if (pack->map) {
		size_t mapoff = (size_t)delta_data_offset;
		err = got_inflate_to_mem_mmap(&delta_buf, &delta_len, pack->map,
		    mapoff, pack->filesize - mapoff);
		if (err)
			return err;
	} else {

		err = got_inflate_to_mem_fd(&delta_buf, &delta_len, pack->fd);
		if (err)
			return err;
	}

	err = add_delta(deltas, delta_offset, tslen, delta_type, delta_size,
	    delta_data_offset, delta_buf, delta_len);
	if (err)
		goto done;

	/* An offset delta must be in the same packfile. */
	if (base_offset >= pack->filesize) {
		err = got_error(GOT_ERR_PACK_OFFSET);
		goto done;
	}

	err = parse_object_type_and_size(&base_type, &base_size, &base_tslen,
	    pack, base_offset);
	if (err)
		goto done;

	err = resolve_delta_chain(deltas, packidx, pack, base_offset,
	    base_tslen, base_type, base_size, recursion - 1);
done:
	if (err)
		free(delta_buf);
	return err;
}

static const struct got_error *
resolve_ref_delta(struct got_delta_chain *deltas, struct got_packidx *packidx,
    struct got_pack *pack, off_t delta_offset, size_t tslen, int delta_type,
    size_t delta_size, unsigned int recursion)
{
	const struct got_error *err;
	struct got_object_id id;
	int idx;
	off_t base_offset;
	uint8_t base_type;
	uint64_t base_size;
	size_t base_tslen;
	off_t delta_data_offset;
	uint8_t *delta_buf = NULL;
	size_t delta_len;

	if (delta_offset >= pack->filesize)
		return got_error(GOT_ERR_PACK_OFFSET);
	delta_data_offset = delta_offset + tslen;
	if (delta_data_offset >= pack->filesize)
		return got_error(GOT_ERR_PACK_OFFSET);

	if (pack->map == NULL) {
		delta_data_offset = lseek(pack->fd, 0, SEEK_CUR);
		if (delta_data_offset == -1)
			return got_error_from_errno();
	}


	if (pack->map) {
		size_t mapoff = (size_t)delta_data_offset;
		memcpy(&id, pack->map + mapoff, sizeof(id));
		mapoff += sizeof(id);
		err = got_inflate_to_mem_mmap(&delta_buf, &delta_len, pack->map,
		    mapoff, pack->filesize - mapoff);
		if (err)
			goto done;
	} else {
		ssize_t n = read(pack->fd, &id, sizeof(id));
		if (n < 0)
			return got_error_from_errno();
		if (n != sizeof(id))
			return got_error(GOT_ERR_BAD_PACKFILE);
		err = got_inflate_to_mem_fd(&delta_buf, &delta_len, pack->fd);
		if (err)
			goto done;
	}

	err = add_delta(deltas, delta_offset, tslen, delta_type, delta_size,
	    delta_data_offset, delta_buf, delta_len);
	if (err)
		goto done;

	/* Delta base must be in the same pack file. */
	idx = get_object_idx(packidx, &id);
	if (idx == -1) {
		err = got_error(GOT_ERR_BAD_PACKFILE);
		goto done;
	}

	base_offset = get_object_offset(packidx, idx);
	if (base_offset == (uint64_t)-1) {
		err = got_error(GOT_ERR_BAD_PACKIDX);
		goto done;
	}

	if (base_offset >= pack->filesize) {
		err = got_error(GOT_ERR_PACK_OFFSET);
		goto done;
	}

	err = parse_object_type_and_size(&base_type, &base_size, &base_tslen,
	    pack, base_offset);
	if (err)
		goto done;

	err = resolve_delta_chain(deltas, packidx, pack, base_offset,
	    base_tslen, base_type, base_size, recursion - 1);
done:
	if (err)
		free(delta_buf);
	return err;
}

static const struct got_error *
resolve_delta_chain(struct got_delta_chain *deltas, struct got_packidx *packidx,
    struct got_pack *pack, off_t delta_offset, size_t tslen, int delta_type,
    size_t delta_size, unsigned int recursion)
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
		err = add_delta(deltas, delta_offset, tslen, delta_type,
		    delta_size, 0, NULL, 0);
		break;
	case GOT_OBJ_TYPE_OFFSET_DELTA:
		err = resolve_offset_delta(deltas, packidx, pack,
		    delta_offset, tslen, delta_type, delta_size, recursion - 1);
		break;
	case GOT_OBJ_TYPE_REF_DELTA:
		err = resolve_ref_delta(deltas, packidx, pack,
		    delta_offset, tslen, delta_type, delta_size, recursion - 1);
		break;
	default:
		return got_error(GOT_ERR_OBJ_TYPE);
	}

	return err;
}

static const struct got_error *
open_delta_object(struct got_object **obj, struct got_repository *repo,
    struct got_packidx *packidx, struct got_pack *pack,
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

	(*obj)->path_packfile = strdup(pack->path_packfile);
	if ((*obj)->path_packfile == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	(*obj)->flags |= GOT_OBJ_FLAG_PACKED;

	SIMPLEQ_INIT(&(*obj)->deltas.entries);
	(*obj)->flags |= GOT_OBJ_FLAG_DELTIFIED;

	err = resolve_delta_chain(&(*obj)->deltas, packidx, pack, offset,
	    tslen, delta_type, delta_size, GOT_DELTA_CHAIN_RECURSION_MAX);
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

	err = get_packfile_path(&path_packfile, packidx);
	if (err)
		return err;

	pack = get_cached_pack(path_packfile, repo);
	if (pack == NULL) {
		err = cache_pack(&pack, path_packfile, packidx, repo);
		if (err)
			goto done;
	}

	err = parse_object_type_and_size(&type, &size, &tslen, pack, offset);
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
		err = open_delta_object(obj, repo, packidx, pack, id, offset,
		    tslen, type, size);
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
    struct got_pack *pack, FILE *outfile)
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
			size_t base_len, mapoff;
			off_t delta_data_offset;

			/* Plain object types are the delta base. */
			if (delta->type != GOT_OBJ_TYPE_COMMIT &&
			    delta->type != GOT_OBJ_TYPE_TREE &&
			    delta->type != GOT_OBJ_TYPE_BLOB &&
			    delta->type != GOT_OBJ_TYPE_TAG) {
				err = got_error(GOT_ERR_BAD_DELTA_CHAIN);
				goto done;
			}

			delta_data_offset = delta->offset + delta->tslen;
			if (delta_data_offset >= pack->filesize) {
				err = got_error(GOT_ERR_PACK_OFFSET);
				goto done;
			}
			if (pack->map == NULL) {
				if (lseek(pack->fd, delta_data_offset, SEEK_SET)
				    == -1) {
					err = got_error_from_errno();
					goto done;
				}
			}
			if (base_file) {
				if (pack->map) {
					mapoff = (size_t)delta_data_offset;
					err = got_inflate_to_file_mmap(
					    &base_len, pack->map, mapoff,
					    pack->filesize - mapoff, base_file);
				} else
					err = got_inflate_to_file_fd(&base_len,
					    pack->fd, base_file);
			} else {
				if (pack->map) {
					mapoff = (size_t)delta_data_offset;
					err = got_inflate_to_mem_mmap(&base_buf,
					    &base_len, pack->map, mapoff,
					    pack->filesize - mapoff);
				} else
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
			err = got_ferror(outfile, GOT_ERR_IO);
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
    struct got_delta_chain *deltas, struct got_pack *pack)
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
			size_t delta_data_offset;

			/* Plain object types are the delta base. */
			if (delta->type != GOT_OBJ_TYPE_COMMIT &&
			    delta->type != GOT_OBJ_TYPE_TREE &&
			    delta->type != GOT_OBJ_TYPE_BLOB &&
			    delta->type != GOT_OBJ_TYPE_TAG) {
				err = got_error(GOT_ERR_BAD_DELTA_CHAIN);
				goto done;
			}

			delta_data_offset = delta->offset + delta->tslen;
			if (delta_data_offset >= pack->filesize) {
				err = got_error(GOT_ERR_PACK_OFFSET);
				goto done;
			}
			if (pack->map) {
				size_t mapoff = (size_t)delta_data_offset;
				err = got_inflate_to_mem_mmap(&base_buf,
				    &base_len, pack->map, mapoff,
				    pack->filesize - mapoff);
			} else {
				if (lseek(pack->fd, delta_data_offset, SEEK_SET)
				    == -1) {
					err = got_error_from_errno();
					goto done;
				}
				err = got_inflate_to_mem_fd(&base_buf,
				    &base_len, pack->fd);
			}
			if (err)
				goto done;
			if (base_len < max_size) {
				uint8_t *p;
				p = reallocarray(base_buf, 1, max_size);
				if (p == NULL) {
					err = got_error_from_errno();
					goto done;
				}
				base_buf = p;
			}
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

	*f = NULL;

	if ((obj->flags & GOT_OBJ_FLAG_PACKED) == 0)
		return got_error(GOT_ERR_OBJ_NOT_PACKED);

	pack = get_cached_pack(obj->path_packfile, repo);
	if (pack == NULL) {
		err = cache_pack(&pack, obj->path_packfile, NULL, repo);
		if (err)
			return err;
	}

	*f = got_opentemp();
	if (*f == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	if ((obj->flags & GOT_OBJ_FLAG_DELTIFIED) == 0) {
		if (obj->pack_offset >= pack->filesize) {
			err = got_error(GOT_ERR_PACK_OFFSET);
			goto done;
		}

		if (pack->map) {
			size_t mapoff = (size_t)obj->pack_offset;
			err = got_inflate_to_file_mmap(&obj->size, pack->map,
			    mapoff, pack->filesize - mapoff, *f);
		} else {
			if (lseek(pack->fd, obj->pack_offset, SEEK_SET) == -1) {
				err = got_error_from_errno();
				goto done;
			}
			err = got_inflate_to_file_fd(&obj->size, pack->fd, *f);
		}
	} else
		err = dump_delta_chain_to_file(&obj->size, &obj->deltas, pack,
		    *f);
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
		if (obj->pack_offset >= pack->filesize) {
			err = got_error(GOT_ERR_PACK_OFFSET);
			goto done;
		}
		if (pack->map) {
			size_t mapoff = (size_t)obj->pack_offset;
			err = got_inflate_to_mem_mmap(buf, len, pack->map,
			    mapoff, pack->filesize - mapoff);
		} else {
			if (lseek(pack->fd, obj->pack_offset, SEEK_SET) == -1) {
				err = got_error_from_errno();
				goto done;
			}
			err = got_inflate_to_mem_fd(buf, len, pack->fd);
		}
	} else
		err = dump_delta_chain_to_mem(buf, len, &obj->deltas, pack);
done:
	return err;
}
