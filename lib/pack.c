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
#include "got_sha1.h"
#include "pack.h"
#include "path.h"

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
		return got_error(GOT_ERR_NO_MEM);

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
		err = got_error(GOT_ERR_NO_MEM);
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
		err = got_error(GOT_ERR_NO_MEM);
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
		err = got_error(GOT_ERR_NO_MEM);
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
		err = got_error(GOT_ERR_NO_MEM);
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
		struct got_object_id *oid = &packidx->sorted_ids[i++];
		uint32_t offset;

		if (got_object_id_cmp(id, oid) < 0)
			continue;
		if (got_object_id_cmp(id, oid) > 0)
			break;

		return i;
	}

	return -1;
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
dump_packed_object(FILE **f, FILE *packfile, off_t offset)
{
	const struct got_error *err = NULL;
	const char *template = "/tmp/got.XXXXXXXXXX";
	uint64_t size = 0;
	uint8_t type = 0;
	uint8_t sizeN;
	int i;
	size_t n;
	const char *type_tag;

	*f = got_opentemp();
	if (*f == NULL) {
		err = got_error(GOT_ERR_FILE_OPEN);
		goto done;
	}

	if (fseeko(packfile, offset, SEEK_SET) != 0) {
		err = got_error_from_errno();
		goto done;
	}

	i = 0;
	do {
		/* We do not support size values which don't fit in 64 bit. */
		if (i > 9) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}

		n = fread(&sizeN, sizeof(sizeN), 1, packfile);
		if (n != 1) {
			err = got_ferror(packfile, GOT_ERR_BAD_PACKIDX);
			goto done;
		}

		if (i == 0) {
			type = (sizeN & GOT_PACK_OBJ_SIZE0_TYPE_MASK) >>
			    GOT_PACK_OBJ_SIZE0_TYPE_MASK_SHIFT;
			size = (sizeN & GOT_PACK_OBJ_SIZE0_VAL_MASK);
		} else {
			size_t shift = 4 + 7 * (i - 1);
			size |= ((sizeN & GOT_PACK_OBJ_SIZE_VAL_MASK) << shift);
		}
		i++;
	} while (sizeN & GOT_PACK_OBJ_SIZE_MORE);

	if (type == GOT_OBJ_TYPE_OFFSET_DELTA)
		printf("object type OFFSET_DELTA not yet implemented\n");
	else if (type == GOT_OBJ_TYPE_REF_DELTA)
		printf("object type REF_DELTA not yet implemented\n");
	else if (type == GOT_OBJ_TYPE_TAG)
		printf("object type TAG not yet implemented\n");

	type_tag = got_object_get_type_tag(type);
	if (type_tag == NULL) {
		err = got_error(GOT_ERR_BAD_OBJ_HDR);
		goto done;
	}

	fprintf(*f, "%s %llu", type_tag, size);
	fputc('\0', *f);

	while (size > 0) {
		uint8_t data[2048];
		size_t len = MIN(size, sizeof(data));

		n = fread(data, len, 1, packfile);
		if (n != 1) {
			err = got_ferror(packfile, GOT_ERR_BAD_PACKIDX);
			goto done;
		}

		n = fwrite(data, len, 1, *f);
		if (n != 1) {
			err = got_ferror(*f, GOT_ERR_BAD_PACKIDX);
			goto done;
		}

		size -= len;
	}

	printf("object type is %d\n", type);
	rewind(*f);
done:
	if (err && *f)
		fclose(*f);
	return err;
}
static const struct got_error *
extract_object(FILE **f, const char *path_packdir,
    struct got_packidx_v2_hdr *packidx, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	int idx = get_object_idx(packidx, id);
	off_t offset;
	char *path_packfile;
	FILE *packfile;
	char hex[SHA1_DIGEST_STRING_LENGTH];
	char *sha1str;

	*f = NULL;
	if (idx == -1) /* object not found in pack index */
		return NULL;

	offset = get_object_offset(packidx, idx);
	if (offset == (uint64_t)-1)
		return got_error(GOT_ERR_BAD_PACKIDX);

	sha1str = got_sha1_digest_to_str(packidx->trailer.packfile_sha1,
	    hex, sizeof(hex));
	if (sha1str == NULL)
		return got_error(GOT_ERR_PACKIDX_CSUM);

	if (asprintf(&path_packfile, "%s/%s%s%s", path_packdir,
	    GOT_PACK_PREFIX, sha1str, GOT_PACKFILE_SUFFIX) == -1)
		return got_error(GOT_ERR_NO_MEM);

	packfile = fopen(path_packfile, "rb");
	if (packfile == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	err = read_packfile_hdr(packfile, packidx);
	if (err)
		goto done;

	printf("Dumping object at offset %llu\n", offset);
	err = dump_packed_object(f, packfile, offset);
	if (err)
		goto done;

done:
	free(path_packfile);
	if (packfile && fclose(packfile) == -1 && err == 0)
		err = got_error_from_errno();
	return err;
}

const struct got_error *
got_packfile_extract_object(FILE **f, struct got_object_id *id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	DIR *packdir = NULL;
	struct dirent *dent;
	char *path_packdir = got_repo_get_path_objects_pack(repo);

	if (path_packdir == NULL) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}

	packdir = opendir(path_packdir);
	if (packdir == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	while ((dent = readdir(packdir)) != NULL) {
		struct got_packidx_v2_hdr *packidx;
		char *path_packidx, *path_object;

		if (!is_packidx_filename(dent->d_name, dent->d_namlen))
			continue;

		if (asprintf(&path_packidx, "%s/%s", path_packdir,
		    dent->d_name) == -1) {
			err = got_error(GOT_ERR_NO_MEM);
			goto done;
		}

		err = got_packidx_open(&packidx, path_packidx);
		free(path_packidx);
		if (err)
			goto done;

		err = extract_object(f, path_packdir, packidx, id);
		if (err)
			goto done;
		if (*f != NULL)
			break;
	}

done:
	free(path_packdir);
	if (packdir && closedir(packdir) != 0 && err == 0)
		err = got_error_from_errno();
	return err;
}
