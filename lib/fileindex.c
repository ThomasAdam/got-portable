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

#include <sys/queue.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <endian.h>

#include "got_error.h"

#include "got_lib_pathset.h"
#include "got_lib_fileindex.h"

const struct got_error *
got_fileindex_entry_update(struct got_fileindex_entry *entry,
    const char *ondisk_path, uint8_t *blob_sha1, uint8_t *commit_sha1)
{
	struct stat sb;

	if (lstat(ondisk_path, &sb) != 0)
		return got_error_from_errno();

	entry->ctime_sec = sb.st_ctime;
	entry->ctime_nsec = sb.st_ctimensec;
	entry->mtime_sec = sb.st_mtime;
	entry->mtime_nsec = sb.st_mtimensec;
	entry->uid = sb.st_uid;
	entry->gid = sb.st_gid;
	entry->size = (sb.st_size & 0xffffffff);
	if (sb.st_mode & S_IFLNK)
		entry->mode = GOT_INDEX_ENTRY_MODE_SYMLINK;
	else
		entry->mode = GOT_INDEX_ENTRY_MODE_REGULAR_FILE;
	entry->mode |= ((sb.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) <<
	    GOT_INDEX_ENTRY_MODE_PERMS_SHIFT);
	memcpy(entry->blob_sha1, blob_sha1, SHA1_DIGEST_LENGTH);
	memcpy(entry->commit_sha1, commit_sha1, SHA1_DIGEST_LENGTH);

	return NULL;
}

const struct got_error *
got_fileindex_entry_alloc(struct got_fileindex_entry **entry,
    const char *ondisk_path, const char *relpath, uint8_t *blob_sha1,
    uint8_t *commit_sha1)
{
	size_t len;

	*entry = calloc(1, sizeof(**entry));
	if (*entry == NULL)
		return got_error_from_errno();

	(*entry)->path = strdup(relpath);
	if ((*entry)->path == NULL) {
		const struct got_error *err = got_error_from_errno();
		free(*entry);
		*entry = NULL;
		return err;
	}

	len = strlen(relpath);
	if (len > GOT_INDEX_ENTRY_F_PATH_LEN)
		len = GOT_INDEX_ENTRY_F_PATH_LEN;
	(*entry)->flags |= len;

	return got_fileindex_entry_update(*entry, ondisk_path, blob_sha1,
	    commit_sha1);
}

void
got_fileindex_entry_free(struct got_fileindex_entry *entry)
{
	free(entry->path);
	free(entry);
}

const struct got_error *
got_fileindex_entry_add(struct got_fileindex *fileindex,
    struct got_fileindex_entry *entry)
{
	return got_pathset_add(fileindex->entries, entry->path, entry);
}

const struct got_error *
got_fileindex_entry_remove(struct got_fileindex *fileindex,
    struct got_fileindex_entry *entry)
{
	return got_pathset_remove(NULL, fileindex->entries, entry->path);
}

struct got_fileindex_entry *
got_fileindex_entry_get(struct got_fileindex *fileindex, const char *path)
{
	struct got_fileindex_entry *entry;
	entry = (struct got_fileindex_entry *)got_pathset_get(
	    fileindex->entries, path);
	return entry;
}

struct pathset_cb_arg {
    got_fileindex_cb cb;
    void *cb_arg;
};

static const struct got_error *
pathset_cb(const char *path, void *data, void *arg)
{
	struct got_fileindex_entry *entry = data;
	struct pathset_cb_arg *a = arg;
	return (*a->cb)(a->cb_arg, entry);
}

const struct got_error *
got_fileindex_for_each_entry_safe(struct got_fileindex *fileindex,
    got_fileindex_cb cb, void *cb_arg)
{
	struct pathset_cb_arg arg;

	arg.cb = cb;
	arg.cb_arg = cb_arg;
	return got_pathset_for_each_safe(fileindex->entries, pathset_cb, &arg);
}

const struct got_error *
got_fileindex_alloc(struct got_fileindex **fileindex)
{
	*fileindex = calloc(1, sizeof(**fileindex));
	if (*fileindex == NULL)
		return got_error_from_errno();

	(*fileindex)->entries = got_pathset_alloc();
	if ((*fileindex)->entries == NULL) {
		free(*fileindex);
		*fileindex = NULL;
		return got_error_from_errno();
	}

	return NULL;
}

static const struct got_error *
free_entry_cb(const char *path, void *data, void *arg)
{
	struct got_fileindex_entry *entry = data;
	got_fileindex_entry_free(entry);
	return NULL;
}

void
got_fileindex_free(struct got_fileindex *fileindex)
{
	got_pathset_for_each_safe(fileindex->entries, free_entry_cb, NULL);
	got_pathset_free(fileindex->entries);
	free(fileindex);
}

static const struct got_error *
write_fileindex_val64(SHA1_CTX *ctx, uint64_t val, FILE *outfile)
{
	size_t n;

	val = htobe64(val);
	SHA1Update(ctx, (uint8_t *)&val, sizeof(val));
	n = fwrite(&val, 1, sizeof(val), outfile);
	if (n != sizeof(val))
		return got_ferror(outfile, GOT_ERR_IO);
	return NULL;
}

static const struct got_error *
write_fileindex_val32(SHA1_CTX *ctx, uint32_t val, FILE *outfile)
{
	size_t n;

	val = htobe32(val);
	SHA1Update(ctx, (uint8_t *)&val, sizeof(val));
	n = fwrite(&val, 1, sizeof(val), outfile);
	if (n != sizeof(val))
		return got_ferror(outfile, GOT_ERR_IO);
	return NULL;
}

static const struct got_error *
write_fileindex_val16(SHA1_CTX *ctx, uint16_t val, FILE *outfile)
{
	size_t n;

	val = htobe16(val);
	SHA1Update(ctx, (uint8_t *)&val, sizeof(val));
	n = fwrite(&val, 1, sizeof(val), outfile);
	if (n != sizeof(val))
		return got_ferror(outfile, GOT_ERR_IO);
	return NULL;
}

static const struct got_error *
write_fileindex_path(SHA1_CTX *ctx, const char *path, FILE *outfile)
{
	size_t n, len, pad = 0;
	static const uint8_t zero[8] = { 0 };

	len = strlen(path);
	while ((len + pad) % 8 != 0)
		pad++;
	if (pad == 0)
		pad = 8; /* NUL-terminate */

	SHA1Update(ctx, path, len);
	n = fwrite(path, 1, len, outfile);
	if (n != len)
		return got_ferror(outfile, GOT_ERR_IO);
	SHA1Update(ctx, zero, pad);
	n = fwrite(zero, 1, pad, outfile);
	if (n != pad)
		return got_ferror(outfile, GOT_ERR_IO);
	return NULL;
}

static const struct got_error *
write_fileindex_entry(SHA1_CTX *ctx, struct got_fileindex_entry *entry,
    FILE *outfile)
{
	const struct got_error *err;
	size_t n;

	err = write_fileindex_val64(ctx, entry->ctime_sec, outfile);
	if (err)
		return err;
	err = write_fileindex_val64(ctx, entry->ctime_nsec, outfile);
	if (err)
		return err;
	err = write_fileindex_val64(ctx, entry->mtime_sec, outfile);
	if (err)
		return err;
	err = write_fileindex_val64(ctx, entry->mtime_nsec, outfile);
	if (err)
		return err;

	err = write_fileindex_val32(ctx, entry->uid, outfile);
	if (err)
		return err;
	err = write_fileindex_val32(ctx, entry->gid, outfile);
	if (err)
		return err;
	err = write_fileindex_val32(ctx, entry->size, outfile);
	if (err)
		return err;

	err = write_fileindex_val16(ctx, entry->mode, outfile);
	if (err)
		return err;

	SHA1Update(ctx, entry->blob_sha1, SHA1_DIGEST_LENGTH);
	n = fwrite(entry->blob_sha1, 1, SHA1_DIGEST_LENGTH, outfile);
	if (n != SHA1_DIGEST_LENGTH)
		return got_ferror(outfile, GOT_ERR_IO);

	SHA1Update(ctx, entry->commit_sha1, SHA1_DIGEST_LENGTH);
	n = fwrite(entry->commit_sha1, 1, SHA1_DIGEST_LENGTH, outfile);
	if (n != SHA1_DIGEST_LENGTH)
		return got_ferror(outfile, GOT_ERR_IO);

	err = write_fileindex_val32(ctx, entry->flags, outfile);
	if (err)
		return err;

	err = write_fileindex_path(ctx, entry->path, outfile);
	return err;
}

struct write_entry_cb_arg {
	SHA1_CTX *ctx;
	FILE *outfile;
};

static const struct got_error *
write_entry_cb(const char *path, void *data, void *arg)
{
	struct got_fileindex_entry *entry = data;
	struct write_entry_cb_arg *a = arg;

	return write_fileindex_entry(a->ctx, entry, a->outfile);
}

const struct got_error *
got_fileindex_write(struct got_fileindex *fileindex, FILE *outfile)
{
	const struct got_error *err = NULL;
	struct got_fileindex_hdr hdr;
	SHA1_CTX ctx;
	uint8_t sha1[SHA1_DIGEST_LENGTH];
	size_t n;
	const size_t len = sizeof(hdr.signature) + sizeof(hdr.version) +
	    sizeof(hdr.nentries);
	uint8_t buf[len];
	struct write_entry_cb_arg arg;

	SHA1Init(&ctx);

	hdr.signature = htobe32(GOT_FILE_INDEX_SIGNATURE);
	hdr.version = htobe32(GOT_FILE_INDEX_VERSION);
	hdr.nentries = htobe32(got_pathset_num_elements(fileindex->entries));

	memcpy(buf, &hdr, len);
	SHA1Update(&ctx, buf, len);
	n = fwrite(buf, 1, len, outfile);
	if (n != len)
		return got_ferror(outfile, GOT_ERR_IO);

	arg.ctx = &ctx;
	arg.outfile = outfile;
	err = got_pathset_for_each_safe(fileindex->entries, write_entry_cb,
	    &arg);
	if (err)
		return err;

	SHA1Final(sha1, &ctx);
	n = fwrite(sha1, 1, sizeof(sha1), outfile);
	if (n != sizeof(sha1))
		return got_ferror(outfile, GOT_ERR_IO);

	return NULL;
}

static const struct got_error *
read_fileindex_val64(uint64_t *val, SHA1_CTX *ctx, FILE *infile)
{
	size_t n;

	n = fread(val, 1, sizeof(*val), infile);
	if (n != sizeof(*val))
		return got_ferror(infile, GOT_ERR_IO);
	SHA1Update(ctx, (uint8_t *)val, sizeof(*val));
	*val = be64toh(*val);
	return NULL;
}

static const struct got_error *
read_fileindex_val32(uint32_t *val, SHA1_CTX *ctx, FILE *infile)
{
	size_t n;

	n = fread(val, 1, sizeof(*val), infile);
	if (n != sizeof(*val))
		return got_ferror(infile, GOT_ERR_IO);
	SHA1Update(ctx, (uint8_t *)val, sizeof(*val));
	*val = be32toh(*val);
	return NULL;
}

static const struct got_error *
read_fileindex_val16(uint16_t *val, SHA1_CTX *ctx, FILE *infile)
{
	size_t n;

	n = fread(val, 1, sizeof(*val), infile);
	if (n != sizeof(*val))
		return got_ferror(infile, GOT_ERR_IO);
	SHA1Update(ctx, (uint8_t *)val, sizeof(*val));
	*val = be16toh(*val);
	return NULL;
}

static const struct got_error *
read_fileindex_path(char **path, SHA1_CTX *ctx, FILE *infile)
{
	const struct got_error *err = NULL;
	uint8_t buf[8];
	size_t n, len = 0, totlen = sizeof(buf);

	*path = malloc(totlen);
	if (*path == NULL)
		return got_error_from_errno();

	do {
		n = fread(buf, 1, sizeof(buf), infile);
		if (n != sizeof(buf))
			return got_ferror(infile, GOT_ERR_IO);
		if (len + sizeof(buf) > totlen) {
			char *p = reallocarray(*path, totlen + sizeof(buf), 1);
			if (p == NULL) {
				err = got_error_from_errno();
				break;
			}
			totlen += sizeof(buf);
			*path = p;
		}
		SHA1Update(ctx, buf, sizeof(buf));
		memcpy(*path + len, buf, sizeof(buf));
		len += sizeof(buf);
	} while (memchr(buf, '\0', sizeof(buf)) == NULL);

	if (err) {
		free(*path);
		*path = NULL;
	}
	return err;
}

static const struct got_error *
read_fileindex_entry(struct got_fileindex_entry **entryp, SHA1_CTX *ctx,
    FILE *infile)
{
	const struct got_error *err;
	struct got_fileindex_entry *entry;
	size_t n;

	*entryp = NULL;

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		return got_error_from_errno();

	err = read_fileindex_val64(&entry->ctime_sec, ctx, infile);
	if (err)
		goto done;
	err = read_fileindex_val64(&entry->ctime_nsec, ctx, infile);
	if (err)
		goto done;
	err = read_fileindex_val64(&entry->mtime_sec, ctx, infile);
	if (err)
		goto done;
	err = read_fileindex_val64(&entry->mtime_nsec, ctx, infile);
	if (err)
		goto done;

	err = read_fileindex_val32(&entry->uid, ctx, infile);
	if (err)
		goto done;
	err = read_fileindex_val32(&entry->gid, ctx, infile);
	if (err)
		goto done;
	err = read_fileindex_val32(&entry->size, ctx, infile);
	if (err)
		goto done;

	err = read_fileindex_val16(&entry->mode, ctx, infile);
	if (err)
		goto done;

	n = fread(entry->blob_sha1, 1, SHA1_DIGEST_LENGTH, infile);
	if (n != SHA1_DIGEST_LENGTH) {
		err = got_ferror(infile, GOT_ERR_IO);
		goto done;
	}
	SHA1Update(ctx, entry->blob_sha1, SHA1_DIGEST_LENGTH);

	n = fread(entry->commit_sha1, 1, SHA1_DIGEST_LENGTH, infile);
	if (n != SHA1_DIGEST_LENGTH) {
		err = got_ferror(infile, GOT_ERR_IO);
		goto done;
	}
	SHA1Update(ctx, entry->commit_sha1, SHA1_DIGEST_LENGTH);

	err = read_fileindex_val32(&entry->flags, ctx, infile);
	if (err)
		goto done;

	err = read_fileindex_path(&entry->path, ctx, infile);
done:
	if (err)
		free(entry);
	else
		*entryp = entry;
	return err;
}

const struct got_error *
got_fileindex_read(struct got_fileindex *fileindex, FILE *infile)
{
	const struct got_error *err = NULL;
	struct got_fileindex_hdr hdr;
	SHA1_CTX ctx;
	struct got_fileindex_entry *entry;
	uint8_t sha1_expected[SHA1_DIGEST_LENGTH];
	uint8_t sha1[SHA1_DIGEST_LENGTH];
	size_t n;
	const size_t len = sizeof(hdr.signature) + sizeof(hdr.version) +
	    sizeof(hdr.nentries);
	uint8_t buf[len];
	int i;

	SHA1Init(&ctx);

	n = fread(buf, 1, len, infile);
	if (n != len) {
		if (n == 0) /* EOF */
			return NULL;
		return got_ferror(infile, GOT_ERR_IO);
	}

	SHA1Update(&ctx, buf, len);

	memcpy(&hdr, buf, len);
	hdr.signature = be32toh(hdr.signature);
	hdr.version = be32toh(hdr.version);
	hdr.nentries = be32toh(hdr.nentries);

	if (hdr.signature != GOT_FILE_INDEX_SIGNATURE)
		return got_error(GOT_ERR_FILEIDX_SIG);
	if (hdr.version != GOT_FILE_INDEX_VERSION)
		return got_error(GOT_ERR_FILEIDX_VER);

	for (i = 0; i < hdr.nentries; i++) {
		err = read_fileindex_entry(&entry, &ctx, infile);
		if (err)
			return err;
		err = got_fileindex_entry_add(fileindex, entry);
		if (err)
			return err;
	}

	n = fread(sha1_expected, 1, sizeof(sha1_expected), infile);
	if (n != sizeof(sha1_expected))
		return got_ferror(infile, GOT_ERR_IO);
	SHA1Final(sha1, &ctx);
	if (memcmp(sha1, sha1_expected, SHA1_DIGEST_LENGTH) != 0)
		return got_error(GOT_ERR_FILEIDX_CSUM);

	return NULL;
}
