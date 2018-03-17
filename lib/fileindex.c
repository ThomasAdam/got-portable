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

#include "got_lib_fileindex.h"

const struct got_error *
got_fileindex_entry_open(struct got_fileindex_entry **entry,
    const char *ondisk_path, const char *relpath, uint8_t *blob_sha1)
{
	struct stat sb;
	size_t len;

	if (lstat(ondisk_path, &sb) != 0)
		return got_error_from_errno();

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
	
	(*entry)->ctime_sec = sb.st_ctime;
	(*entry)->ctime_nsec = sb.st_ctimensec;
	(*entry)->mtime_sec = sb.st_mtime;
	(*entry)->mtime_nsec = sb.st_mtimensec;
	(*entry)->uid = sb.st_uid;
	(*entry)->gid = sb.st_gid;
	(*entry)->size = (sb.st_size & 0xffffffff);
	if (sb.st_mode & S_IFLNK)
		(*entry)->mode = GOT_INDEX_ENTRY_MODE_SYMLINK;
	else
		(*entry)->mode = GOT_INDEX_ENTRY_MODE_REGULAR_FILE;
	(*entry)->mode |= ((sb.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) <<
	    GOT_INDEX_ENTRY_MODE_PERMS_SHIFT);
	memcpy((*entry)->blob_sha1, blob_sha1, SHA1_DIGEST_LENGTH);
	len = strlen(relpath);
	if (len > GOT_INDEX_ENTRY_F_PATH_LEN)
		len = GOT_INDEX_ENTRY_F_PATH_LEN;
	(*entry)->flags |= len;

	return NULL;
}

void
got_fileindex_entry_close(struct got_fileindex_entry *entry)
{
	free(entry->path);
	free(entry);
}

const struct got_error *
got_fileindex_entry_add(struct got_fileindex *fileindex,
    struct got_fileindex_entry *entry)
{
	/* TODO keep entries sorted by name */
	TAILQ_INSERT_TAIL(&fileindex->entries, entry, entry);
	fileindex->nentries++;
	return NULL;
}

struct got_fileindex *
got_fileindex_open(void)
{
	struct got_fileindex *fileindex;

	fileindex = calloc(1, sizeof(*fileindex));
	if (fileindex)
		TAILQ_INIT(&fileindex->entries);
	return fileindex;
}

void
got_fileindex_close(struct got_fileindex *fileindex)
{
	struct got_fileindex_entry *entry;

	while (!TAILQ_EMPTY(&fileindex->entries)) {
		entry = TAILQ_FIRST(&fileindex->entries);
		TAILQ_REMOVE(&fileindex->entries, entry, entry);
		got_fileindex_entry_close(entry);
		fileindex->nentries--;
	}
	free(fileindex);
}

static const struct got_error *
write_fileindex_val64(SHA1_CTX *ctx, uint64_t val, FILE *outfile)
{
	uint8_t buf[sizeof(uint64_t)];
	size_t n;

	val = htobe64(val);
	memcpy(buf, &val, sizeof(val));
	SHA1Update(ctx, buf, sizeof(val));
	n = fwrite(buf, 1, sizeof(val), outfile);
	if (n != sizeof(val))
		return got_ferror(outfile, GOT_ERR_IO);
	return NULL;
}

static const struct got_error *
write_fileindex_val32(SHA1_CTX *ctx, uint32_t val, FILE *outfile)
{
	uint8_t buf[sizeof(uint32_t)];
	size_t n;

	val = htobe32(val);
	memcpy(buf, &val, sizeof(val));
	SHA1Update(ctx, buf, sizeof(val));
	n = fwrite(buf, 1, sizeof(val), outfile);
	if (n != sizeof(val))
		return got_ferror(outfile, GOT_ERR_IO);
	return NULL;
}

static const struct got_error *
write_fileindex_val16(SHA1_CTX *ctx, uint16_t val, FILE *outfile)
{
	uint8_t buf[sizeof(uint16_t)];
	size_t n;

	val = htobe16(val);
	memcpy(buf, &val, sizeof(val));
	SHA1Update(ctx, buf, sizeof(val));
	n = fwrite(buf, 1, sizeof(val), outfile);
	if (n != sizeof(val))
		return got_ferror(outfile, GOT_ERR_IO);
	return NULL;
}

static const struct got_error *
write_fileindex_path(SHA1_CTX *ctx, const char *path, FILE *outfile)
{
	size_t n, len, pad;
	static const uint8_t zero[8] = { 0 };

	len = strlen(path);
	pad = (len % 8);

	SHA1Update(ctx, path, len);
	n = fwrite(path, 1, len, outfile);
	if (n != len)
		return got_ferror(outfile, GOT_ERR_IO);
	if (pad == 0)
		return NULL;
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

	err = write_fileindex_val32(ctx, entry->flags, outfile);
	if (err)
		return err;

	err = write_fileindex_path(ctx, entry->path, outfile);
	return err;
}

const struct got_error *
got_fileindex_write(struct got_fileindex *fileindex, FILE *outfile)
{
	struct got_fileindex_hdr hdr;
	struct got_fileindex_entry *entry;
	SHA1_CTX ctx;
	uint8_t sha1[SHA1_DIGEST_LENGTH];
	size_t n;
	const size_t len = sizeof(hdr.signature) + sizeof(hdr.version) +
	    sizeof(hdr.nentries);
	uint8_t buf[len];

	SHA1Init(&ctx);

	hdr.signature = htobe32(GOT_FILE_INDEX_SIGNATURE);
	hdr.version = htobe32(GOT_FILE_INDEX_VERSION);
	hdr.nentries = htobe32(fileindex->nentries);

	memcpy(buf, &hdr, len);
	SHA1Update(&ctx, buf, len);
	n = fwrite(buf, 1, len, outfile);
	if (n != len)
		return got_ferror(outfile, GOT_ERR_IO);

	TAILQ_FOREACH(entry, &fileindex->entries, entry) {
		const struct got_error *err;
		err = write_fileindex_entry(&ctx, entry, outfile);
		if (err)
			return err;
	}

	SHA1Final(sha1, &ctx);
	n = fwrite(sha1, 1, sizeof(sha1), outfile);
	if (n != sizeof(sha1))
		return got_ferror(outfile, GOT_ERR_IO);

	return NULL;
}
