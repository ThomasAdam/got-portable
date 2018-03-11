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

#include "got_error.h"

#include "got_fileindex_lib.h"

const struct got_error *
got_fileindex_entry_open(struct got_fileindex_entry **entry, const char *path,
    uint8_t *blob_sha1)
{
	struct stat sb;
	size_t len;

	if (lstat(path, &sb) != 0)
		return got_error_from_errno();

	*entry = calloc(1, sizeof(**entry));
	if (*entry == NULL)
		return got_error(GOT_ERR_NO_MEM);

	(*entry)->path = strdup(path);
	if ((*entry)->path == NULL) {
		free(*entry);
		*entry = NULL;
		return got_error(GOT_ERR_NO_MEM);
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
	len = strlen(path);
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

const struct got_error *
got_fileindex_write(struct got_fileindex *fileindex, FILE *outfile)
{
	return NULL;
}
