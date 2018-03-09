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

/*
 * State information for a tracked file in a work tree.
 * When written to disk, multi-byte fields are written in big-endian.
 * Some fields are based on results from stat(2). These are only used in
 * order to detect modifications made to on-disk files, they are never
 * applied back to the filesystem.
 */
struct got_file_index_entry {
	TAILQ_ENTRY(, got_file_index_entry) entry;
	uint64_t ctime_sec;
	uint64_t ctime_nsec;
	uint64_t mtime_sec;
	uint64_t mtime_nsec;
	uint32_t uid;
	uint32_t gid;
	/*
	 * On-disk size is truncated to the lower 32 bits.
	 * The value is only used to check for modifications anyway.
	 */
	uint32_t size;
	uint16_t mode;
#define GOT_INDEX_ENTRY_MODE_OBJ_TYPE	0x000f
#define GOT_INDEX_ENTRY_MODE_PERMS	0xff10

	/* SHA1 of corresponding blob in repository. */
	uint8_t blob_sha1[SHA1_DIGEST_LENGTH];

	uint32_t flags;
#define GOT_INDEX_ENTRY_F_PATH_LEN	0x00000fff
#define GOT_INDEX_ENTRY_F_STAGE		0x00003000
#define GOT_INDEX_ENTRY_F_EXTENDED	0x00004000
#define GOT_INDEX_ENTRY_F_ASSUME_VALID	0x00008000

	/*
	 * UNIX-style path, relative to work tree root.
	 * Variable length and NUL-padded to a multiple of 8.
	 */
	const char *path;
};

/* "Stages" of a file afflicted by a 3-way merge conflict. */
#define GOT_INDEX_ENTRY_STAGE_MERGED	0
#define GOT_INDEX_ENTRY_STAGE_ANCESTOR	1
#define GOT_INDEX_ENTRY_STAGE_OURS	2
#define GOT_INDEX_ENTRY_STAGE_THEIRS	3

/* On-disk file index header structure. */
struct got_file_index_hdr {
	uint32_t signature;	/* big-endian on disk */
	uint32_t version;	/* big-endian on disk */
	uint32_t nentries;	/* big-endian on disk */
	TAILQ_HEAD(, got_file_index_entry) entries;
	uint8_t sha1[SHA1_DIGEST_LENGTH]; /* checksum of above on-disk data */
};
