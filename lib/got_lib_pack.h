/*
 * Copyright (c) 2018, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
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

struct got_pack_privsep_child {
	int imsg_fd;
	pid_t pid;
	struct imsgbuf *ibuf;
};

/* An open pack file. */
struct got_pack {
	char *path_packfile;
	int fd;
	enum got_hash_algorithm algo;
	uint8_t *map;
	off_t filesize;
	struct got_pack_privsep_child *privsep_child;
	int basefd;
	int accumfd;
	int child_has_tempfiles;
	int child_has_delta_outfd;
	struct got_delta_cache *delta_cache;
};

struct got_packidx;

const struct got_error *got_pack_start_privsep_child(struct got_pack *,
    struct got_packidx *);
const struct got_error *got_pack_close(struct got_pack *);

const struct got_error *got_pack_parse_offset_delta(off_t *, size_t *,
    struct got_pack *, off_t, size_t);
const struct got_error *got_pack_parse_ref_delta(struct got_object_id *,
    struct got_pack *, off_t, int);
const struct got_error *got_pack_resolve_delta_chain(struct got_delta_chain *,
    struct got_packidx *, struct got_pack *, off_t, size_t, int, size_t,
    unsigned int);
const struct got_error *got_pack_parse_object_type_and_size(uint8_t *,
    uint64_t *, size_t *, struct got_pack *, off_t);

#define GOT_PACK_PREFIX		"pack-"
#define GOT_PACKFILE_SUFFIX	".pack"
#define GOT_PACKIDX_SUFFIX	".idx"
#define GOT_PACKFILE_NAMELEN	(strlen(GOT_PACK_PREFIX) + \
				SHA1_DIGEST_STRING_LENGTH - 1 + \
				strlen(GOT_PACKFILE_SUFFIX))
#define GOT_PACKIDX_NAMELEN	(strlen(GOT_PACK_PREFIX) + \
				SHA1_DIGEST_STRING_LENGTH - 1 + \
				strlen(GOT_PACKIDX_SUFFIX))

/* See Documentation/technical/pack-format.txt in Git. */

struct got_packidx_trailer {
	u_int8_t	packfile_sha1[SHA1_DIGEST_LENGTH];
	u_int8_t	packidx_sha1[SHA1_DIGEST_LENGTH];
} __attribute__((__packed__));

struct got_packidx_object_id {
	u_int8_t sha1[SHA1_DIGEST_LENGTH];
} __attribute__((__packed__));

/* Ignore pack index version 1 which is no longer written by Git. */
#define GOT_PACKIDX_VERSION 2

struct got_packidx_v2_hdr {
	uint32_t	*magic;		/* big endian */
#define GOT_PACKIDX_V2_MAGIC 0xff744f63	/* "\377t0c" */
	uint32_t	*version;

	/*
	 * Each entry N in the fanout table contains the number of objects in
	 * the packfile whose SHA1 begins with a byte less than or equal to N.
	 * The last entry (index 255) contains the number of objects in the
	 * pack file whose first SHA1 byte is <= 0xff, and thus records the
	 * total number of objects in the pack file. All pointer variables
	 * below point to tables with a corresponding number of entries.
	 */
	uint32_t	*fanout_table;	/* values are big endian */
#define GOT_PACKIDX_V2_FANOUT_TABLE_ITEMS (0xff + 1)

	/* Sorted SHA1 checksums for each object in the pack file. */
	struct got_packidx_object_id *sorted_ids;

	/* CRC32 of the packed representation of each object. */
	uint32_t	*crc32;

	/* Offset into the pack file for each object. */
	uint32_t	*offsets;		/* values are big endian */
#define GOT_PACKIDX_OFFSET_VAL_MASK		0x7fffffff
#define GOT_PACKIDX_OFFSET_VAL_IS_LARGE_IDX	0x80000000

	/* Large offsets table is empty for pack files < 2 GB. */
	uint64_t	*large_offsets;		/* values are big endian */

	struct got_packidx_trailer *trailer;
};

struct got_pack_offset_index {
	uint32_t offset;
	uint32_t idx;
};

struct got_pack_large_offset_index {
	uint64_t offset;
	uint32_t idx;
};

/* An open pack index file. */
struct got_packidx {
	char *path_packidx; /* actual on-disk path */
	int fd;
	uint8_t *map;
	size_t len;
	size_t nlargeobj;
	struct got_packidx_v2_hdr hdr; /* convenient pointers into map */
	struct got_pack_offset_index *sorted_offsets;
	struct got_pack_large_offset_index *sorted_large_offsets;
};

struct got_packfile_hdr {
	uint32_t	signature;
#define GOT_PACKFILE_SIGNATURE	0x5041434b	/* 'P' 'A' 'C' 'K' */
	uint32_t	version;	/* big endian */
#define GOT_PACKFILE_VERSION 2
	uint32_t	nobjects;	/* big endian */
};

struct got_packfile_obj_hdr {
	/*
	 * The object size field uses a variable length encoding:
	 * size0...sizeN form a 4+7+7+...+7 bit integer, where size0 is the
	 * least significant part and sizeN is the most significant part.
	 * If the MSB of a size byte is set, an additional size byte follows.
	 * Of the 7 remaining bits of size0, the first 3 bits indicate the
	 * object's type, and the remaining 4 bits contribute to the size.
	 */
	uint8_t *size;		/* variable length */
#define GOT_PACK_OBJ_SIZE_MORE		0x80
#define GOT_PACK_OBJ_SIZE0_TYPE_MASK	0x70 /* See struct got_object->type */
#define GOT_PACK_OBJ_SIZE0_TYPE_MASK_SHIFT	4
#define GOT_PACK_OBJ_SIZE0_VAL_MASK	0x0f
#define GOT_PACK_OBJ_SIZE_VAL_MASK	0x7f
};

#define GOT_PACK_OBJ_DELTA_OFF_MORE		0x80
#define GOT_PACK_OBJ_DELTA_OFF_VAL_MASK		0x7f

const struct got_error *got_packidx_init_hdr(struct got_packidx *, int, off_t);
const struct got_error *got_packidx_open(struct got_packidx **,
    int, const char *, int);
const struct got_error *got_packidx_close(struct got_packidx *);
const struct got_error *got_packidx_get_packfile_path(char **, const char *);
off_t got_packidx_get_object_offset(struct got_packidx *, int idx);
int got_packidx_get_object_idx(struct got_packidx *, struct got_object_id *);
const struct got_error *got_packidx_get_offset_idx(int *, struct got_packidx *,
    off_t);
const struct got_error *got_packidx_get_object_id(struct got_object_id *,
    struct got_packidx *, int);
const struct got_error *got_packidx_match_id_str_prefix(
    struct got_object_id_queue *, struct got_packidx *, const char *);

const struct got_error *got_packfile_open_object(struct got_object **,
    struct got_pack *, struct got_packidx *, int, struct got_object_id *);
const struct got_error *got_pack_get_delta_chain_max_size(uint64_t *,
    struct got_delta_chain *, struct got_pack *);
const struct got_error *got_pack_get_max_delta_object_size(uint64_t *,
    struct got_object *, struct got_pack *);
const struct got_error *got_pack_dump_delta_chain_to_file(size_t *,
    struct got_delta_chain *, struct got_pack *, FILE *, FILE *, FILE *);
const struct got_error *got_pack_dump_delta_chain_to_mem(uint8_t **, size_t *,
    struct got_delta_chain *, struct got_pack *);
const struct got_error *got_packfile_extract_object(struct got_pack *,
    struct got_object *, FILE *, FILE *, FILE *);
const struct got_error *got_packfile_extract_object_to_mem(uint8_t **, size_t *,
    struct got_object *, struct got_pack *);
const struct got_error *got_packfile_extract_raw_delta(uint8_t **, size_t *,
    size_t *, off_t *, off_t *, off_t *, struct got_object_id *, uint64_t *,
    uint64_t *, struct got_pack *, struct got_packidx *, int);
