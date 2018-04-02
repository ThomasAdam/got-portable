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
 * All code runs under the same UID but sensitive code paths are
 * run in a separate process with tighter pledge(2) promises.
 * Data is communicated between processes via imsg_read(3)/imsg_compose(3).
 * This behaviour is transparent to users of the library.
 *
 * File descriptor passing is used in cases where sizes exceed MAX_IMSGSIZE.
 *
 * We currently do not exec(2) after a fork(2).
 * To achieve fork+exec, releveant parts of our library functionality could
 * be made accessible via separate executables in a libexec directory.
 */

enum got_imsg_type {
	/*
	 * Messages concerned with read access to objects in a repository.
	 * Object and pack files are opened by the main process, where
	 * data may be read as a byte string but without any interpretation.
	 * Decompression and parsing of object and pack files occurs in a
	 * separate process which runs under pledge("stdio").
	 * This sandboxes our own repository parsing code, as well as zlib.
	 */
	GOT_IMSG_READ_LOOSE_OBJECT_HEADER_REQUEST,
	GOT_IMSG_READ_LOOSE_OBJECT_HEADER_REPLY,
	GOT_IMSG_DELTA,
	GOT_IMSG_READ_LOOSE_BLOB_OBJECT_REQUEST,
	GOT_IMSG_READ_LOOSE_BLOB_OBJECT_REPLY,
	GOT_IMSG_READ_LOOSE_TREE_OBJECT_REQUEST,
	GOT_IMSG_READ_LOOSE_TREE_OBJECT_REPLY,
	GOT_IMSG_READ_LOOSE_COMMIT_OBJECT_REQUEST,
	GOT_IMSG_READ_LOOSE_COMMIT_OBJECT_REPLY,
	GOT_IMSG_READ_PACKED_BLOB_OBJECT_REQUEST,
	GOT_IMSG_READ_PACKED_BLOB_OBJECT_REPLY,
	GOT_IMSG_READ_PACKED_TREE_OBJECT_REQUEST,
	GOT_IMSG_READ_PACKED_TREE_OBJECT_REPLY,
	GOT_IMSG_READ_PACKED_COMMIT_OBJECT_REQUEST,
	GOT_IMSG_READ_PACKED_COMMIT_OBJECT_REPLY
};

/* Structure for GOT_IMSG_READ_LOOSE_OBJECT_HEADER_REQUEST data. */
struct got_imsg_read_loose_object_header_request {
	/*
	 * Empty since the following is implied: If imsg fd == -1 then
	 * read raw object data from imsg buffer, else read from fd.
	 */
};

/* Structure for GOT_IMSG_READ_LOOSE_OBJECT_HEADER_REPLY data. */
struct got_imsg_read_loose_object_header_reply {
	/* These fields are the same as in struct got_object. */
	int type;
	int flags;
	size_t hdrlen;
	size_t size;
	struct got_object_id id;

	int ndeltas; /* this many GOT_IMSG_DELTA messages follow */
};

/* Structure for GOT_IMSG_DELTA data. */
struct got_imsg_delta {
	/* These fields are the same as in struct got_delta. */
	off_t offset;
	size_t tslen;
	int type;
	size_t size;
	off_t data_offset;
	size_t delta_len;

	/*
	 * Followed by raw delta data: If imsg fd == -1 then read
	 * delta data from imsg buffer, else read from fd.
	 */
};

/* TODO: Implement the above, and then add more message data types here. */
