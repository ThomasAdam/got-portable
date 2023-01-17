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

enum got_diff_algorithm {
	GOT_DIFF_ALGORITHM_MYERS,
	GOT_DIFF_ALGORITHM_PATIENCE,
};

/*
 * List of all line types in a diff (including '{got,tog} log' lines).
 * XXX GOT_DIFF_LINE_HUNK to GOT_DIFF_LINE_NONE inclusive must map to the
 * DIFF_LINE_* macro counterparts defined in lib/diff_output.h (i.e., 60-64).
 */
enum got_diff_line_type {
	GOT_DIFF_LINE_LOGMSG,
	GOT_DIFF_LINE_AUTHOR,
	GOT_DIFF_LINE_DATE,
	GOT_DIFF_LINE_CHANGES,
	GOT_DIFF_LINE_META,
	GOT_DIFF_LINE_BLOB_MIN,
	GOT_DIFF_LINE_BLOB_PLUS,
	GOT_DIFF_LINE_HUNK = 60,
	GOT_DIFF_LINE_MINUS,
	GOT_DIFF_LINE_PLUS,
	GOT_DIFF_LINE_CONTEXT,
	GOT_DIFF_LINE_NONE
};

struct got_diff_line {
	off_t	offset;
	uint8_t	type;
};

struct got_diffstat_cb_arg;

/*
 * Compute the differences between two blobs and write unified diff text
 * to the provided output file. Two open temporary files must be provided
 * for internal use; these files can be obtained from got_opentemp() and
 * must be closed by the caller.
 * If one of the blobs being diffed does not exist, all corresponding
 * blob object arguments should be set to NULL.
 * Two const char * diff header labels may be provided which will be used
 * to identify each blob in the diff output.
 * If a label is NULL, use the blob's SHA1 checksum instead.
 * The number of context lines to show in the diff must be specified as well.
 * Whitespace differences may optionally be ignored.
 * If not NULL, the two initial output arguments will be populated with an
 * array of line offsets for, and the number of lines in, the unidiff text.
 */
const struct got_error *got_diff_blob(struct got_diff_line **, size_t *,
    struct got_blob_object *, struct got_blob_object *, FILE *, FILE *,
    const char *, const char *, enum got_diff_algorithm, int, int, int,
    struct got_diffstat_cb_arg *, FILE *);

/*
 * Compute the differences between a blob and a file and write unified diff
 * text to the provided output file. The blob object, its content, and its
 * size must be provided. The file's size must be provided, as well as a
 * const char * diff header label which identifies the file.
 * An optional const char * diff header label for the blob may be provided, too.
 * The number of context lines to show in the diff must be specified as well.
 * Whitespace differences may optionally be ignored.
 */
const struct got_error *got_diff_blob_file(struct got_blob_object *, FILE *,
    off_t, const char *, FILE *, int, struct stat *, const char *,
    enum got_diff_algorithm, int, int, int, struct got_diffstat_cb_arg *,
    FILE *);

/*
 * A callback function invoked to handle the differences between two blobs
 * when diffing trees with got_diff_tree(). This callback receives two blobs,
 * their respective IDs, and two corresponding paths within the diffed trees.
 * The first blob contains content from the old side of the diff, and
 * the second blob contains content on the new side of the diff.
 * Two open temporary files must be provided for internal use; these files
 * can be obtained from got_opentemp() and must be closed by the caller.
 * The blob object argument for either blob may be NULL to indicate
 * that no content is present on its respective side of the diff.
 * File modes from relevant tree objects which contain the blobs may
 * also be passed. These will be zero if not available.
 */
typedef const struct got_error *(*got_diff_blob_cb)(void *,
    struct got_blob_object *, struct got_blob_object *, FILE *, FILE *,
    struct got_object_id *, struct got_object_id *,
    const char *, const char *, mode_t, mode_t, struct got_repository *);

/*
 * A pre-defined implementation of got_diff_blob_cb() which appends unidiff
 * output to a file. The caller must allocate and fill in the argument
 * structure.
 */
struct got_diff_blob_output_unidiff_arg {
	FILE *outfile;		/* Unidiff text will be written here. */
	int diff_context;	/* Sets the number of context lines. */
	int ignore_whitespace;	/* Ignore whitespace differences. */
	int force_text_diff;	/* Assume text even if binary data detected. */
	struct got_diffstat_cb_arg *diffstat; /* Compute diffstat of changes */
	enum got_diff_algorithm diff_algo; /* Diffing algorithm to use. */

	/*
	 * The number of lines contained in produced unidiff text output,
	 * and an array of got_diff_lines with byte offset and line type to
	 * each line. May be initialized to zero and NULL to ignore line
	 * metadata. If not NULL, then the array of line offsets and types will
	 * be populated. Optionally, the array can be pre-populated with line
	 * offsets and types, with nlines > 0 indicating the length of the
	 * pre-populated array.  This is useful if the output file already
	 * contains some lines of text.  The array will be grown as needed to
	 * accomodate additional offsets and types, and the last offset found
	 * in a pre-populated array will be added to all subsequent offsets.
	 */
	size_t nlines;
	struct got_diff_line *lines; /* Dispose of with free(3) when done. */
};
const struct got_error *got_diff_blob_output_unidiff(void *,
    struct got_blob_object *, struct got_blob_object *, FILE *, FILE *,
    struct got_object_id *, struct got_object_id *,
    const char *, const char *, mode_t, mode_t, struct got_repository *);

/*
 * Compute the differences between two trees and invoke the provided
 * got_diff_blob_cb() callback when content differs.
 * Diffing of blob content can be suppressed by passing zero for the
 * 'diff_content' parameter. The callback will then only receive blob
 * object IDs and diff labels, but NULL pointers instead of blob objects.
 * If 'diff_content' is set, two open temporary FILEs and two open
 * temporary file descriptors must be provided for internal use; these
 * files can be obtained from got_opentemp() and got_opentempfd(),
 * and must be closed by the caller. Otherwise the files can be NULL.
 * The set of arguments relating to either tree may be NULL to indicate
 * that no content is present on its respective side of the diff.
 */
const struct got_error *got_diff_tree(struct got_tree_object *,
    struct got_tree_object *, FILE *, FILE *, int, int,
    const char *, const char *,
    struct got_repository *, got_diff_blob_cb cb, void *cb_arg, int);

/*
 * Pre-defined implementations of got_diff_blob_cb(): the first of which
 * collects a list of file paths that differ between two trees; the second
 * also computes a diffstat of added/removed lines for each collected path
 * and requires passing an initialized got_diffstat_cb_arg argument.
 * The caller must allocate and initialize a got_pathlist_head * argument.
 * Data pointers of entries added to the path list will point to a struct
 * got_diff_changed_path object.
 * The caller is expected to free both the path and data pointers of all
 * entries on the path list.
 */
struct got_diff_changed_path {
	uint32_t add;	/* number of lines added */
	uint32_t rm;	/* number of lines removed */
	/*
	 * The modification status of this path. It can be GOT_STATUS_ADD,
	 * GOT_STATUS_DELETE, GOT_STATUS_MODIFY, or GOT_STATUS_MODE_CHANGE.
	 */
	int status;
};
const struct got_error *got_diff_tree_collect_changed_paths(void *,
    struct got_blob_object *, struct got_blob_object *, FILE *, FILE *,
    struct got_object_id *, struct got_object_id *,
    const char *, const char *, mode_t, mode_t, struct got_repository *);

struct got_diffstat_cb_arg {
	size_t max_path_len;
	uint32_t ins;
	uint32_t del;
	int add_cols;
	int rm_cols;
	int nfiles;
	struct got_pathlist_head *paths;
	int ignore_ws;
	int force_text;
	enum got_diff_algorithm diff_algo;
};
const struct got_error *got_diff_tree_compute_diffstat(void *,
    struct got_blob_object *, struct got_blob_object *, FILE *, FILE *,
    struct got_object_id *, struct got_object_id *, const char *, const char *,
    mode_t, mode_t, struct got_repository *);

/*
 * Diff two objects, assuming both objects are blobs. Two const char * diff
 * header labels may be provided which will be used to identify each blob in
 * the diff output. If a label is NULL, use the blob's SHA1 checksum instead.
 * Two open temporary files and two temporary file descriptors must be
 * provided for internal use; these files can be obtained from
 * got_opentemp() and got_opentempfd(), and must be closed by the caller.
 * The set of arguments relating to either blob may be NULL/-1 to indicate
 * that no content is present on its respective side of the diff.
 * The number of context lines to show in the diff must be specified as well.
 * Write unified diff text to the provided output FILE.
 * If not NULL, the two initial output arguments will be populated with an
 * array of line offsets for, and the number of lines in, the unidiff text.
 */
const struct got_error *got_diff_objects_as_blobs(struct got_diff_line **,
    size_t *, FILE *, FILE *, int, int, struct got_object_id *,
    struct got_object_id *, const char *, const char *, enum got_diff_algorithm,
    int, int, int, struct got_diffstat_cb_arg *, struct got_repository *,
    FILE *);

struct got_pathlist_head;

/*
 * Diff two objects, assuming both objects are trees. Two const char * diff
 * header labels may be provided which will be used to identify each blob in
 * the trees. If a label is NULL, use the blob's SHA1 checksum instead.
 * The number of context lines to show in diffs must be specified.
 * Two open temporary files and two temporary file descriptors must be
 * provided for internal use; these files can be obtained from
 * got_opentemp() and got_opentempfd(), and must be closed by the caller.
 * If 'diff_content' is not set, the files may be NULL / -1.
 * The set of arguments relating to either tree may be NULL to indicate
 * that no content is present on its respective side of the diff.
 * Write unified diff text to the provided output FILE.
 * If not NULL, the two initial output arguments will be populated with an
 * array of line offsets for, and the number of lines in, the unidiff text.
 */
const struct got_error *got_diff_objects_as_trees(struct got_diff_line **,
    size_t *, FILE *, FILE *, int, int, struct got_object_id *,
    struct got_object_id *, struct got_pathlist_head *, const char *,
    const char *, enum got_diff_algorithm, int, int, int,
    struct got_diffstat_cb_arg *, struct got_repository *, FILE *);

/*
 * Diff two objects, assuming both objects are commits.
 * The number of context lines to show in diffs must be specified.
 * Two open temporary files and two temporary file descriptors must be
 * provided for internal use; these files can be obtained from
 * got_opentemp() and got_opentempfd(), and must be closed by the caller.
 * The set of arguments relating to either commit may be NULL to indicate
 * that no content is present on its respective side of the diff.
 * Write unified diff text to the provided output FILE.
 * If not NULL, the two initial output arguments will be populated with an
 * array of line offsets for, and the number of lines in, the unidiff text.
 */
const struct got_error *got_diff_objects_as_commits(struct got_diff_line **,
    size_t *, FILE *, FILE *, int, int, struct got_object_id *,
    struct got_object_id *, struct got_pathlist_head *, enum got_diff_algorithm,
    int, int, int, struct got_diffstat_cb_arg *, struct got_repository *,
    FILE *);

#define GOT_DIFF_MAX_CONTEXT	64
