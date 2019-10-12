

/*ROR
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)diff.h	8.1 (Berkeley) 6/6/93
 */

#include <sys/types.h>
#include <regex.h>

/*
 * Output format options
 */
#define	D_NORMAL	0	/* Normal output */
#define	D_UNIFIED	3	/* Unified context diff */
#define	D_BRIEF		6	/* Say if the files differ */

/*
 * Output flags
 */
#define	D_HEADER	0x001	/* Print a header/footer between files */
#define	D_EMPTY1	0x002	/* Treat first file as empty (/dev/null) */
#define	D_EMPTY2	0x004	/* Treat second file as empty (/dev/null) */

/*
 * Command line flags
 */
#define D_FORCEASCII	0x008	/* Treat file as ascii regardless of content */
#define D_FOLDBLANKS	0x010	/* Treat all white space as equal */
#define D_MINIMAL	0x020	/* Make diff as small as possible */
#define D_IGNORECASE	0x040	/* Case-insensitive matching */
#define D_PROTOTYPE	0x080	/* Display C function prototype */
#define D_EXPANDTABS	0x100	/* Expand tabs to spaces */
#define D_IGNOREBLANKS	0x200	/* Ignore white space changes */

/*
 * Status values for got_diffreg() return values
 */
#define	D_SAME		0	/* Files are the same */
#define	D_DIFFER	1	/* Files are different */
#define	D_BINARY	2	/* Binary files are different */
#define	D_MISMATCH1	3	/* path1 was a dir, path2 a file */
#define	D_MISMATCH2	4	/* path1 was a file, path2 a dir */
#define	D_SKIPPED1	5	/* path1 was a special file */
#define	D_SKIPPED2	6	/* path2 was a special file */

struct excludes {
	char *pattern;
	struct excludes *next;
};

/*
 * The following struct is used to record change information when
 * doing a "context" or "unified" diff.  (see routine "change" to
 * understand the highly mnemonic field names)
 */
struct context_vec {
	int	a;		/* start line in old file */
	int	b;		/* end line in old file */
	int	c;		/* start line in new file */
	int	d;		/* end line in new file */
};

struct got_diff_change {
	SIMPLEQ_ENTRY(got_diff_change) entry;
	struct context_vec cv;
};

struct got_diff_changes {
	int nchanges;
	SIMPLEQ_HEAD(, got_diff_change) entries;
};

struct got_diff_state {
	int  *J;			/* will be overlaid on class */
	int  *class;		/* will be overlaid on file[0] */
	int  *klist;		/* will be overlaid on file[0] after class */
	int  *member;		/* will be overlaid on file[1] */
	int   clen;
	int   len[2];
	int   pref, suff;	/* length of prefix and suffix */
	int   slen[2];
	int   anychange;
	long *ixnew;		/* will be overlaid on file[1] */
	long *ixold;		/* will be overlaid on klist */
	struct cand *clist;	/* merely a free storage pot for candidates */
	int   clistlen;		/* the length of clist */
	struct line *sfile[2];	/* shortened by pruning common prefix/suffix */
	u_char *chrtran;		/* translation table for case-folding */
	struct context_vec *context_vec_start;
	struct context_vec *context_vec_end;
	struct context_vec *context_vec_ptr;
	struct line *file[2];
#define FUNCTION_CONTEXT_SIZE	55
	char lastbuf[FUNCTION_CONTEXT_SIZE];
	int lastline;
	int lastmatchline;
	struct stat stb1, stb2;
	size_t max_context;
};

void got_diff_state_free(struct got_diff_state *);

struct got_diff_args {
	int	 Tflag;
	int	 diff_format, diff_context, status;
	char	 *diffargs;
	const char *label[2];
};

#define GOT_DIFF_CONFLICT_MARKER_BEGIN	"<<<<<<<"
#define GOT_DIFF_CONFLICT_MARKER_ORIG	"|||||||"
#define GOT_DIFF_CONFLICT_MARKER_SEP	"======="
#define GOT_DIFF_CONFLICT_MARKER_END	">>>>>>>"

const struct got_error *got_diffreg(int *, FILE *,
    FILE *, int, struct got_diff_args *, struct got_diff_state *, FILE *,
    struct got_diff_changes *);

const struct got_error *got_diff_blob_lines_changed(struct got_diff_changes **,
    struct got_blob_object *, struct got_blob_object *);
const struct got_error *got_diff_blob_file_lines_changed(struct got_diff_changes **,
    struct got_blob_object *, FILE *, size_t);
void got_diff_free_changes(struct got_diff_changes *);

const struct got_error *got_merge_diff3(int *, int, const char *, const char *,
    const char *, const char *, const char *);

const struct got_error *got_diff_files(struct got_diff_changes **,
    struct got_diff_state **, struct got_diff_args **, int *, FILE *, size_t,
    const char *, FILE *, size_t, const char *, int, FILE *);

void got_diff_dump_change(FILE *, struct got_diff_change *,
    struct got_diff_state *, struct got_diff_args *, FILE *, FILE *, int);
