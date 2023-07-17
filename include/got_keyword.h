/*
 * Copyright (c) 2023 Mark Jamsek <mark@jamsek.dev>
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
 * Commit keywords to specify references in the repository
 * (cf. svn keywords, fossil special tags, hg revsets).
 */
#define GOT_KEYWORD_BASE	"base"	/* work tree base commit */
#define GOT_KEYWORD_HEAD	"head"	/* worktree/repo HEAD commit */

/*
 * Parse a commit id string for keywords and/or lineage modifiers "(+|-)[N]".
 * Valid keywords are "base" or "head" and must be prefixed with a ":".
 * Lineage modifiers must be prefixed with a ":" and may suffix keywords or
 * reference names:
 *    :keyword:(+/-)N	Nth generation descendant/antecedent of keyword
 *    :keyword:(+/-)	1st generation descendant/antecedent of keyword
 *    :keyword		commit pointed to by keyword
 *    ref:(+/-)[N]	Nth generation descendant/antecedent of ref
 * If a match is found, return the corresponding commit id string in the
 * char ** out parameter, of which the caller takes ownership and must free.
 * Otherwise it will contain NULL, indicating a match was not found.
 * If the modifier is greater than the number of ancestors/descendants, the id
 * string of the oldest/most recent commit (i.e., ROOT/HEAD) will be returned.
 */
const struct got_error *got_keyword_to_idstr(char **, const char *,
    struct got_repository *, struct got_worktree *);
