/* $OpenBSD: conf.h,v 1.34 2006/08/30 16:56:56 hshoexer Exp $	 */
/* $EOM: conf.h,v 1.13 2000/09/18 00:01:47 ho Exp $	 */

/*
 * Copyright (c) 1998, 1999, 2001 Niklas Hallqvist.  All rights reserved.
 * Copyright (c) 2000, 2003 Håkan Olsson.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

struct got_gitconfig_list_node {
	TAILQ_ENTRY(got_gitconfig_list_node) link;
	char	*field;
};

struct got_gitconfig_list {
	size_t	cnt;
	TAILQ_HEAD(got_gitconfig_list_fields_head, got_gitconfig_list_node) fields;
};

struct got_gitconfig;

void     got_gitconfig_free_list(struct got_gitconfig_list *);
const struct got_error *got_gitconfig_get_section_list(
    struct got_gitconfig_list **, struct got_gitconfig *);
struct got_gitconfig_list *got_gitconfig_get_list(struct got_gitconfig *,
    char *, char *);
struct got_gitconfig_list *got_gitconfig_get_tag_list(struct got_gitconfig *,
    const char *);
int got_gitconfig_get_num(struct got_gitconfig *, const char *, const char *,
    int);
char *got_gitconfig_get_str(struct got_gitconfig *, const char *,
    const char *);
const struct got_error *got_gitconfig_open(struct got_gitconfig **, int);
void got_gitconfig_close(struct got_gitconfig *);
int      got_gitconfig_match_num(struct got_gitconfig *, char *, char *, int);
const struct got_error *got_gitconfig_reinit(struct got_gitconfig *, int);
int      got_gitconfig_remove(struct got_gitconfig *, int, char *, char *);
int      got_gitconfig_remove_section(struct got_gitconfig *, int, char *);
int      got_gitconfig_set(struct got_gitconfig *, int, char *, char *, char *,
    int, int);
