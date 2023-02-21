/* $OpenBSD: conf.c,v 1.107 2017/10/27 08:29:32 mpi Exp $	 */
/* $EOM: conf.c,v 1.48 2000/12/04 02:04:29 angelos Exp $	 */

/*
 * Copyright (c) 1998, 1999, 2000, 2001 Niklas Hallqvist.  All rights reserved.
 * Copyright (c) 2000, 2001, 2002 Håkan Olsson.  All rights reserved.
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "got_error.h"

#include "got_lib_gitconfig.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

#define LOG_MISC	0
#define LOG_REPORT	1
#ifdef GITCONFIG_DEBUG
#define LOG_DBG(x) log_debug x
#else
#define LOG_DBG(x)
#endif

#define log_print(...) fprintf(stderr, __VA_ARGS__)
#define log_error(...) fprintf(stderr, __VA_ARGS__)

#ifdef GITCONFIG_DEBUG
static void
log_debug(int cls, int level, const char *fmt, ...)
{
	va_list         ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	putc('\n', stderr);
}
#endif

struct got_gitconfig_trans {
	TAILQ_ENTRY(got_gitconfig_trans) link;
	int	 trans;
	enum got_gitconfig_op {
		CONF_SET, CONF_REMOVE, CONF_REMOVE_SECTION
	}	 op;
	char	*section;
	char	*tag;
	char	*value;
	int	 override;
	int	 is_default;
};

TAILQ_HEAD(got_gitconfig_trans_head, got_gitconfig_trans);

struct got_gitconfig_binding {
	LIST_ENTRY(got_gitconfig_binding) link;
	char	*section;
	char	*tag;
	char	*value;
	int	 is_default;
};

LIST_HEAD(got_gitconfig_bindings, got_gitconfig_binding);

struct got_gitconfig {
	struct got_gitconfig_bindings bindings[256];
	struct got_gitconfig_trans_head trans_queue;
	char	*addr;
	int	seq;
};

static __inline__ u_int8_t
conf_hash(const char *s)
{
	u_int8_t hash = 0;

	while (*s) {
		hash = ((hash << 1) | (hash >> 7)) ^ tolower((unsigned char)*s);
		s++;
	}
	return hash;
}

/*
 * Insert a tag-value combination from LINE (the equal sign is at POS)
 */
static int
conf_remove_now(struct got_gitconfig *conf, char *section, char *tag)
{
	struct got_gitconfig_binding *cb, *next;

	for (cb = LIST_FIRST(&conf->bindings[conf_hash(section)]); cb;
	    cb = next) {
		next = LIST_NEXT(cb, link);
		if (strcasecmp(cb->section, section) == 0 &&
		    strcasecmp(cb->tag, tag) == 0) {
			LIST_REMOVE(cb, link);
			LOG_DBG((LOG_MISC, 95, "[%s]:%s->%s removed", section,
			    tag, cb->value));
			free(cb->section);
			free(cb->tag);
			free(cb->value);
			free(cb);
			return 0;
		}
	}
	return 1;
}

static int
conf_remove_section_now(struct got_gitconfig *conf, char *section)
{
	struct got_gitconfig_binding *cb, *next;
	int	unseen = 1;

	for (cb = LIST_FIRST(&conf->bindings[conf_hash(section)]); cb;
	    cb = next) {
		next = LIST_NEXT(cb, link);
		if (strcasecmp(cb->section, section) == 0) {
			unseen = 0;
			LIST_REMOVE(cb, link);
			LOG_DBG((LOG_MISC, 95, "[%s]:%s->%s removed", section,
			    cb->tag, cb->value));
			free(cb->section);
			free(cb->tag);
			free(cb->value);
			free(cb);
		}
	}
	return unseen;
}

/*
 * Insert a tag-value combination from LINE (the equal sign is at POS)
 * into SECTION of our configuration database.
 */
static int
conf_set_now(struct got_gitconfig *conf, char *section, char *tag,
    char *value, int override, int is_default)
{
	struct got_gitconfig_binding *node = 0;

	if (override)
		conf_remove_now(conf, section, tag);
	else if (got_gitconfig_get_str(conf, section, tag)) {
		if (!is_default)
			LOG_DBG((LOG_MISC, 95,
			    "conf_set_now: duplicate tag [%s]:%s, "
			    "ignoring...", section, tag));
		return 1;
	}
	node = calloc(1, sizeof *node);
	if (!node) {
		log_error("conf_set_now: calloc (1, %lu) failed",
		    (unsigned long)sizeof *node);
		return 1;
	}
	node->section = node->tag = node->value = NULL;
	if ((node->section = strdup(section)) == NULL)
		goto fail;
	if ((node->tag = strdup(tag)) == NULL)
		goto fail;
	if ((node->value = strdup(value)) == NULL)
		goto fail;
	node->is_default = is_default;

	LIST_INSERT_HEAD(&conf->bindings[conf_hash(section)], node, link);
	LOG_DBG((LOG_MISC, 95, "conf_set_now: [%s]:%s->%s", node->section,
	    node->tag, node->value));
	return 0;
fail:
	free(node->value);
	free(node->tag);
	free(node->section);
	free(node);
	return 1;
}

/*
 * Parse the line LINE of SZ bytes.  Skip Comments, recognize section
 * headers and feed tag-value pairs into our configuration database.
 */
static const struct got_error *
conf_parse_line(char **section, struct got_gitconfig *conf, int trans,
    char *line, int ln, size_t sz)
{
	char	*val;
	size_t	 i;
	int	 j;

	/* Lines starting with '#' or ';' are comments.  */
	if (*line == '#' || *line == ';')
		return NULL;

	/* '[section]' parsing...  */
	if (*line == '[') {
		for (i = 1; i < sz; i++)
			if (line[i] == ']')
				break;
		free(*section);
		if (i == sz) {
			log_print("conf_parse_line: %d:"
			    "unmatched ']', ignoring until next section", ln);
			*section = NULL;
			return NULL;
		}
		*section = strndup(line + 1, i - 1);
		if (*section == NULL)
			return got_error_from_errno("strndup");
		return NULL;
	}
	while (sz > 0 && isspace((unsigned char)*line)) {
		line++;
		sz--;
	}

	/* Deal with assignments.  */
	for (i = 0; i < sz; i++)
		if (line[i] == '=') {
			/* If no section, we are ignoring the lines.  */
			if (!*section) {
				log_print("conf_parse_line: %d: ignoring line "
				    "due to no section", ln);
				return NULL;
			}
			line[strcspn(line, " \t=")] = '\0';
			val = line + i + 1 + strspn(line + i + 1, " \t");
			/* Skip trailing whitespace, if any */
			for (j = sz - (val - line) - 1; j > 0 &&
			    isspace((unsigned char)val[j]); j--)
				val[j] = '\0';
			/* XXX Perhaps should we not ignore errors?  */
			got_gitconfig_set(conf, trans, *section, line, val,
			    0, 0);
			return NULL;
		}
	/* Other non-empty lines are weird.  */
	i = strspn(line, " \t");
	if (line[i])
		log_print("conf_parse_line: %d: syntax error", ln);

	return NULL;
}

/* Parse the mapped configuration file.  */
static const struct got_error *
conf_parse(struct got_gitconfig *conf, int trans, char *buf, size_t sz)
{
	const struct got_error *err = NULL;
	char	*cp = buf;
	char	*bufend = buf + sz;
	char	*line, *section = NULL;
	int	ln = 1;

	line = cp;
	while (cp < bufend) {
		if (*cp == '\n') {
			/* Check for escaped newlines.  */
			if (cp > buf && *(cp - 1) == '\\')
				*(cp - 1) = *cp = ' ';
			else {
				*cp = '\0';
				err = conf_parse_line(&section, conf, trans,
				    line, ln, cp - line);
				if (err)
					return err;
				line = cp + 1;
			}
			ln++;
		}
		cp++;
	}
	if (cp != line)
		log_print("conf_parse: last line unterminated, ignored.");
	return NULL;
}

const struct got_error *
got_gitconfig_open(struct got_gitconfig **conf, int fd)
{
	size_t i;

	*conf = calloc(1, sizeof(**conf));
	if (*conf == NULL)
		return got_error_from_errno("malloc");

	for (i = 0; i < nitems((*conf)->bindings); i++)
		LIST_INIT(&(*conf)->bindings[i]);
	TAILQ_INIT(&(*conf)->trans_queue);
	return got_gitconfig_reinit(*conf, fd);
}

static void
conf_clear(struct got_gitconfig *conf)
{
	struct got_gitconfig_binding *cb;
	size_t i;

	if (conf->addr) {
		for (i = 0; i < nitems(conf->bindings); i++)
			for (cb = LIST_FIRST(&conf->bindings[i]); cb;
			    cb = LIST_FIRST(&conf->bindings[i]))
				conf_remove_now(conf, cb->section, cb->tag);
		free(conf->addr);
		conf->addr = NULL;
	}
}

/* Execute all queued operations for this transaction.  Cleanup.  */
static int
conf_end(struct got_gitconfig *conf, int transaction, int commit)
{
	struct got_gitconfig_trans *node, *next;

	for (node = TAILQ_FIRST(&conf->trans_queue); node; node = next) {
		next = TAILQ_NEXT(node, link);
		if (node->trans == transaction) {
			if (commit)
				switch (node->op) {
				case CONF_SET:
					conf_set_now(conf, node->section,
					    node->tag, node->value,
					    node->override, node->is_default);
					break;
				case CONF_REMOVE:
					conf_remove_now(conf, node->section,
					    node->tag);
					break;
				case CONF_REMOVE_SECTION:
					conf_remove_section_now(conf, node->section);
					break;
				default:
					log_print("got_gitconfig_end: unknown "
					    "operation: %d", node->op);
				}
			TAILQ_REMOVE(&conf->trans_queue, node, link);
			free(node->section);
			free(node->tag);
			free(node->value);
			free(node);
		}
	}
	return 0;
}


void
got_gitconfig_close(struct got_gitconfig *conf)
{
	conf_clear(conf);
	free(conf);
}

static int
conf_begin(struct got_gitconfig *conf)
{
	return ++conf->seq;
}

/* Open the config file and map it into our address space, then parse it.  */
const struct got_error *
got_gitconfig_reinit(struct got_gitconfig *conf, int fd)
{
	const struct got_error *err = NULL;
	int	 trans;
	size_t	 sz;
	char	*new_conf_addr = 0;
	struct stat st;

	if (fstat(fd, &st)) {
		err = got_error_from_errno("fstat");
		goto fail;
	}

	sz = st.st_size;
	new_conf_addr = malloc(sz);
	if (new_conf_addr == NULL) {
		err = got_error_from_errno("malloc");
		goto fail;
	}
	/* XXX I assume short reads won't happen here.  */
	if (read(fd, new_conf_addr, sz) != (int)sz) {
		err = got_error_from_errno("read");
		goto fail;
	}

	trans = conf_begin(conf);

	err = conf_parse(conf, trans, new_conf_addr, sz);
	if (err)
		goto fail;

	/* Free potential existing configuration.  */
	conf_clear(conf);
	conf_end(conf, trans, 1);
	conf->addr = new_conf_addr;
	return NULL;

fail:
	free(new_conf_addr);
	return err;
}

/*
 * Return the numeric value denoted by TAG in section SECTION or DEF
 * if that tag does not exist.
 */
int
got_gitconfig_get_num(struct got_gitconfig *conf, const char *section,
    const char *tag, int def)
{
	char	*value = got_gitconfig_get_str(conf, section, tag);

	if (value)
		return atoi(value);
	return def;
}

/* Validate X according to the range denoted by TAG in section SECTION.  */
int
got_gitconfig_match_num(struct got_gitconfig *conf, char *section, char *tag,
    int x)
{
	char	*value = got_gitconfig_get_str(conf, section, tag);
	int	 val, min, max, n;

	if (!value)
		return 0;
	n = sscanf(value, "%d,%d:%d", &val, &min, &max);
	switch (n) {
	case 1:
		LOG_DBG((LOG_MISC, 95, "got_gitconfig_match_num: %s:%s %d==%d?",
		    section, tag, val, x));
		return x == val;
	case 3:
		LOG_DBG((LOG_MISC, 95, "got_gitconfig_match_num: %s:%s %d<=%d<=%d?",
		    section, tag, min, x, max));
		return min <= x && max >= x;
	default:
		log_error("got_gitconfig_match_num: section %s tag %s: invalid number "
		    "spec %s", section, tag, value);
	}
	return 0;
}

/* Return the string value denoted by TAG in section SECTION.  */
char *
got_gitconfig_get_str(struct got_gitconfig *conf, const char *section,
    const char *tag)
{
	struct got_gitconfig_binding *cb;

	for (cb = LIST_FIRST(&conf->bindings[conf_hash(section)]); cb;
	    cb = LIST_NEXT(cb, link))
		if (strcasecmp(section, cb->section) == 0 &&
		    strcasecmp(tag, cb->tag) == 0) {
			LOG_DBG((LOG_MISC, 95, "got_gitconfig_get_str: [%s]:%s->%s",
			    section, tag, cb->value));
			return cb->value;
		}
	LOG_DBG((LOG_MISC, 95,
	    "got_gitconfig_get_str: configuration value not found [%s]:%s", section,
	    tag));
	return 0;
}

const struct got_error *
got_gitconfig_get_section_list(struct got_gitconfig_list **sections,
    struct got_gitconfig *conf)
{
	const struct got_error *err = NULL;
	struct got_gitconfig_list *list = NULL;
	struct got_gitconfig_list_node *node = 0;
	struct got_gitconfig_binding *cb;
	size_t i;

	*sections = NULL;

	list = malloc(sizeof *list);
	if (!list)
		return got_error_from_errno("malloc");
	TAILQ_INIT(&list->fields);
	list->cnt = 0;
	for (i = 0; i < nitems(conf->bindings); i++) {
		for (cb = LIST_FIRST(&conf->bindings[i]); cb;
		    cb = LIST_NEXT(cb, link)) {
			int section_present = 0;
			TAILQ_FOREACH(node, &list->fields, link) {
				if (strcmp(node->field, cb->section) == 0) {
					section_present = 1;
					break;
				}
			}
			if (section_present)
				continue;
			list->cnt++;
			node = calloc(1, sizeof *node);
			if (!node) {
				err = got_error_from_errno("calloc");
				goto cleanup;
			}
			node->field = strdup(cb->section);
			if (!node->field) {
				err = got_error_from_errno("strdup");
				goto cleanup;
			}
			TAILQ_INSERT_TAIL(&list->fields, node, link);
		}
	}

	*sections = list;
	return NULL;

cleanup:
	free(node);
	if (list)
		got_gitconfig_free_list(list);
	return err;
}

/*
 * Build a list of string values out of the comma separated value denoted by
 * TAG in SECTION.
 */
struct got_gitconfig_list *
got_gitconfig_get_list(struct got_gitconfig *conf, char *section, char *tag)
{
	char	*liststr = 0, *p, *field, *t;
	struct got_gitconfig_list *list = 0;
	struct got_gitconfig_list_node *node = 0;

	list = malloc(sizeof *list);
	if (!list)
		goto cleanup;
	TAILQ_INIT(&list->fields);
	list->cnt = 0;
	liststr = got_gitconfig_get_str(conf, section, tag);
	if (!liststr)
		goto cleanup;
	liststr = strdup(liststr);
	if (!liststr)
		goto cleanup;
	p = liststr;
	while ((field = strsep(&p, ",")) != NULL) {
		/* Skip leading whitespace */
		while (isspace((unsigned char)*field))
			field++;
		/* Skip trailing whitespace */
		if (p)
			for (t = p - 1; t > field && isspace((unsigned char)*t); t--)
				*t = '\0';
		if (*field == '\0') {
			log_print("got_gitconfig_get_list: empty field, ignoring...");
			continue;
		}
		list->cnt++;
		node = calloc(1, sizeof *node);
		if (!node)
			goto cleanup;
		node->field = strdup(field);
		if (!node->field)
			goto cleanup;
		TAILQ_INSERT_TAIL(&list->fields, node, link);
	}
	free(liststr);
	return list;

cleanup:
	free(node);
	if (list)
		got_gitconfig_free_list(list);
	free(liststr);
	return 0;
}

struct got_gitconfig_list *
got_gitconfig_get_tag_list(struct got_gitconfig *conf, const char *section)
{
	struct got_gitconfig_list *list = 0;
	struct got_gitconfig_list_node *node = 0;
	struct got_gitconfig_binding *cb;

	list = malloc(sizeof *list);
	if (!list)
		goto cleanup;
	TAILQ_INIT(&list->fields);
	list->cnt = 0;
	for (cb = LIST_FIRST(&conf->bindings[conf_hash(section)]); cb;
	    cb = LIST_NEXT(cb, link))
		if (strcasecmp(section, cb->section) == 0) {
			list->cnt++;
			node = calloc(1, sizeof *node);
			if (!node)
				goto cleanup;
			node->field = strdup(cb->tag);
			if (!node->field)
				goto cleanup;
			TAILQ_INSERT_TAIL(&list->fields, node, link);
		}
	return list;

cleanup:
	free(node);
	if (list)
		got_gitconfig_free_list(list);
	return 0;
}

void
got_gitconfig_free_list(struct got_gitconfig_list *list)
{
	struct got_gitconfig_list_node *node = TAILQ_FIRST(&list->fields);

	while (node) {
		TAILQ_REMOVE(&list->fields, node, link);
		free(node->field);
		free(node);
		node = TAILQ_FIRST(&list->fields);
	}
	free(list);
}

static int
got_gitconfig_trans_node(struct got_gitconfig *conf, int transaction,
    enum got_gitconfig_op op, char *section, char *tag, char *value,
    int override, int is_default)
{
	struct got_gitconfig_trans *node;

	node = calloc(1, sizeof *node);
	if (!node) {
		log_error("got_gitconfig_trans_node: calloc (1, %lu) failed",
		    (unsigned long)sizeof *node);
		return 1;
	}
	node->trans = transaction;
	node->op = op;
	node->override = override;
	node->is_default = is_default;
	if (section && (node->section = strdup(section)) == NULL)
		goto fail;
	if (tag && (node->tag = strdup(tag)) == NULL)
		goto fail;
	if (value && (node->value = strdup(value)) == NULL)
		goto fail;
	TAILQ_INSERT_TAIL(&conf->trans_queue, node, link);
	return 0;

fail:
	free(node->section);
	free(node->tag);
	free(node->value);
	free(node);
	return 1;
}

/* Queue a set operation.  */
int
got_gitconfig_set(struct got_gitconfig *conf, int transaction, char *section,
    char *tag, char *value, int override, int is_default)
{
	return got_gitconfig_trans_node(conf, transaction, CONF_SET, section,
	    tag, value, override, is_default);
}

/* Queue a remove operation.  */
int
got_gitconfig_remove(struct got_gitconfig *conf, int transaction,
    char *section, char *tag)
{
	return got_gitconfig_trans_node(conf, transaction, CONF_REMOVE,
	    section, tag, NULL, 0, 0);
}

/* Queue a remove section operation.  */
int
got_gitconfig_remove_section(struct got_gitconfig *conf, int transaction,
    char *section)
{
	return got_gitconfig_trans_node(conf, transaction, CONF_REMOVE_SECTION,
	    section, NULL, NULL, 0, 0);
}
