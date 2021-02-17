/* $OpenBSD$ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Versions of malloc and friends that check their results, and never return
 * failure (they call fatalx if they encounter an error).
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "got_compat.h"

#include "xmalloc.h"

void *
xmalloc(size_t size)
{
	void *ptr;

	if (size == 0) {
		fprintf(stderr,"xmalloc: zero size");
		exit (1);
	}
	ptr = malloc(size);
	if (ptr == NULL) {
		fprintf(stderr, "xmalloc: allocating %zu bytes: %s",
		    size, strerror(errno));
		exit (1);
	}
	return ptr;
}

void *
xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	if (size == 0 || nmemb == 0)
		fprintf(stderr,"xcalloc: zero size");
	ptr = calloc(nmemb, size);
	if (ptr == NULL) {
		fprintf(stderr, "xcalloc: allocating %zu * %zu bytes: %s",
		    nmemb, size, strerror(errno));
		exit (1);
	}
	return ptr;
}

void *
xrealloc(void *ptr, size_t size)
{
	return xreallocarray(ptr, 1, size);
}

void *
xreallocarray(void *ptr, size_t nmemb, size_t size)
{
	void *new_ptr;

	if (nmemb == 0 || size == 0) {
		fprintf(stderr, "xreallocarray: zero size");
		exit (1);
	}
	new_ptr = reallocarray(ptr, nmemb, size);
	if (new_ptr == NULL) {
		fprintf(stderr, "xreallocarray: allocating %zu * %zu bytes: %s",
		    nmemb, size, strerror(errno));
		exit (1);
	}
	return new_ptr;
}

void *
xrecallocarray(void *ptr, size_t oldnmemb, size_t nmemb, size_t size)
{
	void *new_ptr;

	if (nmemb == 0 || size == 0) {
		fprintf(stderr,"xrecallocarray: zero size");
		exit (1);
	}
	new_ptr = recallocarray(ptr, oldnmemb, nmemb, size);
	if (new_ptr == NULL) {
		fprintf(stderr,"xrecallocarray: allocating %zu * %zu bytes: %s",
		    nmemb, size, strerror(errno));
		exit (1);
	}
	return new_ptr;
}

char *
xstrdup(const char *str)
{
	char *cp;

	if ((cp = strdup(str)) == NULL) {
		fprintf(stderr,"xstrdup: %s", strerror(errno));
		exit (1);
	}
	return cp;
}

char *
xstrndup(const char *str, size_t maxlen)
{
	char *cp;

	if ((cp = strndup(str, maxlen)) == NULL) {
		fprintf(stderr,"xstrndup: %s", strerror(errno));
		exit (1);
	}
	return cp;
}

int
xasprintf(char **ret, const char *fmt, ...)
{
	va_list ap;
	int i;

	va_start(ap, fmt);
	i = xvasprintf(ret, fmt, ap);
	va_end(ap);

	return i;
}

int
xvasprintf(char **ret, const char *fmt, va_list ap)
{
	int i;

	i = vasprintf(ret, fmt, ap);

	if (i == -1) {
		fprintf(stderr,"xasprintf: %s", strerror(errno));
		exit  (1);
	}

	return i;
}

int
xsnprintf(char *str, size_t len, const char *fmt, ...)
{
	va_list ap;
	int i;

	va_start(ap, fmt);
	i = xvsnprintf(str, len, fmt, ap);
	va_end(ap);

	return i;
}

int
xvsnprintf(char *str, size_t len, const char *fmt, va_list ap)
{
	int i;

	if (len > INT_MAX)
		fprintf(stderr,"xsnprintf: len > INT_MAX");

	i = vsnprintf(str, len, fmt, ap);

	if (i < 0 || i >= (int)len) {
		fprintf(stderr,"xsnprintf: overflow");
		exit (1);
	}

	return i;
}
