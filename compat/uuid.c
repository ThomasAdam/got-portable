/*
 * Copyright (c) 2002,2005 Marcel Moolenaar
 * Copyright (c) 2002 Hiten Mahesh Pandya
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <uuid/uuid.h>

#include "got_compat.h"


int32_t uuid_equal(struct uuid* a, struct uuid* b, uint32_t* unused)
{
	return (uuid_compare(*(uuid_t *)a, *(uuid_t *)b) == 0);
}
int32_t uuid_is_nil(struct uuid* uuid, uint32_t* unused)
{
	return uuid_is_null(*(uuid_t *)uuid);
}
void uuid_create(uuid_t *uuid, uint32_t* status)
{
	*status = uuid_s_ok;
	return uuid_generate(*(uuid_t *)uuid);
}
void uuid_create_nil(struct uuid* uuid, uint32_t* unused)
{
	return uuid_clear(*(uuid_t *)uuid);
}
void uuid_from_string(const char* s, uuid_t *uuid, uint32_t *status)
{
  	*status = uuid_parse(s, *(uuid_t *)uuid);
}
void uuid_to_string(uuid_t *uuid, char** s, uint32_t *status)
{
	*s = malloc(36 + 1);  /* 36 byte uuid plus '\0' */
	if (*s == NULL) {
		fprintf(stderr, "uuid_to_string: fatal: malloc\n");
		exit (1);
	}
	uuid_unparse(*(uuid_t *)uuid, *s);
	*status = uuid_s_ok;
}
