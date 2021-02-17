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
