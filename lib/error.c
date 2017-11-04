#include "got_error.h"

#define nitems(a) (sizeof(a) / sizeof((a)[0]))

const struct got_error *
got_error(int code)
{
	int i;

	for (i = 0; i < nitems(got_errors); i++) {
		if (code == got_errors[i].code)
			return &got_errors[i];
	}

	return &got_errors[GOT_ERR_UNKNOWN];
}
