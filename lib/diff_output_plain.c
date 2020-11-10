/* Output all lines of a diff_result. */
/*
 * Copyright (c) 2020 Neels Hofmeyr <neels@hofmeyr.de>
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

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

#include <arraylist.h>
#include <diff_main.h>
#include <diff_output.h>

#include "diff_internal.h"

int
diff_output_plain(struct diff_output_info **output_info, FILE *dest,
		 const struct diff_input_info *info,
		 const struct diff_result *result)
{
	struct diff_output_info *outinfo = NULL;
	int i, rc;

	if (!result)
		return EINVAL;
	if (result->rc != DIFF_RC_OK)
		return result->rc;
	
	if (output_info) {
		*output_info = diff_output_info_alloc();
		if (*output_info == NULL)
			return errno;
		outinfo = *output_info;
	}

	for (i = 0; i < result->chunks.len; i++) {
		struct diff_chunk *c = &result->chunks.head[i];
		if (c->left_count && c->right_count)
			rc = diff_output_lines(outinfo, dest,
					  c->solved ? " " : "?",
					  c->left_start, c->left_count);
		else if (c->left_count && !c->right_count)
			rc = diff_output_lines(outinfo, dest,
					  c->solved ? "-" : "?",
					  c->left_start, c->left_count);
		else if (c->right_count && !c->left_count)
			rc = diff_output_lines(outinfo, dest,
					  c->solved ? "+" : "?",
					  c->right_start, c->right_count);
		if (rc)
			return rc;
	}
	return DIFF_RC_OK;
}
