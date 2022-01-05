/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/time.h>

#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <time.h>

#include "got_lib_ratelimit.h"

#include "got_compat.h"
#include "got_error.h"

void
got_ratelimit_init(struct got_ratelimit *rl, time_t interval_sec,
    unsigned int interval_msec)
{
	memset(rl, 0, sizeof(*rl));
	rl->interval.tv_sec = interval_sec;
	rl->interval.tv_nsec = interval_msec * 1000000UL;
}

const struct got_error *
got_ratelimit_check(int *elapsed, struct got_ratelimit *rl)
{
	struct timespec now, delta;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return got_error_from_errno("clock_gettime");

	if (timespecisset(&rl->last)) {
		timespecsub(&now, &rl->last, &delta);
		*elapsed = timespeccmp(&delta, &rl->interval, >=) ? 1 : 0;
	} else
		*elapsed = 1;

	if (*elapsed)
		rl->last = now;

	return NULL;
}
