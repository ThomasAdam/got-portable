#!/bin/sh
#
# Copyright (c) 2025 Stefan Sperling <stsp@openbsd.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

test_init()
{
	local testname="$1"
	local no_tree="$2"
	if [ -z "$testname" ]; then
		echo "No test name provided" >&2
		return 1
	fi
	local testroot=`mktemp -d \
	    "$GOTSYSD_TEST_ROOT/gotsysd-test-$testname-XXXXXXXXXX"`

	got clone -q -i "${GOTSYSD_SSH_KEY}" \
		"ssh://${GOTSYSD_TEST_USER}@${VMIP}/${GOTSYS_REPO}" \
		$testroot/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		return 1
	fi

	echo "$testroot"
}

test_cleanup()
{
	return 0
}

test_done()
{
	local testroot="$1"
	local result="$2"
	if [ "$result" = "0" ]; then
		test_cleanup "$testroot" || return 1
		if [ -z "$GOT_TEST_QUIET" ]; then
			echo "ok"
		fi
	elif echo "$result" | grep -q "^xfail"; then
		# expected test failure; test reproduces an unfixed bug
		echo "$result"
		test_cleanup "$testroot" || return 1
	else
		echo "test failed; leaving test data in $testroot"
	fi
}
