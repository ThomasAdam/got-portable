#!/bin/sh
#
# Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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

. ../cmdline/common.sh
. ./common.sh

test_clone_basic_access_denied() {
	local testroot=`test_init clone_basic_access_denied 1`

	cp -r ${GOTD_TEST_REPO} $testroot/repo-copy

	got clone -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone \
		2> $testroot/stderr.raw
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got clone succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	grep -v ^gotsh: $testroot/stderr.raw > $testroot/stderr

	# Verify that the clone operation failed.
	echo 'got-fetch-pack: test-repo: Permission denied' \
		> $testroot/stderr.expected
	echo 'got: fetch failed' >> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_clone_basic_access_denied
