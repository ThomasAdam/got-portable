#!/bin/sh
#
# Copyright (c) 2022 Mikhail Pchelin <misha@freebsd.org>
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

test_wrong_commit() {
	local testroot=`test_init wrong_commit`

	echo "0054want aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa multi_ack \
side-band-64k ofs-delta" | ssh ${GOTD_DEVUSER}@127.0.0.1 \
		git-upload-pack '/test-repo' > $testroot/stdout \
		2>$testroot/stderr

	echo -n "0041ERR object aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
not found" > $testroot/stdout.expected

	echo "gotsh: object aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
not found" > $testroot/stderr.expected

	# We use OpenBSD cmp(1) offset extension
	cmp -s $testroot/stdout $testroot/stdout.expected 112 0
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "unexpected stdout" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "unexpected stderr" >&2
		test_done "$testroot" "1"
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_wrong_commit
