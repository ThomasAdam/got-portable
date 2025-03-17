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

. ../cmdline/common.sh
. ./common.sh

test_connection_limit_exceeded() {
	local testroot=`test_init connection_limit_exceeded 1`

	# The gotd.conf connection limit is 2
	xargs -P 3 -I {} sh -c 'eval "$1"' - {} \
		> /dev/null 2> $testroot/stderr <<EOF
ssh ${GOTD_DEVUSER}@127.0.0.1 \"git-upload-pack ${GOTD_TEST_REPO_NAME}\"
ssh ${GOTD_DEVUSER}@127.0.0.1 \"git-upload-pack ${GOTD_TEST_REPO_NAME}\"
ssh ${GOTD_DEVUSER}@127.0.0.1 \"git-upload-pack ${GOTD_TEST_REPO_NAME}\"
EOF
	cat > $testroot/stderr.expected <<EOF
gotsh: connection limit exceeded
gotsh: unexpected end of file
gotsh: unexpected end of file
EOF
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "0"
}

run_test test_connection_limit_exceeded
