#!/bin/sh
#
# Copyright (c) 2019 Stefan Sperling <stsp@openbsd.org>
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

. ./common.sh

function test_status_basic {
	local testroot=`test_init status_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	if [ "$?" != "0" ]; then
		test_done "$testroot" "$?"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	echo "unversioned file" > $testroot/wt/foo
	rm $testroot/wt/epsilon/zeta

	echo 'M  alpha' > $testroot/stdout.expected
	echo '!  epsilon/zeta' >> $testroot/stdout.expected
	echo '?  foo' >> $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp $testroot/stdout.expected $testroot/stdout
	if [ "$?" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$?"
		return 1
	fi

	test_done "$testroot" "0"
}

run_test test_status_basic
