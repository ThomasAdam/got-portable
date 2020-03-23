#!/bin/sh
#
# Copyright (c) 2020 Tracey Emery <tracey@openbsd.org>
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

function test_tree_basic {
	local testroot=`test_init tree_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null

	echo "new file" > $testroot/wt/foo

	(cd $testroot/wt && got add foo > /dev/null)
	(cd $testroot/wt && got commit -m "add foo" foo >/dev/null)

	echo 'alpha' > $testroot/stdout.expected
	echo 'beta' >> $testroot/stdout.expected
	echo 'epsilon/' >> $testroot/stdout.expected
	echo 'foo' >> $testroot/stdout.expected
	echo 'gamma/' >> $testroot/stdout.expected

	(cd $testroot/wt && got tree > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	test_done "$testroot" "$ret"
}

function test_tree_branch {
	local testroot=`test_init tree_branch`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got br foo > $testroot/stdout)

	echo "new file" > $testroot/wt/foo

	(cd $testroot/wt && got add foo > /dev/null)
	(cd $testroot/wt && got commit -m "add foo" foo >/dev/null)

	echo 'alpha' > $testroot/stdout.expected
	echo 'beta' >> $testroot/stdout.expected
	echo 'epsilon/' >> $testroot/stdout.expected
	echo 'foo' >> $testroot/stdout.expected
	echo 'gamma/' >> $testroot/stdout.expected

	(cd $testroot/wt && got tree > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	test_done "$testroot" "$ret"
}

run_test test_tree_basic
run_test test_tree_branch
