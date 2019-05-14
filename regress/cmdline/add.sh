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

function test_add_basic {
	local testroot=`test_init add_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/wt/foo

	echo 'A  foo' > $testroot/stdout.expected
	(cd $testroot/wt && got add foo > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_double_add {
	local testroot=`test_init double_add`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/wt/foo
	(cd $testroot/wt && got add foo > /dev/null)

	(cd $testroot/wt && got add foo)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got add failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" "$ret"
}

function test_add_multiple {
	local testroot=`test_init multiple_add`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/wt/foo
	echo "new file" > $testroot/wt/bar
	echo "new file" > $testroot/wt/baz
	(cd $testroot/wt && got add foo bar baz > $testroot/stdout)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got add failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "A  bar" > $testroot/stdout.expected
	echo "A  baz" >> $testroot/stdout.expected
	echo "A  foo" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

run_test test_add_basic
run_test test_double_add
run_test test_add_multiple
