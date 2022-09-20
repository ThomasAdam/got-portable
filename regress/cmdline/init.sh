#!/bin/sh
#
# Copyright (c) 2022 Mark Jamsek <mark@jamsek.dev>
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

test_init_basic() {
	local testname=init_basic
	local testroot=`mktemp -d "$GOT_TEST_ROOT/got-test-$testname-XXXXXXXX"`
	local headref=main

	gotadmin init $testroot/repo

	local git_head=`(cd $testroot/repo && git symbolic-ref HEAD)`
	echo $git_head > $testroot/content
	echo refs/heads/$headref > $testroot/content.expected
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "fail"
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_init_specified_head() {
	local testname=init_specified_head
	local testroot=`mktemp -d "$GOT_TEST_ROOT/got-test-$testname-XXXXXXXX"`
	local headref=trunk

	gotadmin init -b $headref $testroot/repo

	local git_head=`(cd $testroot/repo && git symbolic-ref HEAD)`
	echo refs/heads/$headref > $testroot/content.expected
	echo $git_head > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "fail"
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_init_basic
run_test test_init_specified_head
