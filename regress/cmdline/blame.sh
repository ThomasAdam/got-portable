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

function test_blame_basic {
	local testroot=`test_init blame_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 1 > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 1" > /dev/null)
	local commit1=`git_show_head $testroot/repo`

	echo 2 >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 2" > /dev/null)
	local commit2=`git_show_head $testroot/repo`

	echo 3 >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 3" > /dev/null)
	local commit3=`git_show_head $testroot/repo`

	(cd $testroot/wt && got blame alpha > $testroot/stdout)

	local short_commit1=`trim_obj_id 32 $commit1`
	local short_commit2=`trim_obj_id 32 $commit2`
	local short_commit3=`trim_obj_id 32 $commit3`

	echo "1) $short_commit1 $GOT_AUTHOR_8 1" > $testroot/stdout.expected
	echo "2) $short_commit2 $GOT_AUTHOR_8 2" >> $testroot/stdout.expected
	echo "3) $short_commit3 $GOT_AUTHOR_8 3" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	test_done "$testroot" "$ret"
}

function test_blame_tag {
	local testroot=`test_init blame_tag`
	local tag=1.0.0

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi
	echo 1 > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 1" > /dev/null)
	local commit1=`git_show_head $testroot/repo`

	echo 2 >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 2" > /dev/null)
	local commit2=`git_show_head $testroot/repo`

	(cd $testroot/repo && git tag -a -m "test" $tag)

	echo 3 >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 3" > /dev/null)
	local commit3=`git_show_head $testroot/repo`

	(cd $testroot/wt && got blame -c $tag alpha > $testroot/stdout)

	local short_commit1=`trim_obj_id 32 $commit1`
	local short_commit2=`trim_obj_id 32 $commit2`

	echo "1) $short_commit1 $GOT_AUTHOR_8 1" > $testroot/stdout.expected
	echo "2) $short_commit2 $GOT_AUTHOR_8 2" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_blame_file_single_line {
	local testroot=`test_init blame_file_single_line`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 1 > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 1" > /dev/null)
	local commit1=`git_show_head $testroot/repo`

	(cd $testroot/wt && got blame alpha > $testroot/stdout)

	local short_commit1=`trim_obj_id 32 $commit1`

	echo "1) $short_commit1 $GOT_AUTHOR_8 1" > $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_blame_file_single_line_no_newline {
	local testroot=`test_init blame_file_single_line_no_newline`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n 1 > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 1" > /dev/null)
	local commit1=`git_show_head $testroot/repo`

	(cd $testroot/wt && got blame alpha > $testroot/stdout)

	local short_commit1=`trim_obj_id 32 $commit1`

	echo "1) $short_commit1 $GOT_AUTHOR_8 1" > $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

run_test test_blame_basic
run_test test_blame_tag
run_test test_blame_file_single_line
run_test test_blame_file_single_line_no_newline
