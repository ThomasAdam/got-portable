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

function test_commit_basic {
	local testroot=`test_init commit_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta >/dev/null)
	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)

	(cd $testroot/wt && got commit -m 'test commit_basic' > $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "A  new" > $testroot/stdout.expected
	echo "M  alpha" >> $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_commit_new_subdir {
	local testroot=`test_init commit_new_subdir`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/wt/d
	echo "new file" > $testroot/wt/d/new
	echo "another new file" > $testroot/wt/d/new2
	(cd $testroot/wt && got add d/new >/dev/null)
	(cd $testroot/wt && got add d/new2 >/dev/null)

	(cd $testroot/wt && \
		got commit -m 'test commit_new_subdir' > $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "A  d/new" > $testroot/stdout.expected
	echo "A  d/new2" >> $testroot/stdout.expected
	echo "created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_commit_subdir {
	local testroot=`test_init commit_subdir`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	echo "modified zeta" > $testroot/wt/epsilon/zeta

	(cd $testroot/wt && \
		got commit -m 'test commit_subdir' epsilon > $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "M  epsilon/zeta" >> $testroot/stdout.expected
	echo "created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_commit_single_file {
	local testroot=`test_init commit_single_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	echo "modified zeta" > $testroot/wt/epsilon/zeta

	(cd $testroot/wt && got commit -m 'test commit_subdir' epsilon/zeta \
		> $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "M  epsilon/zeta" >> $testroot/stdout.expected
	echo "created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_commit_out_of_date {
	local testroot=`test_init commit_out_of_date`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"

	echo "modified alpha" > $testroot/wt/alpha

	(cd $testroot/wt && got commit -m 'test commit_out_of_date' \
		> $testroot/stdout 2> $testroot/stderr)

	local head_rev=`git_show_head $testroot/repo`
	echo -n > $testroot/stdout.expected
	echo "got: work tree must be updated before these" \
		"changes can be committed" > $testroot/stderr.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

function test_commit_added_subdirs {
	local testroot=`test_init commit_added_subdirs`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/wt/d
	echo "new file" > $testroot/wt/d/new
	echo "new file 2" > $testroot/wt/d/new2
	mkdir -p $testroot/wt/d/f
	echo "new file 3" > $testroot/wt/d/f/new3
	mkdir -p $testroot/wt/d/f/g
	echo "new file 4" > $testroot/wt/d/f/g/new4

	(cd $testroot/wt && got add $testroot/wt/*/new* \
		$testroot/wt/*/*/new* $testroot/wt/*/*/*/new* > /dev/null)

	(cd $testroot/wt && got commit -m 'test commit_added_subdirs' \
		> $testroot/stdout 2> $testroot/stderr)

	local head_rev=`git_show_head $testroot/repo`
	echo "A  d/f/new3" > $testroot/stdout.expected
	echo "A  d/f/g/new4" >> $testroot/stdout.expected
	echo "A  d/new" >> $testroot/stdout.expected
	echo "A  d/new2" >> $testroot/stdout.expected
	echo "created commit $head_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		#diff -u $testroot/stdout.expected $testroot/stdout
		ret="xfail ($(head -n 1 $testroot/stderr))"
	fi
	test_done "$testroot" "$ret"
}

run_test test_commit_basic
run_test test_commit_new_subdir
run_test test_commit_subdir
run_test test_commit_single_file
run_test test_commit_out_of_date
run_test test_commit_added_subdirs
