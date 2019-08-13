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

function test_log_in_repo {
	local testroot=`test_init log_in_repo`
	local head_rev=`git_show_head $testroot/repo`

	echo "commit $head_rev (master)" > $testroot/stdout.expected

	for p in "" "." alpha epsilon epsilon/zeta; do
		(cd $testroot/repo && got log $p | \
			grep ^commit > $testroot/stdout)
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret="$?"
		if [ "$ret" != "0" ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	for p in "" "." zeta; do
		(cd $testroot/repo/epsilon && got log $p | \
			grep ^commit > $testroot/stdout)
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret="$?"
		if [ "$ret" != "0" ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	test_done "$testroot" "0"
}

function test_log_in_bare_repo {
	local testroot=`test_init log_in_bare_repo`
	local head_rev=`git_show_head $testroot/repo`

	echo "commit $head_rev (master)" > $testroot/stdout.expected

	for p in "" "." alpha epsilon epsilon/zeta; do
		(cd $testroot/repo/.git && got log $p | \
			grep ^commit > $testroot/stdout)
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret="$?"
		if [ "$ret" != "0" ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	test_done "$testroot" "0"
}

function test_log_in_worktree {
	local testroot=`test_init log_in_worktree`
	local head_rev=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "commit $head_rev (master)" > $testroot/stdout.expected

	for p in "" "." alpha epsilon; do
		(cd $testroot/wt && got log $p | \
			grep ^commit > $testroot/stdout)
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret="$?"
		if [ "$ret" != "0" ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	for p in "" "." zeta; do
		(cd $testroot/wt/epsilon && got log $p | \
			grep ^commit > $testroot/stdout)
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret="$?"
		if [ "$ret" != "0" ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	test_done "$testroot" "0"
}

function test_log_tag {
	local testroot=`test_init log_tag`
	local commit_id=`git_show_head $testroot/repo`
	local tag="1.0.0"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git tag -a -m "test" $tag)

	echo "commit $commit_id (master, tags/$tag)" > $testroot/stdout.expected
	(cd $testroot/wt && got log -l1 -c $tag | grep ^commit \
		> $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}


run_test test_log_in_repo
run_test test_log_in_bare_repo
run_test test_log_in_worktree
run_test test_log_tag
