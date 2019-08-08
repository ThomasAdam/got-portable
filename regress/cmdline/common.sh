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

export GOT_AUTHOR="Flan Hacker <flan_hacker@openbsd.org>"

export MALLOC_OPTIONS=S

function git_init
{
	git init -q "$@"
}

function git_commit
{
	local repo="$1"
	shift
	(cd $repo && git commit -q -a "$@")
}

function git_rm
{
	local repo="$1"
	shift
	(cd $repo && git rm -q "$@")
}

function git_show_head
{
	local repo="$1"
	(cd $repo && git show --no-patch --pretty='format:%H')
}

function git_show_parent_commit
{
	local repo="$1"
	(cd $repo && git show --no-patch --pretty='format:%P')
}

function git_show_tree
{
	local repo="$1"
	(cd $repo && git show --no-patch --pretty='format:%T')
}

function trim_obj_id
{
	let trimcount=$1
	id=$2

	pat=""
	while [ trimcount -gt 0 ]; do
		pat="[0-9a-f]$pat"
		let trimcount--
	done

	echo ${id%$pat}
}

function git_commit_tree
{
	local repo="$1"
	local msg="$2"
	local tree="$3"
	(cd $repo && git commit-tree -m "$msg" "$tree")
}

function make_test_tree
{
	repo="$1"

	echo alpha > $repo/alpha
	echo beta > $repo/beta
	mkdir $repo/gamma
	echo delta > $repo/gamma/delta
	mkdir $repo/epsilon
	echo zeta > $repo/epsilon/zeta
}

function get_blob_id
{
	repo="$1"
	tree_path="$2"
	filename="$3"

	got tree -r $repo -i $tree_path | grep ${filename}$ | cut -d' ' -f 1
}

function test_init
{
	local testname="$1"
	local no_tree="$2"
	if [ -z "$testname" ]; then
		echo "No test name provided" >&2
		return 1
	fi
	local testroot=`mktemp -p /tmp -d got-test-$testname-XXXXXXXX`
	mkdir $testroot/repo
	git_init $testroot/repo
	if [ -z "$no_tree" ]; then
		make_test_tree $testroot/repo
		(cd $repo && git add .)
		git_commit $testroot/repo -m "adding the test tree"
	fi
	echo "$testroot"
}

function test_cleanup
{
	local testroot="$1"

	(cd $testroot/repo && git fsck --strict \
		> $testroot/fsck.stdout 2> $testroot/fsck.stderr)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo -n "git fsck: "
		cat $testroot/fsck.stderr
		echo "git fsck failed; leaving test data in $testroot"
		return 1
	fi

	rm -rf "$testroot"
}

function run_test
{
	testfunc="$1"
	echo -n "$testfunc "
	$testfunc
}

function test_done
{
	local testroot="$1"
	local result="$2"
	if [ "$result" == "0" ]; then
		test_cleanup "$testroot" || return 1
		echo "ok"
	elif echo "$result" | grep -q "^xfail"; then
		# expected test failure; test reproduces an unfixed bug
		echo "$result"
		test_cleanup "$testroot" || return 1
	else
		echo "test failed; leaving test data in $testroot"
	fi
}
