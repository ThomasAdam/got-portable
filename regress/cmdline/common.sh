#!/bin/sh
#
# Copyright (c) 2019, 2020 Stefan Sperling <stsp@openbsd.org>
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

export GIT_AUTHOR_NAME="Flan Hacker"
export GIT_AUTHOR_EMAIL="flan_hacker@openbsd.org"
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME"
export GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
export GOT_AUTHOR="$GIT_AUTHOR_NAME <$GIT_AUTHOR_EMAIL>"
export GOT_AUTHOR_8="flan_hac"
export GOT_LOG_DEFAULT_LIMIT=0

export MALLOC_OPTIONS=S

function git_init
{
	git init -q "$1"
}

function maybe_pack_repo
{
	local repo="$1"
	if [ -n "$GOT_TEST_PACK" ]; then
		(cd $repo && git repack -a -q)
	fi
}

function git_commit
{
	local repo="$1"
	shift
	(cd $repo && git commit --author="$GOT_AUTHOR" -q -a "$@")
	maybe_pack_repo $repo
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

function git_show_branch_head
{
	local repo="$1"
	local branch="$2"
	(cd $repo && git show --no-patch --pretty='format:%H' $branch)
}


function git_show_author_time
{
	local repo="$1"
	local object="$2"
	(cd $repo && git show --no-patch --pretty='format:%at' $object)
}

function git_show_tagger_time
{
	local repo="$1"
	local tag="$2"
	(cd $repo && git cat-file tag $tag | grep ^tagger | \
		sed -e "s/^tagger $GOT_AUTHOR//" | cut -d' ' -f2)
}

function git_show_parent_commit
{
	local repo="$1"
	local commit="$2"
	(cd $repo && git show --no-patch --pretty='format:%P' $commit)
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
	maybe_pack_repo $repo
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

function make_single_file_repo
{
	repo="$1"
	file="$2"

	mkdir $repo
	git_init $repo
	echo "this is file $file" > $repo/$file
	(cd $repo && git add .)
	git_commit $repo -m "intialize $repo with file $file"
}

function get_loose_object_path
{
	local repo="$1"
	local id="$2"
	local id0=`trim_obj_id 38 $id`
	local idrest=`echo ${id#[0-9a-f][0-9a-f]}`
	echo "$repo/.git/objects/$id0/$idrest"
}

function get_blob_id
{
	repo="$1"
	tree_path="$2"
	filename="$3"

	got tree -r $repo -i $tree_path | grep "[0-9a-f] ${filename}$" | \
		cut -d' ' -f 1
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
	touch $testroot/repo/.git/git-daemon-export-ok
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
