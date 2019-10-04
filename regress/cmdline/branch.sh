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

function test_branch_create {
	local testroot=`test_init branch_create`

	# Create a branch based on repository's HEAD reference
	got branch -r $testroot/repo newbranch
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got branch command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure that Git recognizes the branch Got has created
	(cd $testroot/repo && git checkout -q newbranch)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "git checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	got checkout -b newbranch $testroot/repo $testroot/wt >/dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified delta on branch" > $testroot/content.expected
	cat $testroot/wt/gamma/delta > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# Create a branch based on the work tree's branch
	(cd $testroot/wt && got branch anotherbranch)
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git checkout -q anotherbranch)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "git checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Create a branch based on another specific branch
	(cd $testroot/wt && got branch yetanotherbranch master)
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git checkout -q yetanotherbranch)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "git checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Create a branch based on a specific commit
	local commit_id=`git_show_head $testroot/repo`
	got branch -r $testroot/repo commitbranch $commit_id
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got branch command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git checkout -q commitbranch)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "git checkout command failed unexpectedly"
	fi
	test_done "$testroot" "$ret"
}

function test_branch_list {
	local testroot=`test_init branch_list`
	local commit_id=`git_show_head $testroot/repo`

	for b in branch1 branch2 branch3; do
		got branch -r $testroot/repo $b
		ret="$?"
		if [ "$ret" != "0" ]; then
			echo "got branch command failed unexpectedly"
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	got branch -l -r $testroot/repo > $testroot/stdout
	echo "  branch1: $commit_id" > $testroot/stdout.expected
	echo "  branch2: $commit_id" >> $testroot/stdout.expected
	echo "  branch3: $commit_id" >> $testroot/stdout.expected
	echo "  master: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got checkout $testroot/repo $testroot/wt >/dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got branch -l > $testroot/stdout)
	echo "  branch1: $commit_id" > $testroot/stdout.expected
	echo "  branch2: $commit_id" >> $testroot/stdout.expected
	echo "  branch3: $commit_id" >> $testroot/stdout.expected
	echo "* master: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified delta" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta"
	local commit_id2=`git_show_head $testroot/repo`

	(cd $testroot/wt && got branch -l > $testroot/stdout)
	echo "  branch1: $commit_id" > $testroot/stdout.expected
	echo "  branch2: $commit_id" >> $testroot/stdout.expected
	echo "  branch3: $commit_id" >> $testroot/stdout.expected
	echo "~ master: $commit_id2" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update > /dev/null)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got update command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got branch -l > $testroot/stdout)
	echo "  branch1: $commit_id" > $testroot/stdout.expected
	echo "  branch2: $commit_id" >> $testroot/stdout.expected
	echo "  branch3: $commit_id" >> $testroot/stdout.expected
	echo "* master: $commit_id2" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update -b branch1 > /dev/null)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got update command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got branch -l > $testroot/stdout)
	echo "* branch1: $commit_id" > $testroot/stdout.expected
	echo "  branch2: $commit_id" >> $testroot/stdout.expected
	echo "  branch3: $commit_id" >> $testroot/stdout.expected
	echo "  master: $commit_id2" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_branch_delete {
	local testroot=`test_init branch_delete`
	local commit_id=`git_show_head $testroot/repo`

	for b in branch1 branch2 branch3; do
		got branch -r $testroot/repo $b
		ret="$?"
		if [ "$ret" != "0" ]; then
			echo "got branch command failed unexpectedly"
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	got branch -d branch2 -r $testroot/repo > $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got update command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -l -r $testroot/repo > $testroot/stdout
	echo "  branch1: $commit_id" > $testroot/stdout.expected
	echo "  branch3: $commit_id" >> $testroot/stdout.expected
	echo "  master: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo > $testroot/stdout
	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/branch1: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/branch3: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -d bogus_branch_name -r $testroot/repo \
		> $testroot/stdout 2> $testroot/stderr
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "got update succeeded unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: reference refs/heads/bogus_branch_name not found" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

function test_branch_delete_current_branch {
	local testroot=`test_init branch_delete_current_branch`
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt >/dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got branch -d master > $testroot/stdout \
		2> $testroot/stderr)

	echo "got: will not delete this work tree's current branch" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

function test_branch_delete_packed {
	local testroot=`test_init branch_delete_packed`
	local commit_id=`git_show_head $testroot/repo`

	for b in branch1 branch2 branch3; do
		got branch -r $testroot/repo $b
		ret="$?"
		if [ "$ret" != "0" ]; then
			echo "got branch command failed unexpectedly"
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	(cd $testroot/repo && git pack-refs --all)

	got branch -d branch2 -r $testroot/repo > $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got update command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -l -r $testroot/repo > $testroot/stdout
	echo "  branch1: $commit_id" > $testroot/stdout.expected
	echo "  branch3: $commit_id" >> $testroot/stdout.expected
	echo "  master: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo > $testroot/stdout
	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/branch1: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/branch3: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -d bogus_branch_name -r $testroot/repo \
		> $testroot/stdout 2> $testroot/stderr
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "got update succeeded unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: reference refs/heads/bogus_branch_name not found" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

function test_branch_show {
	local testroot=`test_init branch_show`
	local commit_id=`git_show_head $testroot/repo`

	for b in branch1 branch2 branch3; do
		got branch -r $testroot/repo $b
		ret="$?"
		if [ "$ret" != "0" ]; then
			echo "got branch command failed unexpectedly"
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	got checkout $testroot/repo $testroot/wt >/dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got branch > $testroot/stdout)
	echo "master" > $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update -b branch1 > /dev/null)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got update command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got branch > $testroot/stdout)
	echo "branch1" > $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

run_test test_branch_create
run_test test_branch_list
run_test test_branch_delete
run_test test_branch_delete_current_branch
run_test test_branch_delete_packed
run_test test_branch_show
