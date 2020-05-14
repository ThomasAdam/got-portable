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

function test_cherrypick_basic {
	local testroot=`test_init cherrypick_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git checkout -q -b newbranch)
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	echo "modified alpha on branch" > $testroot/repo/alpha
	(cd $testroot/repo && git rm -q beta)
	echo "new file on branch" > $testroot/repo/epsilon/new
	(cd $testroot/repo && git add epsilon/new)
	git_commit $testroot/repo -m "committing more changes on newbranch"

	local branch_rev=`git_show_head $testroot/repo`

	(cd $testroot/wt && got cherrypick $branch_rev > $testroot/stdout)

	echo "G  alpha" > $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo "Merged commit $branch_rev" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha on branch" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/beta ]; then
		echo "removed file beta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "new file on branch" > $testroot/content.expected
	cat $testroot/wt/epsilon/new > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'M  alpha' > $testroot/stdout.expected
	echo 'D  beta' >> $testroot/stdout.expected
	echo 'A  epsilon/new' >> $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_cherrypick_root_commit {
	local testroot=`test_init cherrypick_root_commit`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git checkout -q -b newbranch)
	(cd $testroot/repo && git rm -q alpha)
	(cd $testroot/repo && git rm -q beta)
	(cd $testroot/repo && git rm -q epsilon/zeta)
	(cd $testroot/repo && git rm -q gamma/delta)
	mkdir -p $testroot/repo/epsilon
	echo "new file on branch" > $testroot/repo/epsilon/new
	(cd $testroot/repo && git add epsilon/new)
	git_commit $testroot/repo -m "committing on newbranch"

	echo "modified new file on branch" >> $testroot/repo/epsilon/new
	git_commit $testroot/repo -m "committing on newbranch again"

	tree=`git_show_tree $testroot/repo`
	root_commit=`git_commit_tree $testroot/repo "new root commit" $tree`

	(cd $testroot/wt && got cherrypick $root_commit > $testroot/stdout)

	echo "A  epsilon/new" > $testroot/stdout.expected
	echo "Merged commit $root_commit" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file on branch" > $testroot/content.expected
	echo "modified new file on branch" >> $testroot/content.expected
	cat $testroot/wt/epsilon/new > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'A  epsilon/new' > $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_cherrypick_into_work_tree_with_conflicts {
	local testroot=`test_init cherrypick_into_work_tree_with_conflicts`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git checkout -q -b newbranch)
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	echo "modified alpha on branch" > $testroot/repo/alpha
	(cd $testroot/repo && git rm -q beta)
	echo "new file on branch" > $testroot/repo/epsilon/new
	(cd $testroot/repo && git add epsilon/new)
	git_commit $testroot/repo -m "committing more changes on newbranch"

	local branch_rev=`git_show_head $testroot/repo`

	# fake a merge conflict
	echo '<<<<<<<' > $testroot/wt/alpha
	echo 'alpha' >> $testroot/wt/alpha
	echo '=======' >> $testroot/wt/alpha
	echo 'alpha, too' >> $testroot/wt/alpha
	echo '>>>>>>>' >> $testroot/wt/alpha
	cp $testroot/wt/alpha $testroot/content.expected

	echo "C  alpha" > $testroot/stdout.expected
	(cd $testroot/wt && got status  > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got cherrypick $branch_rev \
		> $testroot/stdout 2> $testroot/stderr)
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "cherrypick succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	echo -n "got: work tree contains conflicted files; " \
		> $testroot/stderr.expected
	echo "these conflicts must be resolved first" \
		>> $testroot/stderr.expected

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
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/content.expected $testroot/wt/alpha
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/wt/alpha
	fi
	test_done "$testroot" "$ret"
}

function test_cherrypick_modified_submodule {
	local testroot=`test_init cherrypick_modified_submodules`

	make_single_file_repo $testroot/repo2 foo

	(cd $testroot/repo && git submodule -q add ../repo2)
	(cd $testroot/repo && git commit -q -m 'adding submodule')

	got checkout $testroot/repo $testroot/wt > /dev/null

	echo "modified foo" > $testroot/repo2/foo
	(cd $testroot/repo2 && git commit -q -a -m 'modified a submodule')

	(cd $testroot/repo && git checkout -q -b newbranch)
	# Update the repo/repo2 submodule link on newbranch
	(cd $testroot/repo && git -C repo2 pull -q)
	(cd $testroot/repo && git add repo2)
	git_commit $testroot/repo -m "modified submodule link"
	local commit_id=`git_show_head $testroot/repo`

	# This cherrypick is a no-op because Got's file index
	# does not track submodules.
	(cd $testroot/wt && got cherrypick $commit_id > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_cherrypick_added_submodule {
	local testroot=`test_init cherrypick_added_submodules`

	got checkout $testroot/repo $testroot/wt > /dev/null

	make_single_file_repo $testroot/repo2 foo

	# Add the repo/repo2 submodule on newbranch
	(cd $testroot/repo && git checkout -q -b newbranch)
	(cd $testroot/repo && git submodule -q add ../repo2)
	(cd $testroot/repo && git commit -q -m 'adding submodule')
	local commit_id=`git_show_head $testroot/repo`

	(cd $testroot/wt && got cherrypick $commit_id > $testroot/stdout)

	echo "A  .gitmodules" > $testroot/stdout.expected
	echo "Merged commit $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_cherrypick_conflict_wt_file_vs_repo_submodule {
	local testroot=`test_init cherrypick_conflict_wt_file_vs_repo_submodule`

	got checkout $testroot/repo $testroot/wt > /dev/null

	# Add a file which will clash with the submodule
	echo "This is a file called repo2" > $testroot/wt/repo2
	(cd $testroot/wt && got add repo2 > /dev/null)
	(cd $testroot/wt && got commit -m 'add file repo2' > /dev/null)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "commit failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	make_single_file_repo $testroot/repo2 foo

	# Add the repo/repo2 submodule on newbranch
	(cd $testroot/repo && git checkout -q -b newbranch)
	(cd $testroot/repo && git submodule -q add ../repo2)
	(cd $testroot/repo && git commit -q -m 'adding submodule')
	local commit_id=`git_show_head $testroot/repo`

	# Modify the clashing file such that any modifications brought
	# in by 'got cherrypick' would require a merge.
	echo "This file was changed" > $testroot/wt/repo2

	(cd $testroot/wt && got update >/dev/null)
	(cd $testroot/wt && got cherrypick $commit_id > $testroot/stdout)

	echo "A  .gitmodules" > $testroot/stdout.expected
	echo "Merged commit $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo "A  .gitmodules" > $testroot/stdout.expected
	echo "M  repo2" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

run_test test_cherrypick_basic
run_test test_cherrypick_root_commit
run_test test_cherrypick_into_work_tree_with_conflicts
run_test test_cherrypick_modified_submodule
run_test test_cherrypick_added_submodule
run_test test_cherrypick_conflict_wt_file_vs_repo_submodule
