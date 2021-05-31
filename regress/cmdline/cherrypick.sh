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

test_cherrypick_basic() {
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

test_cherrypick_root_commit() {
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

test_cherrypick_into_work_tree_with_conflicts() {
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
	if [ "$ret" = "0" ]; then
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

test_cherrypick_modified_submodule() {
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

test_cherrypick_added_submodule() {
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

test_cherrypick_conflict_wt_file_vs_repo_submodule() {
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

test_cherrypick_modified_symlinks() {
	local testroot=`test_init cherrypick_modified_symlinks`

	(cd $testroot/repo && ln -s alpha alpha.link)
	(cd $testroot/repo && ln -s epsilon epsilon.link)
	(cd $testroot/repo && ln -s /etc/passwd passwd.link)
	(cd $testroot/repo && ln -s ../beta epsilon/beta.link)
	(cd $testroot/repo && ln -s nonexistent nonexistent.link)
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "add symlinks"
	local commit_id1=`git_show_head $testroot/repo`

	got branch -r $testroot/repo foo

	got checkout -b foo $testroot/repo $testroot/wt > /dev/null

	(cd $testroot/repo && ln -sf beta alpha.link)
	(cd $testroot/repo && ln -sfh gamma epsilon.link)
	(cd $testroot/repo && ln -sf ../gamma/delta epsilon/beta.link)
	(cd $testroot/repo && ln -sf .got/bar $testroot/repo/dotgotfoo.link)
	(cd $testroot/repo && git rm -q nonexistent.link)
	(cd $testroot/repo && ln -sf epsilon/zeta zeta.link)
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "change symlinks"
	local commit_id2=`git_show_head $testroot/repo`

	(cd $testroot/wt && got cherrypick $commit_id2 > $testroot/stdout)

	echo "G  alpha.link" > $testroot/stdout.expected
	echo "G  epsilon/beta.link" >> $testroot/stdout.expected
	echo "A  dotgotfoo.link" >> $testroot/stdout.expected
	echo "G  epsilon.link" >> $testroot/stdout.expected
	echo "D  nonexistent.link" >> $testroot/stdout.expected
	echo "A  zeta.link" >> $testroot/stdout.expected
	echo "Merged commit $commit_id2" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if ! [ -h $testroot/wt/alpha.link ]; then
		echo "alpha.link is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/alpha.link > $testroot/stdout
	echo "beta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if ! [ -h $testroot/wt/epsilon.link ]; then
		echo "epsilon.link is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/epsilon.link > $testroot/stdout
	echo "gamma" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/passwd.link ]; then
		echo -n "passwd.link symlink points outside of work tree: " >&2
		readlink $testroot/wt/passwd.link >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n "/etc/passwd" > $testroot/content.expected
	cp $testroot/wt/passwd.link $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	readlink $testroot/wt/epsilon/beta.link > $testroot/stdout
	echo "../gamma/delta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/nonexistent.link ]; then
		echo -n "nonexistent.link still exists on disk: " >&2
		readlink $testroot/wt/nonexistent.link >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

test_cherrypick_symlink_conflicts() {
	local testroot=`test_init cherrypick_symlink_conflicts`

	(cd $testroot/repo && ln -s alpha alpha.link)
	(cd $testroot/repo && ln -s epsilon epsilon.link)
	(cd $testroot/repo && ln -s /etc/passwd passwd.link)
	(cd $testroot/repo && ln -s ../beta epsilon/beta.link)
	(cd $testroot/repo && ln -s nonexistent nonexistent.link)
	(cd $testroot/repo && ln -sf epsilon/zeta zeta.link)
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "add symlinks"
	local commit_id1=`git_show_head $testroot/repo`

	(cd $testroot/repo && ln -sf beta alpha.link)
	(cd $testroot/repo && ln -sf beta boo.link)
	(cd $testroot/repo && ln -sfh gamma epsilon.link)
	(cd $testroot/repo && ln -sf ../gamma/delta epsilon/beta.link)
	echo 'this is regular file foo' > $testroot/repo/dotgotfoo.link
	(cd $testroot/repo && ln -sf .got/bar dotgotbar.link)
	(cd $testroot/repo && git rm -q nonexistent.link)
	(cd $testroot/repo && ln -sf gamma/delta zeta.link)
	(cd $testroot/repo && ln -sf alpha new.link)
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "change symlinks"
	local commit_id2=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -c $commit_id1 foo
	got checkout -b foo $testroot/repo $testroot/wt > /dev/null

	# modified symlink to file A vs modified symlink to file B
	(cd $testroot/wt && ln -sf gamma/delta alpha.link)
	# modified symlink to dir A vs modified symlink to file B
	(cd $testroot/wt && ln -sfh beta epsilon.link)
	# modeified symlink to file A vs modified symlink to dir B
	(cd $testroot/wt && ln -sfh ../gamma epsilon/beta.link)
	# added regular file A vs added bad symlink to file A
	(cd $testroot/wt && ln -sf .got/bar dotgotfoo.link)
	(cd $testroot/wt && got add dotgotfoo.link > /dev/null)
	# added bad symlink to file A vs added regular file A
	echo 'this is regular file bar' > $testroot/wt/dotgotbar.link
	(cd $testroot/wt && got add dotgotbar.link > /dev/null)
	# added symlink to file A vs unversioned file A
	echo 'this is unversioned file boo' > $testroot/wt/boo.link
	# removed symlink to non-existent file A vs modified symlink
	# to nonexistent file B
	(cd $testroot/wt && ln -sf nonexistent2 nonexistent.link)
	# modified symlink to file A vs removed symlink to file A
	(cd $testroot/wt && got rm zeta.link > /dev/null)
	# added symlink to file A vs added symlink to file B
	(cd $testroot/wt && ln -sf beta new.link)
	(cd $testroot/wt && got add new.link > /dev/null)
	(cd $testroot/wt && got commit -S -m  "change symlinks on foo" \
		> /dev/null)

	(cd $testroot/wt && got update >/dev/null)
	(cd $testroot/wt && got cherrypick $commit_id2 > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	echo "C  alpha.link" >> $testroot/stdout.expected
	echo "C  epsilon/beta.link" >> $testroot/stdout.expected
	echo "?  boo.link" >> $testroot/stdout.expected
	echo "C  epsilon.link" >> $testroot/stdout.expected
	echo "C  dotgotbar.link" >> $testroot/stdout.expected
	echo "C  dotgotfoo.link" >> $testroot/stdout.expected
	echo "D  nonexistent.link" >> $testroot/stdout.expected
	echo "!  zeta.link" >> $testroot/stdout.expected
	echo "C  new.link" >> $testroot/stdout.expected
	echo "Merged commit $commit_id2" >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 6" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/alpha.link ]; then
		echo "alpha.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	echo "<<<<<<< merged change: commit $commit_id2" \
		> $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo "3-way merge base: commit $commit_id1" \
		>> $testroot/content.expected
	echo "alpha" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "gamma/delta" >> $testroot/content.expected
	echo '>>>>>>>' >> $testroot/content.expected
	echo -n "" >> $testroot/content.expected

	cp $testroot/wt/alpha.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/boo.link ]; then
		echo "boo.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	echo "this is unversioned file boo" > $testroot/content.expected
	cp $testroot/wt/boo.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/epsilon.link ]; then
		echo "epsilon.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	echo "<<<<<<< merged change: commit $commit_id2" \
		> $testroot/content.expected
	echo "gamma" >> $testroot/content.expected
	echo "3-way merge base: commit $commit_id1" \
		>> $testroot/content.expected
	echo "epsilon" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo '>>>>>>>' >> $testroot/content.expected
	echo -n "" >> $testroot/content.expected

	cp $testroot/wt/epsilon.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/passwd.link ]; then
		echo -n "passwd.link symlink points outside of work tree: " >&2
		readlink $testroot/wt/passwd.link >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n "/etc/passwd" > $testroot/content.expected
	cp $testroot/wt/passwd.link $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/epsilon/beta.link ]; then
		echo "epsilon/beta.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	echo "<<<<<<< merged change: commit $commit_id2" \
		> $testroot/content.expected
	echo "../gamma/delta" >> $testroot/content.expected
	echo "3-way merge base: commit $commit_id1" \
		>> $testroot/content.expected
	echo "../beta" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "../gamma" >> $testroot/content.expected
	echo '>>>>>>>' >> $testroot/content.expected
	echo -n "" >> $testroot/content.expected

	cp $testroot/wt/epsilon/beta.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/nonexistent.link ]; then
		echo -n "nonexistent.link still exists on disk: " >&2
		readlink $testroot/wt/nonexistent.link >&2
		test_done "$testroot" "1"
		return 1
	fi

	if [ -h $testroot/wt/dotgotfoo.link ]; then
		echo "dotgotfoo.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	echo "<<<<<<< merged change: commit $commit_id2" \
		> $testroot/content.expected
	echo "this is regular file foo" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo -n ".got/bar" >> $testroot/content.expected
	echo '>>>>>>>' >> $testroot/content.expected
	cp $testroot/wt/dotgotfoo.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/dotgotbar.link ]; then
		echo "dotgotbar.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi
	echo "<<<<<<< merged change: commit $commit_id2" \
		> $testroot/content.expected
	echo -n ".got/bar" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "this is regular file bar" >> $testroot/content.expected
	echo '>>>>>>>' >> $testroot/content.expected
	echo -n "" >> $testroot/content.expected
	cp $testroot/wt/dotgotbar.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/new.link ]; then
		echo "new.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	echo "<<<<<<< merged change: commit $commit_id2" \
		> $testroot/content.expected
	echo "alpha" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo '>>>>>>>' >> $testroot/content.expected
	echo -n "" >> $testroot/content.expected

	cp $testroot/wt/new.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "A  dotgotfoo.link" > $testroot/stdout.expected
	echo "M  new.link" >> $testroot/stdout.expected
	echo "D  nonexistent.link" >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "0"
}

test_cherrypick_with_path_prefix_and_empty_tree() {
	local testroot=`test_init cherrypick_with_path_prefix_and_empty_tree 1`

	(cd $testroot/repo && git commit --allow-empty \
		-m "initial empty commit" >/dev/null)

	(cd $testroot/repo && got br bar >/dev/null)

	mkdir -p $testroot/repo/epsilon
	echo "file foo" > $testroot/repo/epsilon/foo
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "add file foo"
	local commit_id=`git_show_head $testroot/repo`

	got checkout -b bar $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/wt/epsilon
	echo "new file" > $testroot/wt/epsilon/new
	(cd $testroot/wt && got add epsilon/new >/dev/null)
	(cd $testroot/wt && got commit -m "add file on branch bar" > /dev/null)

	got checkout -b bar -p epsilon $testroot/repo $testroot/wt2 > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	(cd $testroot/wt2 && got cherrypick $commit_id > $testroot/stdout)

	echo "A  foo" > $testroot/stdout.expected
	echo "Merged commit $commit_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_cherrypick_conflict_no_eol() {
	local testroot=`test_init cherrypick_conflict_no_eol 1`
	local content_a="aaa\naaa\naaa\naaa\naaa\naaa\n"
	local content_b="aaa\naaa\nbbb\naaa\naaa\naaa\naaa"
	local content_c="aaa\naaa\nccc\naaa\naaa\naaa\naaa"

	printf "$content_a" > $testroot/repo/a
	(cd $testroot/repo && git add a)
	git_commit $testroot/repo -m "initial commit"

	(cd $testroot/repo && got branch newbranch)

	printf "$content_b" > $testroot/repo/a
	git_commit $testroot/repo -m "change bbb"

	printf "$content_c" > $testroot/repo/a
	git_commit $testroot/repo -m "change ccc"
	local ccc_commit=`git_show_head $testroot/repo`

	got checkout -b newbranch $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got cherrypick $ccc_commit > $testroot/stdout)

	echo "C  a" > $testroot/stdout.expected
	echo "Merged commit $ccc_commit" >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_cherrypick_conflict_no_eol2() {
	local testroot=`test_init cherrypick_conflict_no_eol2 1`
	local content_a="aaa\naaa\naaa\naaa\naaa\naaa"
	local content_b="aaa\naaa\nbbb\naaa\naaa\naaa"
	local content_c="aaa\naaa\nbbb\naaa\naaa\naaa\n"

	printf "$content_a" > $testroot/repo/a
	(cd $testroot/repo && git add a)
	git_commit $testroot/repo -m "initial commit"

	(cd $testroot/repo && got branch newbranch)

	printf "$content_b" > $testroot/repo/a
	git_commit $testroot/repo -m "change bbb"

	printf "$content_c" > $testroot/repo/a
	git_commit $testroot/repo -m "change ccc"
	local ccc_commit=`git_show_head $testroot/repo`

	got checkout -b newbranch $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got cherrypick $ccc_commit \
		> $testroot/stdout 2> $testroot/stderr)

	echo "C  a" > $testroot/stdout.expected
	echo "Merged commit $ccc_commit" >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		#diff -u $testroot/stdout.expected $testroot/stdout
		ret="xfail $(head -n 1 $testroot/stderr)"
	fi
	test_done "$testroot" "$ret"
}

test_cherrypick_unrelated_changes() {
	local testroot=`test_init cherrypick_unrelated_changes`

	# Sorry about the large HERE document but I have not found
	# a smaller reproduction recipe yet...
	cat > $testroot/repo/reference.c <<EOF
const struct got_error *
got_ref_alloc(struct got_reference **ref, const char *name,
    struct got_object_id *id)
{
        if (!is_valid_ref_name(name))
                return got_error_path(name, GOT_ERR_BAD_REF_NAME);

        return alloc_ref(ref, name, id, 0);
}

static const struct got_error *
parse_packed_ref_line(struct got_reference **ref, const char *abs_refname,
    const char *line)
{
        struct got_object_id id;
        const char *name;

        *ref = NULL;

        if (line[0] == '#' || line[0] == '^')
                return NULL;

        if (!got_parse_sha1_digest(id.sha1, line))
                return got_error(GOT_ERR_BAD_REF_DATA);

        if (abs_refname) {
                if (strcmp(line + SHA1_DIGEST_STRING_LENGTH, abs_refname) != 0)
                        return NULL;
                name = abs_refname;
        } else
                name = line + SHA1_DIGEST_STRING_LENGTH;

        return alloc_ref(ref, name, &id, GOT_REF_IS_PACKED);
}

static const struct got_error *
open_packed_ref(struct got_reference **ref, FILE *f, const char **subdirs,
    int nsubdirs, const char *refname)
{
        const struct got_error *err = NULL;
        char *abs_refname;
        char *line = NULL;
        size_t linesize = 0;
        ssize_t linelen;
        int i, ref_is_absolute = (strncmp(refname, "refs/", 5) == 0);

        *ref = NULL;

        if (ref_is_absolute)
                abs_refname = (char *)refname;
        do {
                linelen = getline(&line, &linesize, f);
                if (linelen == -1) {
                        if (feof(f))
                                break;
                        err = got_ferror(f, GOT_ERR_BAD_REF_DATA);
                        break;
                }
                if (linelen > 0 && line[linelen - 1] == '\n')
                        line[linelen - 1] = '\0';
                for (i = 0; i < nsubdirs; i++) {
                        if (!ref_is_absolute &&
                            asprintf(&abs_refname, "refs/%s/%s", subdirs[i],
                            refname) == -1)
                                return got_error_from_errno("asprintf");
                        err = parse_packed_ref_line(ref, abs_refname, line);
                        if (!ref_is_absolute)
                                free(abs_refname);
                        if (err || *ref != NULL)
                                break;
                }
                if (err)
                        break;
        } while (*ref == NULL);
        free(line);

        return err;
}

static const struct got_error *
open_ref(struct got_reference **ref, const char *path_refs, const char *subdir,
    const char *name, int lock)
{
        const struct got_error *err = NULL;
        char *path = NULL;
        char *absname = NULL;
        int ref_is_absolute = (strncmp(name, "refs/", 5) == 0);
        int ref_is_well_known = (subdir[0] == '\0' && is_well_known_ref(name));

        *ref = NULL;

        if (ref_is_absolute || ref_is_well_known) {
                if (asprintf(&path, "%s/%s", path_refs, name) == -1)
                        return got_error_from_errno("asprintf");
                absname = (char *)name;
        } else {
                if (asprintf(&path, "%s/%s%s%s", path_refs, subdir,
                    subdir[0] ? "/" : "", name) == -1)
                        return got_error_from_errno("asprintf");

                if (asprintf(&absname, "refs/%s%s%s",
                    subdir, subdir[0] ? "/" : "", name) == -1) {
                        err = got_error_from_errno("asprintf");
                        goto done;
                }
        }

        err = parse_ref_file(ref, name, absname, path, lock);
done:
        if (!ref_is_absolute && !ref_is_well_known)
                free(absname);
        free(path);
        return err;
}

const struct got_error *
got_ref_open(struct got_reference **ref, struct got_repository *repo,
   const char *refname, int lock)
{
        const struct got_error *err = NULL;
        char *path_refs = NULL;
        const char *subdirs[] = {
            GOT_REF_HEADS, GOT_REF_TAGS, GOT_REF_REMOTES
        };
        size_t i;
        int well_known = is_well_known_ref(refname);
        struct got_lockfile *lf = NULL;

        *ref = NULL;

        path_refs = get_refs_dir_path(repo, refname);
        if (path_refs == NULL) {
                err = got_error_from_errno2("get_refs_dir_path", refname);
                goto done;
        }

        if (well_known) {
                err = open_ref(ref, path_refs, "", refname, lock);
        } else {
                char *packed_refs_path;
                FILE *f;

                /* Search on-disk refs before packed refs! */
                for (i = 0; i < nitems(subdirs); i++) {
                        err = open_ref(ref, path_refs, subdirs[i], refname,
                            lock);
                        if ((err && err->code != GOT_ERR_NOT_REF) || *ref)
                                goto done;
                }

                packed_refs_path = got_repo_get_path_packed_refs(repo);
                if (packed_refs_path == NULL) {
                        err = got_error_from_errno(
                            "got_repo_get_path_packed_refs");
                        goto done;
                }

                if (lock) {
                        err = got_lockfile_lock(&lf, packed_refs_path);
                        if (err)
                                goto done;
                }
                f = fopen(packed_refs_path, "rb");
                free(packed_refs_path);
                if (f != NULL) {
                        err = open_packed_ref(ref, f, subdirs, nitems(subdirs),
                            refname);
                        if (!err) {
                                if (fclose(f) == EOF) {
                                        err = got_error_from_errno("fclose");
                                        got_ref_close(*ref);
                                        *ref = NULL;
                                } else if (*ref)
                                        (*ref)->lf = lf;
                        }
                }
        }
done:
        if (!err && *ref == NULL)
                err = got_error_not_ref(refname);
        if (err && lf)
                got_lockfile_unlock(lf);
        free(path_refs);
        return err;
}

struct got_reference *
got_ref_dup(struct got_reference *ref)
{
        struct got_reference *ret;

        ret = calloc(1, sizeof(*ret));
        if (ret == NULL)
                return NULL;

        ret->flags = ref->flags;
        if (ref->flags & GOT_REF_IS_SYMBOLIC) {
                ret->ref.symref.name = strdup(ref->ref.symref.name);
                if (ret->ref.symref.name == NULL) {
                        free(ret);
                        return NULL;
                }
                ret->ref.symref.ref = strdup(ref->ref.symref.ref);
                if (ret->ref.symref.ref == NULL) {
                        free(ret->ref.symref.name);
                        free(ret);
                        return NULL;
                }
        } else {
                ret->ref.ref.name = strdup(ref->ref.ref.name);
                if (ret->ref.ref.name == NULL) {
                        free(ret);
                        return NULL;
                }
                memcpy(ret->ref.ref.sha1, ref->ref.ref.sha1,
                    sizeof(ret->ref.ref.sha1));
        }

        return ret;
}

const struct got_error *
got_reflist_entry_dup(struct got_reflist_entry **newp,
    struct got_reflist_entry *re)
{
        const struct got_error *err = NULL;
        struct got_reflist_entry *new;

        *newp = NULL;

        new = malloc(sizeof(*new));
        if (new == NULL)
                return got_error_from_errno("malloc");

        new->ref = got_ref_dup(re->ref);
        if (new->ref == NULL) {
                err = got_error_from_errno("got_ref_dup");
                free(new);
                return err;
        }

        *newp = new;
        return NULL;
}

void
got_ref_list_free(struct got_reflist_head *refs)
{
        struct got_reflist_entry *re;

        while ((re = TAILQ_FIRST(refs))) {
                TAILQ_REMOVE(refs, re, entry);
                free(re);
        }

}
EOF
	(cd $testroot/repo && git add reference.c)
	git_commit $testroot/repo -m "added reference.c file"
	local base_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git checkout -q -b newbranch)
	ed -s $testroot/repo/reference.c <<EOF
91a
        if (!is_valid_ref_name(name))
                return got_error_path(name, GOT_ERR_BAD_REF_NAME);

.
w
q
EOF
	git_commit $testroot/repo -m "added lines on newbranch"
	local branch_rev1=`git_show_head $testroot/repo`

	ed -s $testroot/repo/reference.c <<EOF
255a
                got_ref_close(re->ref);
.
w
q
EOF
	git_commit $testroot/repo -m "more lines on newbranch"

	local branch_rev2=`git_show_head $testroot/repo`

	(cd $testroot/wt && got cherrypick $branch_rev2 > $testroot/stdout)

	echo "G  reference.c" > $testroot/stdout.expected
	echo "Merged commit $branch_rev2" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/diff.expected <<EOF
--- reference.c
+++ reference.c
@@ -250,6 +250,7 @@ got_ref_list_free(struct got_reflist_head *refs)
 
         while ((re = TAILQ_FIRST(refs))) {
                 TAILQ_REMOVE(refs, re, entry);
+                got_ref_close(re->ref);
                 free(re);
         }
 
EOF
	(cd $testroot/wt && got diff |
		egrep -v '^(diff|blob|file)' > $testroot/diff)
	cmp -s $testroot/diff.expected $testroot/diff
	ret="$?"
	if [ "$ret" != "0" ]; then
		#diff -u $testroot/diff.expected $testroot/diff
		ret="xfail cherrypick results in unexpected diff"
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_cherrypick_basic
run_test test_cherrypick_root_commit
run_test test_cherrypick_into_work_tree_with_conflicts
run_test test_cherrypick_modified_submodule
run_test test_cherrypick_added_submodule
run_test test_cherrypick_conflict_wt_file_vs_repo_submodule
run_test test_cherrypick_modified_symlinks
run_test test_cherrypick_symlink_conflicts
run_test test_cherrypick_with_path_prefix_and_empty_tree
run_test test_cherrypick_conflict_no_eol
run_test test_cherrypick_conflict_no_eol2
run_test test_cherrypick_unrelated_changes
