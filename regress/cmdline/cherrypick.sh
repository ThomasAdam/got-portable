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

function test_cherrypick_modified_symlinks {
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

function test_cherrypick_symlink_conflicts {
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
	(cd $testroot/wt && got commit -m  "change on symlinks on branch foo" \
		> /dev/null)

	(cd $testroot/wt && got update >/dev/null)
	(cd $testroot/wt && got cherrypick $commit_id2 > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	echo "C  alpha.link" >> $testroot/stdout.expected
	echo "C  epsilon/beta.link" >> $testroot/stdout.expected
	echo "?  boo.link" >> $testroot/stdout.expected
	echo "C  epsilon.link" >> $testroot/stdout.expected
	echo "C  dotgotbar.link" >> $testroot/stdout.expected
	echo "U  dotgotfoo.link" >> $testroot/stdout.expected
	echo "D  nonexistent.link" >> $testroot/stdout.expected
	echo "!  zeta.link" >> $testroot/stdout.expected
	echo "C  new.link" >> $testroot/stdout.expected
	echo "Merged commit $commit_id2" >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 5" >> $testroot/stdout.expected
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

	cat > $testroot/symlink-conflict-header <<EOF
got: Could not install symbolic link because of merge conflict.
ln(1) may be used to fix the situation. If this is intended to be a
regular file instead then its expected contents may be filled in.
The following conflicting symlink target paths were found:
EOF
	cp $testroot/symlink-conflict-header $testroot/content.expected
	echo "<<<<<<< merged change: commit $commit_id2" \
		>> $testroot/content.expected
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

	cp $testroot/symlink-conflict-header $testroot/content.expected
	echo "<<<<<<< merged change: commit $commit_id2" \
		>> $testroot/content.expected
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

	cp $testroot/symlink-conflict-header $testroot/content.expected
	echo "<<<<<<< merged change: commit $commit_id2" \
		>> $testroot/content.expected
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

	echo "this is regular file foo" > $testroot/content.expected
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

	cp $testroot/symlink-conflict-header $testroot/content.expected
	echo "<<<<<<< merged change: commit $commit_id2" \
		>> $testroot/content.expected
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

run_test test_cherrypick_basic
run_test test_cherrypick_root_commit
run_test test_cherrypick_into_work_tree_with_conflicts
run_test test_cherrypick_modified_submodule
run_test test_cherrypick_added_submodule
run_test test_cherrypick_conflict_wt_file_vs_repo_submodule
run_test test_cherrypick_modified_symlinks
run_test test_cherrypick_symlink_conflicts
