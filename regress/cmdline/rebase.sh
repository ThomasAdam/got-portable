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

. ./common.sh

test_rebase_basic() {
	local testroot=`test_init rebase_basic`
	local commit0=`git_show_head $testroot/repo`
	local commit0_author_time=`git_show_author_time $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	echo "modified alpha on branch" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on branch" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing more changes on newbranch"

	local orig_commit1=`git_show_parent_commit $testroot/repo`
	local orig_commit2=`git_show_head $testroot/repo`
	local orig_author_time2=`git_show_author_time $testroot/repo`

	git -C $testroot/repo checkout -q master
	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rebase master > $testroot/stdout \
		2> $testroot/stderr)
	echo -n "got: cannot rebase refs/heads/master onto itself: " \
		> $testroot/stderr.expected
	echo "update -b required" >> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rebase newbranch > $testroot/stdout)

	git -C $testroot/repo checkout -q newbranch
	local new_commit1=`git_show_parent_commit $testroot/repo`
	local new_commit2=`git_show_head $testroot/repo`
	local new_author_time2=`git_show_author_time $testroot/repo`

	local short_orig_commit1=`trim_obj_id 12 $orig_commit1`
	local short_orig_commit2=`trim_obj_id 12 $orig_commit2`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`
	local short_new_commit2=`trim_obj_id 12 $new_commit2`

	echo "G  gamma/delta" >> $testroot/stdout.expected
	echo -n "$short_orig_commit1 -> $short_new_commit1" \
		>> $testroot/stdout.expected
	echo ": committing to delta on newbranch" >> $testroot/stdout.expected
	echo "G  alpha" >> $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo -n "$short_orig_commit2 -> $short_new_commit2" \
		>> $testroot/stdout.expected
	echo ": committing more changes on newbranch" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/newbranch" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified delta on branch" > $testroot/content.expected
	cat $testroot/wt/gamma/delta > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha on branch" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
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
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $new_commit2 (newbranch)" > $testroot/stdout.expected
	echo "commit $new_commit1" >> $testroot/stdout.expected
	echo "commit $master_commit (master)" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update > $testroot/stdout)

	echo 'Already up-to-date' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# We should have a backup of old commits
	(cd $testroot/repo && got rebase -l > $testroot/stdout)
	d_orig2=`date -u -r $orig_author_time2 +"%a %b %e %X %Y UTC"`
	d_new2=`date -u -r $new_author_time2 +"%F"`
	d_0=`date -u -r $commit0_author_time +"%F"`
	cat > $testroot/stdout.expected <<EOF
-----------------------------------------------
commit $orig_commit2 (formerly newbranch)
from: $GOT_AUTHOR
date: $d_orig2
 
 committing more changes on newbranch
 
has become commit $new_commit2 (newbranch)
 $d_new2 $GOT_AUTHOR_11  committing more changes on newbranch
history forked at $commit0
 $d_0 $GOT_AUTHOR_11  adding the test tree
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Asking for backups of a branch which has none should yield an error
	(cd $testroot/repo && got rebase -l master \
		> $testroot/stdout 2> $testroot/stderr)
	echo -n > $testroot/stdout.expected
	echo "got: refs/got/backup/rebase/master/: no such reference found" \
		> $testroot/stderr.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# Delete all backup refs
	(cd $testroot/repo && got rebase -X \
		> $testroot/stdout 2> $testroot/stderr)
	echo -n "Deleted refs/got/backup/rebase/newbranch/$new_commit2: " \
		> $testroot/stdout.expected
	echo "$orig_commit2" >> $testroot/stdout.expected
	echo -n > $testroot/stderr.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && got rebase -l > $testroot/stdout)
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rebase_ancestry_check() {
	local testroot=`test_init rebase_ancestry_check`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"
	local newbranch_id=`git_show_head $testroot/repo`

	(cd $testroot/wt && got rebase newbranch > $testroot/stdout \
		2> $testroot/stderr)

	echo "refs/heads/newbranch is already based on refs/heads/master" \
		> $testroot/stdout.expected
	echo "Switching work tree from refs/heads/master to refs/heads/newbranch" \
		>> $testroot/stdout.expected
	echo "U  gamma/delta" >> $testroot/stdout.expected
	echo "Updated to refs/heads/newbranch: ${newbranch_id}" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_rebase_continue() {
	local testroot=`test_init rebase_continue`
	local init_commit=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified alpha on branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on newbranch"
	local orig_commit1=`git_show_head $testroot/repo`
	local short_orig_commit1=`trim_obj_id 12 $orig_commit1`

	git -C $testroot/repo checkout -q master
	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rebase newbranch > $testroot/stdout \
		2> $testroot/stderr)

	echo "C  alpha" > $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected
	echo -n "$short_orig_commit1 -> merge conflict" \
		>> $testroot/stdout.expected
	echo ": committing to alpha on newbranch" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: conflicts must be resolved before rebasing can continue" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo '<<<<<<<' > $testroot/content.expected
	echo "modified alpha on master" >> $testroot/content.expected
	echo "||||||| 3-way merge base: commit $init_commit" \
		>> $testroot/content.expected
	echo "alpha" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "modified alpha on branch" >> $testroot/content.expected
	echo ">>>>>>> merged change: commit $orig_commit1" \
		>> $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	cat > $testroot/stdout.expected <<EOF
C  alpha
Work tree is rebasing refs/heads/newbranch onto refs/heads/master
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# resolve the conflict
	echo "modified alpha on branch and master" > $testroot/wt/alpha

	# test interaction of 'got stage' and rebase -c
	(cd $testroot/wt && got stage alpha > /dev/null)
	(cd $testroot/wt && got rebase -c > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "rebase succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo -n "got: work tree contains files with staged changes; " \
		> $testroot/stderr.expected
	echo "these changes must be committed or unstaged first" \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got unstage alpha > /dev/null)
	(cd $testroot/wt && got rebase -c > $testroot/stdout)

	git -C $testroot/repo checkout -q newbranch
	local new_commit1=`git_show_head $testroot/repo`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`

	echo -n "$short_orig_commit1 -> $short_new_commit1" \
		> $testroot/stdout.expected
	echo ": committing to alpha on newbranch" >> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/newbranch" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi


	(cd $testroot/wt && got log -l2 | grep ^commit > $testroot/stdout)
	echo "commit $new_commit1 (newbranch)" > $testroot/stdout.expected
	echo "commit $master_commit (master)" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rebase_abort() {
	local testroot=`test_init rebase_abort`

	local init_commit=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified beta on branch" > $testroot/repo/beta
	git_commit $testroot/repo -m "committing to beta on newbranch"
	local orig_commit1=`git_show_head $testroot/repo`
	local short_orig_commit1=`trim_obj_id 12 $orig_commit1`

	echo "modified alpha on branch" > $testroot/repo/alpha
	echo "new file on branch" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo \
		-m "changing alpha and adding new on newbranch"
	local orig_commit2=`git_show_head $testroot/repo`
	local short_orig_commit2=`trim_obj_id 12 $orig_commit2`

	git -C $testroot/repo checkout -q master
	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# unrelated unversioned file in work tree
	touch $testroot/wt/unversioned-file

	(cd $testroot/wt && got rebase newbranch > $testroot/stdout \
		2> $testroot/stderr)

	new_commit1=$(cd $testroot/wt && got info beta | \
		grep '^based on commit:' | cut -d' ' -f4)
	local short_new_commit1=`trim_obj_id 12 $new_commit1`
	
	echo "G  beta" > $testroot/stdout.expected
	echo -n "$short_orig_commit1 -> $short_new_commit1" \
		>> $testroot/stdout.expected
	echo ": committing to beta on newbranch" >> $testroot/stdout.expected
	echo "C  alpha" >> $testroot/stdout.expected
	echo "A  epsilon/new" >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected
	echo -n "$short_orig_commit2 -> merge conflict" \
		>> $testroot/stdout.expected
	echo ": changing alpha and adding new on newbranch" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: conflicts must be resolved before rebasing can continue" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo '<<<<<<<' > $testroot/content.expected
	echo "modified alpha on master" >> $testroot/content.expected
	echo "||||||| 3-way merge base: commit $orig_commit1" \
		>> $testroot/content.expected
	echo "alpha" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "modified alpha on branch" >> $testroot/content.expected
	echo ">>>>>>> merged change: commit $orig_commit2" \
		>> $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# unrelated file in work tree added during conflict resolution
	touch $testroot/wt/added-file
	(cd $testroot/wt && got add added-file > /dev/null)

	(cd $testroot/wt && got status > $testroot/stdout)

	cat > $testroot/stdout.expected <<EOF
A  added-file
C  alpha
A  epsilon/new
?  unversioned-file
Work tree is rebasing refs/heads/newbranch onto refs/heads/master
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rebase -a > $testroot/stdout)

	git -C $testroot/repo checkout -q newbranch

	echo "Switching work tree to refs/heads/master" \
		> $testroot/stdout.expected
	echo 'R  added-file' >> $testroot/stdout.expected
	echo 'R  alpha' >> $testroot/stdout.expected
	echo 'R  epsilon/new' >> $testroot/stdout.expected
	echo 'G  added-file' >> $testroot/stdout.expected
	echo 'U  beta' >> $testroot/stdout.expected
	echo "Rebase of refs/heads/newbranch aborted" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha on master" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 -c newbranch \
		| grep ^commit > $testroot/stdout)
	echo "commit $orig_commit2 (newbranch)" > $testroot/stdout.expected
	echo "commit $orig_commit1" >> $testroot/stdout.expected
	echo "commit $init_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got info .| \
		grep '^based on commit:' | sort | uniq > $testroot/stdout)
	echo "based on commit: $master_commit" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "?  added-file" > $testroot/stdout.expected
	echo "?  unversioned-file" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat $testroot/wt/beta > $testroot/content
	echo 'beta' > $testroot/content.expected
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# A subsequent update should be a no-op.
	(cd $testroot/wt && got update > $testroot/stdout)
	echo 'Already up-to-date' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rebase_no_op_change() {
	local testroot=`test_init rebase_no_op_change`
	local init_commit=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified alpha on branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on newbranch"
	local orig_commit1=`git_show_head $testroot/repo`
	local short_orig_commit1=`trim_obj_id 12 $orig_commit1`

	git -C $testroot/repo checkout -q master
	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rebase newbranch > $testroot/stdout \
		2> $testroot/stderr)

	echo "C  alpha" > $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected
	echo -n "$short_orig_commit1 -> merge conflict" \
		>> $testroot/stdout.expected
	echo ": committing to alpha on newbranch" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: conflicts must be resolved before rebasing can continue" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo '<<<<<<<' > $testroot/content.expected
	echo "modified alpha on master" >> $testroot/content.expected
	echo "||||||| 3-way merge base: commit $init_commit" \
		>> $testroot/content.expected
	echo "alpha" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "modified alpha on branch" >> $testroot/content.expected
	echo ">>>>>>> merged change: commit $orig_commit1" \
		>> $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	cat > $testroot/stdout.expected <<EOF
C  alpha
Work tree is rebasing refs/heads/newbranch onto refs/heads/master
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# resolve the conflict
	echo "modified alpha on master" > $testroot/wt/alpha

	(cd $testroot/wt && got rebase -c > $testroot/stdout)

	git -C $testroot/repo checkout -q newbranch
	local new_commit1=`git_show_head $testroot/repo`

	echo -n "$short_orig_commit1 -> no-op change" \
		> $testroot/stdout.expected
	echo ": committing to alpha on newbranch" >> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/newbranch" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi


	(cd $testroot/wt && got log -l2 | grep ^commit > $testroot/stdout)
	echo "commit $master_commit (master, newbranch)" \
		> $testroot/stdout.expected
	echo "commit $init_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rebase_in_progress() {
	local testroot=`test_init rebase_in_progress`
	local init_commit=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified alpha on branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on newbranch"
	local orig_commit1=`git_show_head $testroot/repo`
	local short_orig_commit1=`trim_obj_id 12 $orig_commit1`

	git -C $testroot/repo checkout -q master
	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rebase newbranch > $testroot/stdout \
		2> $testroot/stderr)

	echo "C  alpha" > $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected
	echo -n "$short_orig_commit1 -> merge conflict" \
		>> $testroot/stdout.expected
	echo ": committing to alpha on newbranch" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: conflicts must be resolved before rebasing can continue" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo '<<<<<<<' > $testroot/content.expected
	echo "modified alpha on master" >> $testroot/content.expected
	echo "||||||| 3-way merge base: commit $init_commit" \
		>> $testroot/content.expected
	echo "alpha" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "modified alpha on branch" >> $testroot/content.expected
	echo ">>>>>>> merged change: commit $orig_commit1" \
		>> $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	cat > $testroot/stdout.expected <<EOF
C  alpha
Work tree is rebasing refs/heads/newbranch onto refs/heads/master
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	for cmd in update commit; do
		(cd $testroot/wt && got $cmd > $testroot/stdout \
			2> $testroot/stderr)

		echo -n > $testroot/stdout.expected
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi

		echo -n "got: a rebase operation is in progress in this " \
			> $testroot/stderr.expected
		echo "work tree and must be continued or aborted first" \
			>> $testroot/stderr.expected
		cmp -s $testroot/stderr.expected $testroot/stderr
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stderr.expected $testroot/stderr
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	test_done "$testroot" "$ret"
}

test_rebase_path_prefix() {
	local testroot=`test_init rebase_path_prefix`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	local orig_commit1=`git_show_parent_commit $testroot/repo`
	local orig_commit2=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q master
	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout -p epsilon $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rebase newbranch \
		> $testroot/stdout 2> $testroot/stderr)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n "got: cannot rebase branch which contains changes outside " \
		> $testroot/stderr.expected
	echo "of this work tree's path prefix" >> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# rebase should succeed when using a complete work tree
	got checkout $testroot/repo $testroot/wt2 > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt2 && got rebase newbranch \
		> $testroot/stdout 2> $testroot/stderr)

	git -C $testroot/repo checkout -q newbranch
	local new_commit1=`git_show_parent_commit $testroot/repo`
	local new_commit2=`git_show_head $testroot/repo`

	local short_orig_commit2=`trim_obj_id 12 $orig_commit2`
	local short_new_commit2=`trim_obj_id 12 $new_commit2`

	echo "G  gamma/delta" > $testroot/stdout.expected
	echo -n "$short_orig_commit2 -> $short_new_commit2" \
		>> $testroot/stdout.expected
	echo ": committing to delta on newbranch" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/newbranch" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# the first work tree should remain usable
	(cd $testroot/wt && got update -b master \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo 'Already up-to-date' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rebase_preserves_logmsg() {
	local testroot=`test_init rebase_preserves_logmsg`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "modified delta on newbranch"

	echo "modified alpha on branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha on newbranch"

	(cd $testroot/repo && got log -c newbranch -l2 | grep -v ^date: \
		> $testroot/log.expected)

	local orig_commit1=`git_show_parent_commit $testroot/repo`
	local orig_commit2=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q master
	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rebase newbranch > /dev/null \
		2> $testroot/stderr)

	git -C $testroot/repo checkout -q newbranch
	local new_commit1=`git_show_parent_commit $testroot/repo`
	local new_commit2=`git_show_head $testroot/repo`

	echo -n > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -c newbranch -l2 | grep -v ^date: \
		> $testroot/log)
	ed -s $testroot/log.expected <<-EOF
	,s/$orig_commit1/$new_commit1/
	,s/$orig_commit2/$new_commit2/
	w
	EOF
	cmp -s $testroot/log.expected $testroot/log
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/log.expected $testroot/log
	fi

	test_done "$testroot" "$ret"
}

test_rebase_preserves_author_data() {
	local testroot=`test_init rebase_preserves_author_data`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	TZ=EST git_commit $testroot/repo -m "modified delta on newbranch"

	sleep 1		# get a new timestamp
	echo "modified alpha on branch" > $testroot/repo/alpha
	TZ=CET git_commit $testroot/repo -m "modified alpha on newbranch"

	local orig_commit1=`git_show_parent_commit $testroot/repo`
	local orig_commit2=`git_show_head $testroot/repo`

	(cd $testroot/repo && got cat $orig_commit1 $orig_commit2 | \
		grep '^author ' > $testroot/author_data.expected)

	git -C $testroot/repo checkout -q master
	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	sleep 1		# get a new timestamp
	(cd $testroot/wt && got rebase newbranch > /dev/null \
		2> $testroot/stderr)

	git -C $testroot/repo checkout -q newbranch
	local new_commit1=`git_show_parent_commit $testroot/repo`
	local new_commit2=`git_show_head $testroot/repo`

	echo -n > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got cat $new_commit1 $new_commit2 | \
		grep '^author ' > $testroot/author_data)
	ed -s $testroot/author_data.expected <<-EOF
	,s/ [+-][0-9]\{4\}\$/ +0000/
	w
	EOF
	cmp -s $testroot/author_data.expected $testroot/author_data
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/author_data.expected $testroot/author_data
	fi

	test_done "$testroot" "$ret"
}

test_rebase_no_commits_to_rebase() {
	local testroot=`test_init rebase_no_commits_to_rebase`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# Create an unrelated branch with 'got import'.
	mkdir -p $testroot/newtree
	echo "new file" > $testroot/newtree/newfile
	got import -m new -b newbranch -r $testroot/repo \
		$testroot/newtree > /dev/null

	echo "modified alpha on master" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'test rebase_no_commits_to_rebase' \
		> /dev/null)
	(cd $testroot/wt && got update > /dev/null)

	(cd $testroot/wt && got rebase newbranch > $testroot/stdout \
		2> $testroot/stderr)

	echo -n "got: specified branch shares no common ancestry " \
		> $testroot/stderr.expected
	echo "with work tree's branch" >> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update > $testroot/stdout)
	echo "Already up-to-date" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rebase_forward() {
	local testroot=`test_init rebase_forward`
	local commit0=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "change alpha 1" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'test rebase_forward' \
		> /dev/null)
	local commit1=`git_show_head $testroot/repo`

	echo "change alpha 2" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'test rebase_forward' \
		> /dev/null)
	local commit2=`git_show_head $testroot/repo`

	# Simulate a situation where fast-forward is required.
	# We want to fast-forward master to origin/master:
	# commit 3907e11dceaae2ca7f8db79c2af31794673945ad (origin/master)
	# commit ffcffcd102cf1af6572fbdbb4cf07a0f1fd2d840 (master)
	# commit 87a6a8a2263a15b61c016ff1720b24741d455eb5
	(cd $testroot/repo && got ref -d master >/dev/null)
	(cd $testroot/repo && got ref -c $commit1 refs/heads/master)
	(cd $testroot/repo && got ref -c $commit2 refs/remotes/origin/master)

	(cd $testroot/wt && got up -b origin/master > /dev/null)

	(cd $testroot/wt && got rebase master \
		> $testroot/stdout 2> $testroot/stderr)

	echo "Forwarding refs/heads/master to commit $commit2" \
		> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure that rebase operation was completed correctly
	(cd $testroot/wt && got rebase -a \
		> $testroot/stdout 2> $testroot/stderr)
	echo -n "" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	echo "got: rebase operation not in progress" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got branch -n > $testroot/stdout)
	echo "master" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $commit2 (master, origin/master)" > $testroot/stdout.expected
	echo "commit $commit1" >> $testroot/stdout.expected
	echo "commit $commit0" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Forward-only rebase operations should not be backed up
	(cd $testroot/repo && got rebase -l > $testroot/stdout)
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rebase_forward_path_prefix() {
	local testroot=`test_init rebase_forward_path_prefix`
	local commit0=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt-full > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "change alpha 1" > $testroot/wt-full/alpha
	(cd $testroot/wt-full && got commit -m 'test rebase_forward' \
		> /dev/null)
	local commit1=`git_show_head $testroot/repo`

	echo "change alpha 2" > $testroot/wt-full/alpha
	(cd $testroot/wt-full && got commit -m 'test rebase_forward' \
		> /dev/null)
	local commit2=`git_show_head $testroot/repo`

	# Simulate a situation where fast-forward is required.
	# We want to fast-forward master to origin/master:
	# commit 3907e11dceaae2ca7f8db79c2af31794673945ad (origin/master)
	# commit ffcffcd102cf1af6572fbdbb4cf07a0f1fd2d840 (master)
	# commit 87a6a8a2263a15b61c016ff1720b24741d455eb5
	(cd $testroot/repo && got ref -d master >/dev/null)
	(cd $testroot/repo && got ref -c $commit1 refs/heads/master)
	(cd $testroot/repo && got ref -c $commit2 refs/remotes/origin/master)

	# Work tree which uses a path-prefix and will be used for rebasing
	got checkout -p epsilon -b origin/master $testroot/repo $testroot/wt \
		> /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rebase master \
		> $testroot/stdout 2> $testroot/stderr)

	echo "Forwarding refs/heads/master to commit $commit2" \
		> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure that rebase operation was completed correctly
	(cd $testroot/wt && got rebase -a \
		> $testroot/stdout 2> $testroot/stderr)
	echo -n "" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	echo "got: rebase operation not in progress" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got branch -n > $testroot/stdout)
	echo "master" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $commit2 (master, origin/master)" > $testroot/stdout.expected
	echo "commit $commit1" >> $testroot/stdout.expected
	echo "commit $commit0" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Forward-only rebase operations should not be backed up
	(cd $testroot/repo && got rebase -l > $testroot/stdout)
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rebase_out_of_date() {
	local testroot=`test_init rebase_out_of_date`
	local initial_commit=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	echo "modified alpha on branch" > $testroot/repo/alpha
	git -C $testroot/repo rm -q beta
	echo "new file on branch" > $testroot/repo/epsilon/new
	git -C $testroot/repo add epsilon/new
	git_commit $testroot/repo -m "committing more changes on newbranch"

	local orig_commit1=`git_show_parent_commit $testroot/repo`
	local orig_commit2=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q master
	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local master_commit1=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q master
	echo "modified beta on master" > $testroot/repo/beta
	git_commit $testroot/repo -m "committing to beta on master"
	local master_commit2=`git_show_head $testroot/repo`

	got checkout -c $master_commit1 $testroot/repo $testroot/wt \
		> /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rebase newbranch > $testroot/stdout \
		2> $testroot/stderr)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n "got: work tree must be updated before it can be " \
		> $testroot/stderr.expected
	echo "used to rebase a branch" >> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $master_commit2 (master)" > $testroot/stdout.expected
	echo "commit $master_commit1" >> $testroot/stdout.expected
	echo "commit $initial_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rebase_trims_empty_dir() {
	local testroot=`test_init rebase_trims_empty_dir`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	git -C $testroot/repo rm -q epsilon/zeta
	git_commit $testroot/repo -m "removing zeta on newbranch"

	local orig_commit1=`git_show_parent_commit $testroot/repo`
	local orig_commit2=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q master
	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing to alpha on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rebase newbranch > $testroot/stdout)

	git -C $testroot/repo checkout -q newbranch
	local new_commit1=`git_show_parent_commit $testroot/repo`
	local new_commit2=`git_show_head $testroot/repo`

	local short_orig_commit1=`trim_obj_id 12 $orig_commit1`
	local short_orig_commit2=`trim_obj_id 12 $orig_commit2`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`
	local short_new_commit2=`trim_obj_id 12 $new_commit2`

	echo "G  gamma/delta" >> $testroot/stdout.expected
	echo -n "$short_orig_commit1 -> $short_new_commit1" \
		>> $testroot/stdout.expected
	echo ": committing to delta on newbranch" >> $testroot/stdout.expected
	echo "D  epsilon/zeta" >> $testroot/stdout.expected
	echo -n "$short_orig_commit2 -> $short_new_commit2" \
		>> $testroot/stdout.expected
	echo ": removing zeta on newbranch" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/newbranch" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified delta on branch" > $testroot/content.expected
	cat $testroot/wt/gamma/delta > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha on master" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/epsilon ]; then
		echo "parent of removed zeta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $new_commit2 (newbranch)" > $testroot/stdout.expected
	echo "commit $new_commit1" >> $testroot/stdout.expected
	echo "commit $master_commit (master)" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rebase_delete_missing_file() {
	local testroot=`test_init rebase_delete_missing_file`

	mkdir -p $testroot/repo/d/f/g
	echo "new file" > $testroot/repo/d/f/g/new
	git -C $testroot/repo add d/f/g/new
	git_commit $testroot/repo -m "adding a subdir"
	local commit0=`git_show_head $testroot/repo`

	got br -r $testroot/repo -c master newbranch

	got checkout -b newbranch $testroot/repo $testroot/wt > /dev/null

	echo "modified delta on branch" > $testroot/wt/gamma/delta
	(cd $testroot/wt && got commit \
		-m "committing to delta on newbranch" > /dev/null)

	(cd $testroot/wt && got rm beta d/f/g/new > /dev/null)
	(cd $testroot/wt && got commit \
		-m "removing beta and d/f/g/new on newbranch" > /dev/null)

	git -C $testroot/repo checkout -q newbranch
	local orig_commit1=`git_show_parent_commit $testroot/repo`
	local orig_commit2=`git_show_head $testroot/repo`

	local short_orig_commit1=`trim_obj_id 12 $orig_commit1`
	local short_orig_commit2=`trim_obj_id 12 $orig_commit2`

	(cd $testroot/wt && got update -b master > /dev/null)
	(cd $testroot/wt && got rm beta d/f/g/new > /dev/null)
	(cd $testroot/wt && got commit \
		-m "removing beta and d/f/g/new on master" > /dev/null)

	git -C $testroot/repo checkout -q master
	local master_commit=`git_show_head $testroot/repo`

	(cd $testroot/wt && got update -b master > /dev/null)
	(cd $testroot/wt && got rebase newbranch > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "rebase succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	local new_commit1=$(cd $testroot/wt && got info | \
		grep '^work tree base commit: ' | cut -d: -f2 | tr -d ' ')

	local short_orig_commit2=`trim_obj_id 12 $orig_commit2`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`

	echo "G  gamma/delta" >> $testroot/stdout.expected
	echo -n "$short_orig_commit1 -> $short_new_commit1" \
		>> $testroot/stdout.expected
	echo ": committing to delta on newbranch" >> $testroot/stdout.expected
	echo "!  beta" >> $testroot/stdout.expected
	echo "!  d/f/g/new" >> $testroot/stdout.expected
	echo -n "Files which had incoming changes but could not be found " \
		>> $testroot/stdout.expected
	echo "in the work tree: 2" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n "got: changes destined for some files were not yet merged " \
		> $testroot/stderr.expected
	echo -n "and should be merged manually if required before the " \
		>> $testroot/stderr.expected
	echo "rebase operation is continued" >> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# ignore the missing changes and continue
	(cd $testroot/wt && got rebase -c > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "rebase failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo -n "$short_orig_commit2 -> no-op change" \
		> $testroot/stdout.expected
	echo ": removing beta and d/f/g/new on newbranch" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/newbranch" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified delta on branch" > $testroot/content.expected
	cat $testroot/wt/gamma/delta > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/beta ]; then
		echo "removed file beta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo checkout -q newbranch
	local new_commit1=`git_show_head $testroot/repo`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`

	(cd $testroot/wt && got log -l3 | grep ^commit > $testroot/stdout)
	echo "commit $new_commit1 (newbranch)" > $testroot/stdout.expected
	echo "commit $master_commit (master)" >> $testroot/stdout.expected
	echo "commit $commit0" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rebase_rm_add_rm_file() {
	local testroot=`test_init rebase_rm_add_rm_file`

	git -C $testroot/repo checkout -q -b newbranch
	git -C $testroot/repo rm -q beta
	git_commit $testroot/repo -m "removing beta from newbranch"
	local orig_commit1=`git_show_head $testroot/repo`

	echo 'restored beta' > $testroot/repo/beta
	git -C $testroot/repo add beta
	git_commit $testroot/repo -m "restoring beta on newbranch"
	local orig_commit2=`git_show_head $testroot/repo`

	git -C $testroot/repo rm -q beta
	git_commit $testroot/repo -m "removing beta from newbranch again"
	local orig_commit3=`git_show_head $testroot/repo`

	git -C $testroot/repo checkout -q master
	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rebase newbranch > $testroot/stdout)

	# this would error out with 'got: file index is corrupt'
	(cd $testroot/wt && got status > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got status command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo checkout -q newbranch
	local new_commit3=`git_show_head $testroot/repo`
	local new_commit2=`git_show_parent_commit $testroot/repo`
	local new_commit1=`git_show_parent_commit $testroot/repo $new_commit2`

	git -C $testroot/repo checkout -q newbranch

	local short_orig_commit1=`trim_obj_id 12 $orig_commit1`
	local short_orig_commit2=`trim_obj_id 12 $orig_commit2`
	local short_orig_commit3=`trim_obj_id 12 $orig_commit3`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`
	local short_new_commit2=`trim_obj_id 12 $new_commit2`
	local short_new_commit3=`trim_obj_id 12 $new_commit3`

	echo "D  beta" > $testroot/stdout.expected
	echo -n "$short_orig_commit1 -> $short_new_commit1" \
		>> $testroot/stdout.expected
	echo ": removing beta from newbranch" >> $testroot/stdout.expected
	echo "A  beta" >> $testroot/stdout.expected
	echo -n "$short_orig_commit2 -> $short_new_commit2" \
		>> $testroot/stdout.expected
	echo ": restoring beta on newbranch" >> $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo -n "$short_orig_commit3 -> $short_new_commit3" \
		>> $testroot/stdout.expected
	echo ": removing beta from newbranch again" >> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/newbranch" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got status command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got log -l4 | grep ^commit > $testroot/stdout)
	echo "commit $new_commit3 (newbranch)" > $testroot/stdout.expected
	echo "commit $new_commit2" >> $testroot/stdout.expected
	echo "commit $new_commit1" >> $testroot/stdout.expected
	echo "commit $master_commit (master)" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rebase_resets_committer() {
	local testroot=`test_init rebase_resets_committer`
	local commit0=`git_show_head $testroot/repo`
	local commit0_author_time=`git_show_author_time $testroot/repo`
	local committer="Flan Luck <flan_luck@openbsd.org>"

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	echo "modified alpha on branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing more changes on newbranch"

	local orig_commit1=`git_show_parent_commit $testroot/repo`
	local orig_commit2=`git_show_head $testroot/repo`
	local orig_author_time2=`git_show_author_time $testroot/repo`

	git -C $testroot/repo checkout -q master
	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && env GOT_AUTHOR="$committer" \
		got rebase newbranch > $testroot/stdout)

	git -C $testroot/repo checkout -q newbranch
	local new_commit1=`git_show_parent_commit $testroot/repo`
	local new_commit2=`git_show_head $testroot/repo`
	local new_author_time2=`git_show_author_time $testroot/repo`

	local short_orig_commit1=`trim_obj_id 12 $orig_commit1`
	local short_orig_commit2=`trim_obj_id 12 $orig_commit2`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`
	local short_new_commit2=`trim_obj_id 12 $new_commit2`

	echo "G  gamma/delta" >> $testroot/stdout.expected
	echo -n "$short_orig_commit1 -> $short_new_commit1" \
		>> $testroot/stdout.expected
	echo ": committing to delta on newbranch" >> $testroot/stdout.expected
	echo "G  alpha" >> $testroot/stdout.expected
	echo -n "$short_orig_commit2 -> $short_new_commit2" \
		>> $testroot/stdout.expected
	echo ": committing more changes on newbranch" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/newbranch" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Original commit only had one author
	(cd $testroot/repo && got log -l1 -c $orig_commit2 | \
		egrep '^(from|via):' > $testroot/stdout)
	echo "from: $GOT_AUTHOR" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Rebased commit should have new committer name added
	(cd $testroot/repo && got log -l1 -c $new_commit2 | \
		egrep '^(from|via):' > $testroot/stdout)
	echo "from: $GOT_AUTHOR" > $testroot/stdout.expected
	echo "via: $committer" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rebase_no_author_info() {
	local testroot=`test_init rebase_no_author_info`
	local commit0=`git_show_head $testroot/repo`
	local commit0_author_time=`git_show_author_time $testroot/repo`
	local committer="$GOT_AUTHOR"

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	echo "modified alpha on branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "committing more changes on newbranch"

	local orig_commit1=`git_show_parent_commit $testroot/repo`
	local orig_commit2=`git_show_head $testroot/repo`
	local orig_author_time2=`git_show_author_time $testroot/repo`

	git -C $testroot/repo checkout -q master
	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# unset in a subshell to avoid affecting our environment
	(unset GOT_AUTHOR && cd $testroot/wt && \
		got rebase newbranch > $testroot/stdout)

	git -C $testroot/repo checkout -q newbranch
	local new_commit1=`git_show_parent_commit $testroot/repo`
	local new_commit2=`git_show_head $testroot/repo`
	local new_author_time2=`git_show_author_time $testroot/repo`

	local short_orig_commit1=`trim_obj_id 12 $orig_commit1`
	local short_orig_commit2=`trim_obj_id 12 $orig_commit2`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`
	local short_new_commit2=`trim_obj_id 12 $new_commit2`

	echo "G  gamma/delta" >> $testroot/stdout.expected
	echo -n "$short_orig_commit1 -> $short_new_commit1" \
		>> $testroot/stdout.expected
	echo ": committing to delta on newbranch" >> $testroot/stdout.expected
	echo "G  alpha" >> $testroot/stdout.expected
	echo -n "$short_orig_commit2 -> $short_new_commit2" \
		>> $testroot/stdout.expected
	echo ": committing more changes on newbranch" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/newbranch" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Original commit only had one author
	(cd $testroot/repo && got log -l1 -c $orig_commit2 | \
		egrep '^(from|via):' > $testroot/stdout)
	echo "from: $committer" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Author info of rebased commit should match the original
	(cd $testroot/repo && got log -l1 -c $new_commit2 | \
		egrep '^(from|via):' > $testroot/stdout)
	echo "from: $committer" > $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_rebase_nonbranch() {
	local testroot=`test_init rebase_nonbranch`

	got ref -r $testroot/repo -c refs/heads/master \
		refs/remotes/origin/master >/dev/null
	
	got checkout -b master $testroot/repo $testroot/wt >/dev/null

	(cd $testroot/wt && got rebase origin/master > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "rebase succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo -n "got: will not rebase a branch which lives outside the " \
		> $testroot/stderr.expected
	echo '"refs/heads/" reference namespace' >> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_rebase_umask() {
	local testroot=`test_init rebase_umask`
	local commit0=`git_show_head "$testroot/repo"`

	got checkout "$testroot/repo" "$testroot/wt" >/dev/null
	(cd "$testroot/wt" && got branch newbranch) >/dev/null

	echo "modified alpha on branch" >$testroot/wt/alpha
	(cd "$testroot/wt" && got commit -m 'modified alpha on newbranch') \
		>/dev/null

	(cd "$testroot/wt" && got update -b master) >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update failed!" >&2
		test_done "$testroot" $ret
		return 1
	fi

	echo "modified beta on master" >$testroot/wt/beta
	(cd "$testroot/wt" && got commit -m 'modified beta on master') \
		>/dev/null
	(cd "$testroot/wt" && got update) >/dev/null

	# using a subshell to avoid clobbering global umask
	(umask 077 && cd "$testroot/wt" && got rebase newbranch) >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got rebase failed" >&2
		test_done "$testroot" $ret
		return 1
	fi

	ls -l "$testroot/wt/alpha" | grep -q ^-rw-------
	if [ $? -ne 0 ]; then
		echo "alpha is not 0600 after rebase" >&2
		ls -l "$testroot/wt/alpha" >&2
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" 0
}

test_rebase_out_of_date2() {
	local testroot=`test_init rebase_out_of_date2`
	local commit0=`git_show_head $testroot/repo`
	local commit0_author_time=`git_show_author_time $testroot/repo`

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	local orig_commit1=`git_show_parent_commit $testroot/repo`
	local orig_commit2=`git_show_head $testroot/repo`
	local orig_author_time2=`git_show_author_time $testroot/repo`

	git -C $testroot/repo checkout -q master
	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# Backdate the file alpha to an earlier version.
	# This sets the work tree's base commit ID back to $commit0,
	# which is out-of-date with respect to the master branch.
	(cd $testroot/wt && got update -c $commit0 alpha > /dev/null)

	# Rebase into an out-of-date work tree should be refused.
	(cd $testroot/wt && got rebase newbranch > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "rebase succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo -n > $testroot/stdout.expected
	echo -n "got: work tree must be updated before it can be used to " \
		> $testroot/stderr.expected
	echo "rebase a branch" >> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_rebase_one_commit() {
	local testroot=`test_init rebase_one_commit`

	if ! got checkout $testroot/repo $testroot/wt >/dev/null; then
		test_done "$testroot" 1
		return 1
	fi

	(cd $testroot/wt && got branch newbranch) >/dev/null

	echo "modified alpha on newbranch" >$testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'edit alpha') >/dev/null
	(cd $testroot/wt && got update) >/dev/null
	local commit=`git_show_branch_head $testroot/repo newbranch`

	echo -n '' > $testroot/stderr.expected

	(cd $testroot/wt && got rebase master >$testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "rebase command failed unexpectedly" >&2
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "1"
		return 1
	fi

	echo "Forwarding refs/heads/master to commit $commit" \
		>$testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	if ! cmp -s $testroot/stdout.expected $testroot/stdout; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" 0
}

test_rebase_merge_commit() {
	local testroot=`test_init rebase_merge_commit`
	local commit0=`git_show_branch_head $testroot/repo master`

	if ! got checkout $testroot/repo $testroot/wt >/dev/null; then
		test_done "$testroot" 1
		return 1
	fi

	echo "modified delta on master" >$testroot/wt/gamma/delta
	(cd $testroot/wt && got commit -m 'edit delta') >/dev/null
	local commit1=`git_show_branch_head $testroot/repo master`

	(cd $testroot/wt && got branch -c $commit0 newbranch1) >/dev/null
	echo "modified alpha on newbranch1" >$testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'edit alpha') >/dev/null
	(cd $testroot/wt && got update) >/dev/null
	local commit2=`git_show_branch_head $testroot/repo master`

	echo "modified alpha on newbranch1 again" >$testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'edit alpha again') >/dev/null
	(cd $testroot/wt && got update) >/dev/null
	local commit3=`git_show_branch_head $testroot/repo newbranch1`

	(cd $testroot/wt && got branch -c $commit0 newbranch2) >/dev/null
	echo "modified beta on newbranch2" >$testroot/wt/beta
	(cd $testroot/wt && got commit -m 'edit beta') >/dev/null
	(cd $testroot/wt && got update) >/dev/null
	local commit4=`git_show_branch_head $testroot/repo newbranch2`

	echo "modified beta on newbranch2 again" >$testroot/wt/beta
	(cd $testroot/wt && got commit -m 'edit beta again') >/dev/null
	(cd $testroot/wt && got update) >/dev/null
	local commit5=`git_show_branch_head $testroot/repo newbranch2`

	echo -n '' > $testroot/stderr.expected

	(cd $testroot/wt && got merge newbranch1 >$testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "merge command failed unexpectedly" >&2
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "1"
		return 1
	fi

	local merge_commit=`git_show_branch_head $testroot/repo newbranch2`

	echo "G  alpha" >> $testroot/stdout.expected
	echo -n "Merged refs/heads/newbranch1 into refs/heads/newbranch2: " \
		>> $testroot/stdout.expected
	echo $merge_commit >> $testroot/stdout.expected

	if ! cmp -s $testroot/stdout.expected $testroot/stdout; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" 1
		return 1
	fi

	(cd $testroot/wt && got update -b master) >/dev/null
	(cd $testroot/wt && got rebase newbranch2) > $testroot/stdout

	local new_commit5=`git_show_parent_commit $testroot/repo newbranch2`
	local short_orig_commit5=`trim_obj_id 12 $commit5`
	local short_new_commit5=`trim_obj_id 12 $new_commit5`

	local new_commit4=`git_show_parent_commit $testroot/repo $new_commit5`
	local short_orig_commit4=`trim_obj_id 12 $commit4`
	local short_new_commit4=`trim_obj_id 12 $new_commit4`

	local new_merge_commit=`git_show_branch_head $testroot/repo newbranch2`
	local short_orig_merge_commit=`trim_obj_id 12 $merge_commit`
	local short_new_merge_commit=`trim_obj_id 12 $new_merge_commit`

	echo "G  beta"> $testroot/stdout.expected
	echo "$short_orig_commit4 -> $short_new_commit4: edit beta" \
		>> $testroot/stdout.expected
	echo "G  beta" >> $testroot/stdout.expected
	echo "$short_orig_commit5 -> $short_new_commit5: edit beta again" \
		>> $testroot/stdout.expected
	echo "G  alpha" >> $testroot/stdout.expected
	echo -n "$short_orig_merge_commit -> $short_new_merge_commit: " \
		>> $testroot/stdout.expected
	echo "merge refs/heads/newbranch1 into refs/head" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/newbranch2" \
		>> $testroot/stdout.expected

	if ! cmp -s $testroot/stdout.expected $testroot/stdout; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" 0
}

test_rebase_across_merge_commit() {
	local testroot=`test_init rebase_across_merge_commit`
	local commit0=`git_show_branch_head $testroot/repo master`

	if ! got checkout $testroot/repo $testroot/wt >/dev/null; then
		test_done "$testroot" 1
		return 1
	fi

	echo "modified delta on master" >$testroot/wt/gamma/delta
	(cd $testroot/wt && got commit -m 'edit delta') >/dev/null
	local commit1=`git_show_branch_head $testroot/repo master`

	(cd $testroot/wt && got branch -c $commit0 newbranch1) >/dev/null
	echo "modified alpha on newbranch1" >$testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'edit alpha') >/dev/null
	(cd $testroot/wt && got update) >/dev/null
	local commit2=`git_show_branch_head $testroot/repo master`

	echo "modified alpha on newbranch1 again" >$testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'edit alpha again') >/dev/null
	(cd $testroot/wt && got update) >/dev/null
	local commit3=`git_show_branch_head $testroot/repo newbranch1`

	(cd $testroot/wt && got branch -c $commit0 newbranch2) >/dev/null
	echo "modified beta on newbranch2" >$testroot/wt/beta
	(cd $testroot/wt && got commit -m 'edit beta') >/dev/null
	(cd $testroot/wt && got update) >/dev/null
	local commit4=`git_show_branch_head $testroot/repo newbranch2`

	echo "modified beta on newbranch2 again" >$testroot/wt/beta
	(cd $testroot/wt && got commit -m 'edit beta again') >/dev/null
	(cd $testroot/wt && got update) >/dev/null
	local commit5=`git_show_branch_head $testroot/repo newbranch2`

	echo -n '' > $testroot/stderr.expected

	(cd $testroot/wt && got merge newbranch1 >$testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "merge command failed unexpectedly" >&2
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "1"
		return 1
	fi

	local merge_commit=`git_show_branch_head $testroot/repo newbranch2`

	echo "G  alpha" >> $testroot/stdout.expected
	echo -n "Merged refs/heads/newbranch1 into refs/heads/newbranch2: " \
		>> $testroot/stdout.expected
	echo $merge_commit >> $testroot/stdout.expected

	if ! cmp -s $testroot/stdout.expected $testroot/stdout; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" 1
		return 1
	fi

	(cd $testroot/wt && got rebase master) > $testroot/stdout

	local new_commit1=`git_show_head $testroot/repo`
	local short_orig_commit1=`trim_obj_id 12 $commit1`
	local short_new_commit1=`trim_obj_id 12 $new_commit1`

	echo "G  gamma/delta"> $testroot/stdout.expected
	echo "$short_orig_commit1 -> $short_new_commit1: edit delta" \
		>> $testroot/stdout.expected
	echo "Switching work tree to refs/heads/master" \
		>> $testroot/stdout.expected

	if ! cmp -s $testroot/stdout.expected $testroot/stdout; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" 0
}

test_rebase_merged_history_traversal() {
	local testroot=`test_init rebase_merged_history_traversal`
	local commit0=`git_show_branch_head $testroot/repo master`

	if ! got checkout $testroot/repo $testroot/wt >/dev/null; then
		test_done "$testroot" 1
		return 1
	fi

	(cd $testroot/wt && got branch -c $commit0 newbranch1) >/dev/null
	echo "modified alpha on newbranch1" >$testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'edit alpha') >/dev/null
	(cd $testroot/wt && got update) >/dev/null
	local commit2=`git_show_branch_head $testroot/repo master`

	echo "modified alpha on newbranch1 again" >$testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'edit alpha again') >/dev/null
	(cd $testroot/wt && got update) >/dev/null
	local commit3=`git_show_branch_head $testroot/repo newbranch1`

	echo -n '' > $testroot/stderr.expected

	(cd $testroot/wt && got update -b master) >/dev/null
	(cd $testroot/wt && got merge -M newbranch1 >$testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "merge command failed unexpectedly" >&2
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "1"
		return 1
	fi

	local merge_commit=`git_show_head $testroot/repo`

	echo "G  alpha" > $testroot/stdout.expected
	echo -n "Merged refs/heads/newbranch1 into refs/heads/master: " \
		>> $testroot/stdout.expected
	echo $merge_commit >> $testroot/stdout.expected
	if ! cmp -s $testroot/stdout.expected $testroot/stdout; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" 1
		return 1
	fi

	echo "modified delta on master" >$testroot/wt/gamma/delta
	(cd $testroot/wt && got commit -m 'edit delta') >/dev/null
	local commit1=`git_show_branch_head $testroot/repo master`

	(cd $testroot/wt && got branch newbranch2) >/dev/null
	(cd $testroot/wt && got rebase newbranch1) > $testroot/stdout

	echo "Forwarding refs/heads/newbranch1 to commit $commit1" > \
		$testroot/stdout.expected
	echo "Switching work tree to refs/heads/newbranch1" \
		>> $testroot/stdout.expected

	if ! cmp -s $testroot/stdout.expected $testroot/stdout; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_rebase_basic
run_test test_rebase_ancestry_check
run_test test_rebase_continue
run_test test_rebase_abort
run_test test_rebase_no_op_change
run_test test_rebase_in_progress
run_test test_rebase_path_prefix
run_test test_rebase_preserves_logmsg
run_test test_rebase_preserves_author_data
run_test test_rebase_no_commits_to_rebase
run_test test_rebase_forward
run_test test_rebase_forward_path_prefix
run_test test_rebase_out_of_date
run_test test_rebase_trims_empty_dir
run_test test_rebase_delete_missing_file
run_test test_rebase_rm_add_rm_file
run_test test_rebase_resets_committer
run_test test_rebase_no_author_info
run_test test_rebase_nonbranch
run_test test_rebase_umask
run_test test_rebase_out_of_date2
run_test test_rebase_one_commit
run_test test_rebase_merge_commit
run_test test_rebase_across_merge_commit
run_test test_rebase_merged_history_traversal
