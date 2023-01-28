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

test_backout_basic() {
	local testroot=`test_init backout_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new" > $testroot/wt/new
	(cd $testroot/wt && got add new > /dev/null)
	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got rm epsilon/zeta > /dev/null)
	(cd $testroot/wt && got commit -m "bad changes" > /dev/null)

	local bad_commit=`git_show_head $testroot/repo`


	(cd $testroot/wt && got update > /dev/null)

	echo "modified beta" > $testroot/wt/beta
	(cd $testroot/wt && got commit -m "changing beta" > /dev/null)

	(cd $testroot/wt && got update > /dev/null)

	(cd $testroot/wt && got backout $bad_commit > $testroot/stdout)

	echo "G  alpha" > $testroot/stdout.expected
	echo "A  epsilon/zeta" >> $testroot/stdout.expected
	echo "D  new" >> $testroot/stdout.expected
	echo "Backed out commit $bad_commit" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e "$testroot/wt/new" ]; then
		echo "file '$testroot/wt/new' still exists on disk" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ ! -e "$testroot/wt/epsilon/zeta" ]; then
		echo "file '$testroot/wt/epsilon/zeta' is missing on disk" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'M  alpha' > $testroot/stdout.expected
	echo 'A  epsilon/zeta' >> $testroot/stdout.expected
	echo 'D  new' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_backout_edits_for_file_since_deleted() {
	local testroot=`test_init backout_edits_for_file_since_deleted`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "changing alpha" > /dev/null)

	local bad_commit=`git_show_head $testroot/repo`


	(cd $testroot/wt && got update > /dev/null)

	(cd $testroot/wt && got rm alpha > /dev/null)
	(cd $testroot/wt && got commit -m "removing alpha" > /dev/null)

	(cd $testroot/wt && got update > /dev/null)

	(cd $testroot/wt && got backout $bad_commit > $testroot/stdout)

	echo "!  alpha" > $testroot/stdout.expected
	echo "Backed out commit $bad_commit" >> $testroot/stdout.expected
	echo -n "Files which had incoming changes but could not be found " \
		>> $testroot/stdout.expected
	echo "in the work tree: 1" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e "$testroot/wt/alpha" ]; then
		echo "file '$testroot/wt/alpha' still exists on disk" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n '' > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_backout_next_commit() {
	local testroot=`test_init backout_next_commit`
	local commit0=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new" > $testroot/wt/new
	(cd $testroot/wt && got add new > /dev/null)
	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got rm epsilon/zeta > /dev/null)
	(cd $testroot/wt && got commit -m "bad changes" > /dev/null)

	local bad_commit=`git_show_head $testroot/repo`

	(cd $testroot/wt && got update -c $commit0 > /dev/null)

	(cd $testroot/wt && got backout $bad_commit > $testroot/stdout)

	echo "G  alpha" > $testroot/stdout.expected
	echo "G  epsilon/zeta" >> $testroot/stdout.expected
	echo "!  new" >> $testroot/stdout.expected
	echo "Backed out commit $bad_commit" >> $testroot/stdout.expected
	echo -n "Files which had incoming changes but could not be found " \
		>> $testroot/stdout.expected
	echo "in the work tree: 1" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e "$testroot/wt/new" ]; then
		echo "file '$testroot/wt/new' still exists on disk" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "zeta" > $testroot/content.expected
	cat $testroot/wt/epsilon/zeta > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n '' > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_backout_umask() {
	local testroot=`test_init backout_umask`

	got checkout "$testroot/repo" "$testroot/wt" >/dev/null
	echo "edit alpha" >$testroot/wt/alpha
	(cd "$testroot/wt" && got commit -m 'edit alpha') >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" $ret
		return 1
	fi

	local commit=`git_show_head "$testroot/repo"`

	(cd "$testroot/wt" && got update) >/dev/null

	# using a subshell to avoid clobbering global umask
	(umask 077 && cd "$testroot/wt" && got backout $commit) >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" $ret
		return 1
	fi

	if ! ls -l "$testroot/wt/alpha" | grep -q ^-rw-------; then
		echo "alpha is not 0600 after backout" >&2
		ls -l "$testroot/wt/alpha" >&2
		test_done "$testroot" $ret
		return 1
	fi

	test_done "$testroot" 0
}

test_backout_logmsg_ref() {
	local testroot=`test_init backout_logmsg_ref`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git checkout -q -b newbranch)

	echo "modified delta on branch" > $testroot/repo/gamma/delta
	echo "modified alpha on branch" > $testroot/repo/alpha
	(cd $testroot/repo && git rm -q beta)
	echo "new file on branch" > $testroot/repo/epsilon/new
	(cd $testroot/repo && git add epsilon/new)

	git_commit $testroot/repo -m "commit changes on newbranch"
	local commit_time=`git_show_author_time $testroot/repo`
	local branch_rev=`git_show_head $testroot/repo`

	echo "modified new file on branch" > $testroot/repo/epsilon/new

	git_commit $testroot/repo -m "commit modified new file on newbranch"
	local commit_time2=`git_show_author_time $testroot/repo`
	local branch_rev2=`git_show_head $testroot/repo`

	(cd $testroot/wt && got backout $branch_rev > /dev/null)
	(cd $testroot/wt && got backout $branch_rev2 > /dev/null)

	# show all backout log message refs in the work tree
	local sep="-----------------------------------------------"
	local logmsg="commit changes on newbranch"
	local changeset=" M  alpha\n D  beta\n A  epsilon/new\n M  gamma/delta"
	local logmsg2="commit modified new file on newbranch"
	local changeset2=" M  epsilon/new"
	local date=`date -u -r $commit_time +"%a %b %e %X %Y UTC"`
	local date2=`date -u -r $commit_time2 +"%a %b %e %X %Y UTC"`
	local ymd=`date -u -r $commit_time +"%F"`
	local short_id=$(printf '%.7s' $branch_rev)
	local ymd2=`date -u -r $commit_time2 +"%F"`
	local short_id2="newbranch"
	local sorted=$(printf "$branch_rev\n$branch_rev2" | sort)

	for r in $sorted; do
		echo $sep >> $testroot/stdout.expected
		if [ $r == $branch_rev ]; then
			echo "commit $r" >> $testroot/stdout.expected
			echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
			echo "date: $date" >> $testroot/stdout.expected
			printf " \n $logmsg\n \n" >> $testroot/stdout.expected
			printf "$changeset\n\n" >> $testroot/stdout.expected

			# for forthcoming wt 'backout -X' test
			echo "deleted: $ymd $short_id $logmsg" >> \
			    $testroot/stdout.wt_deleted
		else
			echo "commit $r (newbranch)" \
			    >> $testroot/stdout.expected
			echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
			echo "date: $date2" >> $testroot/stdout.expected
			printf " \n $logmsg2\n \n" >> $testroot/stdout.expected
			printf "$changeset2\n\n" >> $testroot/stdout.expected

			# for forthcoming wt 'backout -X' test
			echo "deleted: $ymd2 $short_id2 $logmsg2" >> \
			    $testroot/stdout.wt_deleted
		fi
	done

	(cd $testroot/wt && got backout -l > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# only show log message ref of the specified commit id
	echo $sep > $testroot/stdout.expected
	echo "commit $branch_rev" >> $testroot/stdout.expected
	echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo "date: $date" >> $testroot/stdout.expected
	printf " \n $logmsg\n \n" >> $testroot/stdout.expected
	printf "$changeset\n\n" >> $testroot/stdout.expected

	(cd $testroot/wt && got backout -l $branch_rev > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# only show log message ref of the specified symref
	echo $sep > $testroot/stdout.expected
	echo "commit $branch_rev2 (newbranch)" >> $testroot/stdout.expected
	echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo "date: $date2" >> $testroot/stdout.expected
	printf " \n $logmsg2\n \n" >> $testroot/stdout.expected
	printf "$changeset2\n\n" >> $testroot/stdout.expected

	(cd $testroot/wt && got backout -l "newbranch" > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# create a second work tree with backed-out commits and ensure
	# bo -l within the new work tree only shows the refs it created
	got checkout $testroot/repo $testroot/wt2 > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git checkout -q -b newbranch2)

	echo "modified delta on branch2" > $testroot/repo/gamma/delta
	echo "modified alpha on branch2" > $testroot/repo/alpha
	echo "new file on branch2" > $testroot/repo/epsilon/new2
	(cd $testroot/repo && git add epsilon/new2)

	git_commit $testroot/repo -m "commit changes on newbranch2"
	local b2_commit_time=`git_show_author_time $testroot/repo`
	local branch2_rev=`git_show_head $testroot/repo`

	echo "modified file new2 on branch2" > $testroot/repo/epsilon/new2

	git_commit $testroot/repo -m "commit modified file new2 on newbranch2"
	local b2_commit_time2=`git_show_author_time $testroot/repo`
	local branch2_rev2=`git_show_head $testroot/repo`

	(cd $testroot/wt2 && got backout $branch2_rev > /dev/null)
	(cd $testroot/wt2 && got backout $branch2_rev2 > /dev/null)

	local b2_logmsg="commit changes on newbranch2"
	local b2_changeset=" M  alpha\n A  epsilon/new2\n M  gamma/delta"
	local b2_logmsg2="commit modified file new2 on newbranch2"
	local b2_changeset2=" M  epsilon/new2"
	date=`date -u -r $b2_commit_time +"%a %b %e %X %Y UTC"`
	date2=`date -u -r $b2_commit_time2 +"%a %b %e %X %Y UTC"`
	sorted=$(printf "$branch2_rev\n$branch2_rev2" | sort)

	echo -n > $testroot/stdout.expected
	for r in $sorted; do
		echo $sep >> $testroot/stdout.expected
		if [ $r == $branch2_rev ]; then
			echo "commit $r" >> $testroot/stdout.expected
			echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
			echo "date: $date" >> $testroot/stdout.expected
			printf " \n $b2_logmsg\n \n" >> \
			    $testroot/stdout.expected
			printf "$b2_changeset\n\n" >> \
			    $testroot/stdout.expected
		else
			echo "commit $r (newbranch2)" \
			    >> $testroot/stdout.expected
			echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
			echo "date: $date2" >> $testroot/stdout.expected
			printf " \n $b2_logmsg2\n \n" >> \
			    $testroot/stdout.expected
			printf "$b2_changeset2\n\n" >> \
			    $testroot/stdout.expected
		fi
	done

	(cd $testroot/wt2 && got backout -l > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# ensure both wt and wt2 logmsg refs can be retrieved from the repo
	sorted=`printf \
	    "$branch_rev\n$branch_rev2\n$branch2_rev\n$branch2_rev2" | sort`

	echo -n > $testroot/stdout.expected
	for r in $sorted; do
		echo "commit $r" >> $testroot/stdout.expected
	done

	(cd $testroot/repo && got backout -l | grep ^commit | \
	    sort | cut -f1,2 -d' ' > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# delete logmsg ref of the specified commit in work tree 2
	ymd=`date -u -r $b2_commit_time +"%F"`
	short_id=$(printf '%.7s' $branch2_rev)

	echo "deleted: $ymd $short_id $b2_logmsg" > $testroot/stdout.expected
	(cd $testroot/wt2 && got backout -X $branch2_rev > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# delete all logmsg refs in work tree 1
	(cd $testroot && mv stdout.wt_deleted stdout.expected)
	(cd $testroot/wt && got backout -X > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# confirm all work tree 1 refs were deleted
	echo -n > $testroot/stdout.expected
	(cd $testroot/wt && got backout -l > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# make sure the remaining ref in work tree 2 was not also deleted
	echo $sep > $testroot/stdout.expected
	echo "commit $branch2_rev2 (newbranch2)" >> $testroot/stdout.expected
	echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo "date: $date2" >> $testroot/stdout.expected
	printf " \n $b2_logmsg2\n \n" >> $testroot/stdout.expected
	printf "$b2_changeset2\n\n" >> $testroot/stdout.expected

	(cd $testroot/wt2 && got backout -l > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# ensure we can delete work tree refs from the repository dir
	ymd=`date -u -r $b2_commit_time2 +"%F"`
	echo "deleted: $ymd newbranch2 $b2_logmsg2" > $testroot/stdout.expected
	(cd $testroot/repo && got backout -X > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_backout_basic
run_test test_backout_edits_for_file_since_deleted
run_test test_backout_next_commit
run_test test_backout_umask
run_test test_backout_logmsg_ref
