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

test_parseargs "$@"
run_test test_backout_basic
run_test test_backout_edits_for_file_since_deleted
run_test test_backout_next_commit
run_test test_backout_umask
