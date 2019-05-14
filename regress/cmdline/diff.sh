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

function test_diff_basic {
	local testroot=`test_init diff_basic`
	local head_rev=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta >/dev/null)
	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)

	echo "diff $head_rev $testroot/wt" > $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'alpha$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + alpha' >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified alpha' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'beta$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + /dev/null' >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ beta' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-beta' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo 'file + new' >> $testroot/stdout.expected
	echo '--- new' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_diff_shows_conflict {
	local testroot=`test_init diff_shows_conflict 1`

	echo "1" > $testroot/repo/numbers
	echo "2" >> $testroot/repo/numbers
	echo "3" >> $testroot/repo/numbers
	echo "4" >> $testroot/repo/numbers
	echo "5" >> $testroot/repo/numbers
	echo "6" >> $testroot/repo/numbers
	echo "7" >> $testroot/repo/numbers
	echo "8" >> $testroot/repo/numbers
	(cd $testroot/repo && git add numbers)
	git_commit $testroot/repo -m "added numbers file"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	sed -i 's/2/22/' $testroot/repo/numbers
	git_commit $testroot/repo -m "modified line 2"
	local head_rev=`git_show_head $testroot/repo`

	# modify line 2 in a conflicting way
	sed -i 's/2/77/' $testroot/wt/numbers

	echo "C  numbers" > $testroot/stdout.expected
	echo -n "Updated to commit $head_rev" >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "diff $head_rev $testroot/wt" > $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'numbers$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + numbers' >> $testroot/stdout.expected
	echo '--- numbers' >> $testroot/stdout.expected
	echo '+++ numbers' >> $testroot/stdout.expected
	echo '@@ -1,5 +1,9 @@' >> $testroot/stdout.expected
	echo ' 1' >> $testroot/stdout.expected
	echo "+<<<<<<< commit $head_rev" >> $testroot/stdout.expected
	echo ' 22' >> $testroot/stdout.expected
	echo '+=======' >> $testroot/stdout.expected
	echo '+77' >> $testroot/stdout.expected
	echo '+>>>>>>> numbers' >> $testroot/stdout.expected
	echo ' 3' >> $testroot/stdout.expected
	echo ' 4' >> $testroot/stdout.expected
	echo ' 5' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

run_test test_diff_basic
run_test test_diff_shows_conflict
