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
		test_done "$testroot" "$ret"
		return 1
	fi

	# diff non-existent path
	(cd $testroot/wt && got diff nonexistent > $testroot/stdout \
		2> $testroot/stderr)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: nonexistent: No such file or directory" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
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
	local base_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	sed -i 's/2/22/' $testroot/repo/numbers
	sed -i 's/8/33/' $testroot/repo/numbers
	git_commit $testroot/repo -m "modified line 2"
	local head_rev=`git_show_head $testroot/repo`

	# modify lines 2 and 8 in conflicting ways
	sed -i 's/2/77/' $testroot/wt/numbers
	sed -i 's/8/88/' $testroot/wt/numbers

	echo "C  numbers" > $testroot/stdout.expected
	echo -n "Updated to commit $head_rev" >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected

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
	echo '@@ -1,8 +1,20 @@' >> $testroot/stdout.expected
	echo ' 1' >> $testroot/stdout.expected
	echo "+<<<<<<< merged change: commit $head_rev" \
		>> $testroot/stdout.expected
	echo ' 22' >> $testroot/stdout.expected
	echo "+||||||| 3-way merge base: commit $base_commit" \
		>> $testroot/stdout.expected
	echo '+2' >> $testroot/stdout.expected
	echo '+=======' >> $testroot/stdout.expected
	echo '+77' >> $testroot/stdout.expected
	echo '+>>>>>>>' >> $testroot/stdout.expected
	echo ' 3' >> $testroot/stdout.expected
	echo ' 4' >> $testroot/stdout.expected
	echo ' 5' >> $testroot/stdout.expected
	echo ' 6' >> $testroot/stdout.expected
	echo ' 7' >> $testroot/stdout.expected
	echo "+<<<<<<< merged change: commit $head_rev" \
		>> $testroot/stdout.expected
	echo ' 33' >> $testroot/stdout.expected
	echo "+||||||| 3-way merge base: commit $base_commit" \
		>> $testroot/stdout.expected
	echo '+8' >> $testroot/stdout.expected
	echo '+=======' >> $testroot/stdout.expected
	echo '+88' >> $testroot/stdout.expected
	echo '+>>>>>>>' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_diff_tag {
	local testroot=`test_init diff_tag`
	local commit_id0=`git_show_head $testroot/repo`
	local tag1=1.0.0
	local tag2=2.0.0

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "changed alpha"
	local commit_id1=`git_show_head $testroot/repo`

	(cd $testroot/repo && git tag -m "test" $tag1)

	echo "new file" > $testroot/repo/new
	(cd $testroot/repo && git add new)
	git_commit $testroot/repo -m "new file"
	local commit_id2=`git_show_head $testroot/repo`

	(cd $testroot/repo && git tag -m "test" $tag2)

	echo "diff $commit_id0 refs/tags/$tag1" > $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id0 -i | grep 'alpha$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'alpha$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified alpha' >> $testroot/stdout.expected

	got diff -r $testroot/repo $commit_id0 $tag1 > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "diff refs/tags/$tag1 refs/tags/$tag2" > $testroot/stdout.expected
	echo "blob - /dev/null" >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i -c $commit_id2 | grep 'new$' | \
		cut -d' ' -f 1 | tr -d '\n' >> $testroot/stdout.expected
	echo " (mode 644)" >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected

	got diff -r $testroot/repo $tag1 $tag2 > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_diff_lightweight_tag {
	local testroot=`test_init diff_tag`
	local commit_id0=`git_show_head $testroot/repo`
	local tag1=1.0.0
	local tag2=2.0.0

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "changed alpha"
	local commit_id1=`git_show_head $testroot/repo`

	(cd $testroot/repo && git tag $tag1)

	echo "new file" > $testroot/repo/new
	(cd $testroot/repo && git add new)
	git_commit $testroot/repo -m "new file"
	local commit_id2=`git_show_head $testroot/repo`

	(cd $testroot/repo && git tag $tag2)

	echo "diff $commit_id0 refs/tags/$tag1" > $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id0 -i | grep 'alpha$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'alpha$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified alpha' >> $testroot/stdout.expected

	got diff -r $testroot/repo $commit_id0 $tag1 > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "diff refs/tags/$tag1 refs/tags/$tag2" > $testroot/stdout.expected
	echo "blob - /dev/null" >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i -c $commit_id2 | grep 'new$' | \
		cut -d' ' -f 1 | tr -d '\n' >> $testroot/stdout.expected
	echo " (mode 644)" >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected

	got diff -r $testroot/repo $tag1 $tag2 > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_diff_ignore_whitespace {
	local testroot=`test_init diff_ignore_whitespace`
	local commit_id0=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha   " > $testroot/wt/alpha

	(cd $testroot/wt && got diff -w > $testroot/stdout)

	echo "diff $commit_id0 $testroot/wt" > $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id0 -i | grep 'alpha$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo 'file + alpha' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

run_test test_diff_basic
run_test test_diff_shows_conflict
run_test test_diff_tag
run_test test_diff_lightweight_tag
run_test test_diff_ignore_whitespace
