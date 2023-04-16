#!/bin/sh
#
# Copyright (c) 2023 Mark Jamsek <mark@jamsek.dev>
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

test_blame_basic()
{
	test_init blame_basic 80 8

	local commit_id1=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo aaaa >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "a change" > /dev/null)
	local commit_id2=`git_show_head $testroot/repo`

	echo bbbb >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "b change" > /dev/null)
	local commit_id3=`git_show_head $testroot/repo`

	echo cccc >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "c change" > /dev/null)
	local commit_id4=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local ymd=`date -u -r $author_time +"%G-%m-%d"`

	cat <<EOF >$TOG_TEST_SCRIPT
WAIT_FOR_UI	wait for blame to finish
SCREENDUMP
EOF

	local commit_id1_short=`trim_obj_id 32 $commit_id1`
	local commit_id2_short=`trim_obj_id 32 $commit_id2`
	local commit_id3_short=`trim_obj_id 32 $commit_id3`
	local commit_id4_short=`trim_obj_id 32 $commit_id4`

	cat <<EOF >$testroot/view.expected
commit $commit_id4
[1/4] /alpha
$commit_id1_short alpha
$commit_id2_short aaaa
$commit_id3_short bbbb
$commit_id4_short cccc


EOF

	cd $testroot/wt && tog blame alpha
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_blame_basic
