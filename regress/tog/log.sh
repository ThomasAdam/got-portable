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

test_log_hsplit_diff()
{
	test_init log_hsplit_diff

	local head_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local date=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	local ymd=`date -u -r $author_time +"%G-%m-%d"`

	cat <<EOF >$testroot/log_hsplit_diff
KEY_ENTER	open diff view of selected commit
S		toggle horizontal split
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
commit $head_id [1/1] master
$ymd flan_hacker  adding the test tree




--------------------------------------------------------------------------------
[1/40] diff /dev/null $head_id
commit $head_id (master)
from: Flan Hacker <flan_hacker@openbsd.org>
date: $date

adding the test tree

A  alpha         |  1+  0-
A  beta          |  1+  0-
A  epsilon/zeta  |  1+  0-
A  gamma/delta   |  1+  0-

4 files changed, 4 insertions(+), 0 deletions(-)

commit - /dev/null
commit + $head_id
blob - /dev/null
EOF

	cd $testroot/repo && tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_log_vsplit_diff()
{
	# make screen wide enough for vsplit
	test_init log_vsplit_diff 142

	local head_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local date=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	local ymd=`date -u -r $author_time +"%G-%m-%d"`
	local blobid_alpha=`get_blob_id $testroot/repo "" alpha`
	local blobid_beta=`get_blob_id $testroot/repo "" beta`

	cat <<EOF >$testroot/log_vsplit_diff
KEY_ENTER	open diff view of selected commit in vertical split
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
commit $head_id [1/1] master |[1/40] diff /dev/null $head_id
$ymd flan_hacker  adding the test tree                 |commit $head_id (master)
                                                             |from: Flan Hacker <flan_hacker@openbsd.org>
                                                             |date: $date
                                                             |
                                                             |adding the test tree
                                                             |
                                                             |A  alpha         |  1+  0-
                                                             |A  beta          |  1+  0-
                                                             |A  epsilon/zeta  |  1+  0-
                                                             |A  gamma/delta   |  1+  0-
                                                             |
                                                             |4 files changed, 4 insertions(+), 0 deletions(-)
                                                             |
                                                             |commit - /dev/null
                                                             |commit + $head_id
                                                             |blob - /dev/null
                                                             |blob + $blobid_alpha (mode 644)
                                                             |--- /dev/null
                                                             |+++ alpha
                                                             |@@ -0,0 +1 @@
                                                             |+alpha
                                                             |blob - /dev/null
                                                             |blob + $blobid_beta (mode 644)
EOF

	cd $testroot/repo && tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_log_show_author()
{
	# make view wide enough to show id
	test_init log_show_author 120 4

	local head_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local date=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	local ymd=`date -u -r $author_time +"%G-%m-%d"`
	local head_id_len8=`trim_obj_id 32 $head_id`

	echo "mod alpha" > $testroot/repo/alpha
	cd $testroot/repo && git add .
	cd $testroot/repo && \
	    git commit --author "Johnny Cash <john@cash.net>" -m author > \
	    /dev/null

	local commit1=`git_show_head $testroot/repo`
	local id1_len8=`trim_obj_id 32 $commit1`

	cat <<EOF >$testroot/log_show_author
@		toggle show author
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
commit $commit1 [1/2] master
$ymd $id1_len8 john         author
$ymd $head_id_len8 flan_hacker  adding the test tree
:show commit author
EOF

	cd $testroot/repo && tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_log_scroll_right()
{
	test_init log_scroll_right 80 3

	local head_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local date=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	local ymd=`date -u -r $author_time +"%G-%m-%d"`
	local msg="scroll this log message to the right four characters"
	local scrolled_msg="ll this log message to the right four characters"

	echo "mod alpha" > $testroot/repo/alpha
	cd $testroot/repo && git add . && git commit -m "$msg" > /dev/null

	local commit1=`git_show_head $testroot/repo`

	cat <<EOF >$testroot/log_scroll_right
l		scroll right
l		scroll right
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
commit $commit1 [1/2] master
$ymd flan_hacker  $scrolled_msg
$ymd flan_hacker  ng the test tree
EOF

	cd $testroot/repo && tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_log_hsplit_ref()
{
	test_init log_hsplit_ref 80 10

	local head_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local date=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	local ymd=`date -u -r $author_time +"%G-%m-%d"`

	cat <<EOF >$testroot/log_hsplit_ref
R		open ref view
S		toggle horizontal split
-		reduce size of ref view split
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
commit $head_id [1/1] master
$ymd flan_hacker  adding the test tree

--------------------------------------------------------------------------------
references [1/2]
HEAD -> refs/heads/master
refs/heads/master



EOF

	cd $testroot/repo && tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_log_hsplit_tree()
{
	test_init log_hsplit_tree 80 10

	local head_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local date=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	local ymd=`date -u -r $author_time +"%G-%m-%d"`

	cat <<EOF >$testroot/log_hsplit_tree
T		open tree view
S		toggle horizontal split
j		move selection cursor down one entry to "beta"
-		reduce size of tree view split
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
commit $head_id [1/1] master
$ymd flan_hacker  adding the test tree

--------------------------------------------------------------------------------
commit $head_id
[2/4] /

  alpha
  beta
  epsilon/
EOF

	cd $testroot/repo && tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_log_logmsg_widechar()
{
	# make view wide enough to fit logmsg line length
	# but short enough so long diff lines are truncated
	test_init log_logmsg_widechar 182 30
	widechar_commit $testroot/repo

	local head_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local date=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	local commit1=`git_show_parent_commit $testroot/repo`
	local blobid=`get_blob_id $testroot/repo "" $(widechar_filename)`

	cat <<EOF >$testroot/log_logmsg_widechar
KEY_ENTER	open selected commit in diff view
F		toggle fullscreen
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
[1/26] diff $commit1 $head_id
commit $head_id (master)
from: Flan Hacker <flan_hacker@openbsd.org>
date: $date

$(widechar_logmsg)

A  $(widechar_filename)  |  5+  0-

1 file changed, 5 insertions(+), 0 deletions(-)

commit - $commit1
commit + $head_id
blob - /dev/null
blob + $blobid (mode 644)
--- /dev/null
+++ $(widechar_filename)
@@ -0,0 +1,5 @@
+ウィリアム・ユワート・グラッドストン（英語: William Ewart Gladstone PC FRS FSS、1809年12月29日 - 1898年5月19日）は、イギリスの政治家。
+
+ヴィクトリア朝中期から後期にかけて、自由党を指導して、4度にわたり首相を務めた。
+
+生涯を通じて敬虔なイングランド国教会の信徒であり、キリスト教の精神を政治に反映させることを目指した。多くの自由主義改革を行い、帝国主義にも批判的であった。好敵手である保守党党首ベン



(END)
EOF

	cd $testroot/repo && tog log
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
run_test test_log_hsplit_diff
run_test test_log_vsplit_diff
run_test test_log_show_author
run_test test_log_scroll_right
run_test test_log_hsplit_ref
run_test test_log_hsplit_tree
run_test test_log_logmsg_widechar
