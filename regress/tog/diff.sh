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

test_diff_contiguous_commits()
{
	test_init diff_contiguous_commits

	local commit_id1=`git_show_head $testroot/repo`
	local alpha_id_old=`get_blob_id $testroot/repo "" alpha`

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "changed alpha"
	local author_time=`git_show_author_time $testroot/repo`
	local date=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	local head_id=`git_show_head $testroot/repo`
	local head_id_truncated=`trim_obj_id 13 $head_id`
	local alpha_id=`get_blob_id $testroot/repo "" alpha`

	cat <<EOF >$TOG_TEST_SCRIPT
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
[1/20] diff $commit_id1 $head_id_truncated
commit $head_id (master)
from: Flan Hacker <flan_hacker@openbsd.org>
date: $date

changed alpha

M  alpha  |  1+  1-

1 file changed, 1 insertion(+), 1 deletion(-)

commit - $commit_id1
commit + $head_id
blob - $alpha_id_old
blob + $alpha_id
--- alpha
+++ alpha
@@ -1 +1 @@
-alpha
+modified alpha



(END)
EOF

	cd $testroot/repo && tog diff $commit_id1 $head_id
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_diff_arbitrary_commits()
{
	test_init diff_arbitrary_commits 80 18

	local commit_id1=`git_show_head $testroot/repo`
	local alpha_id_old=`get_blob_id $testroot/repo "" alpha`

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "changed alpha"
	local commit_id2=`git_show_head $testroot/repo`

	echo "modified alpha again" > $testroot/repo/alpha
	echo "new file" > $testroot/repo/new
	(cd $testroot/repo && git add new)
	git_commit $testroot/repo -m "new file"
	local head_id=`git_show_head $testroot/repo`
	local head_id_truncated=`trim_obj_id 13 $head_id`
	local alpha_id=`get_blob_id $testroot/repo "" alpha`
	local new_id=`get_blob_id $testroot/repo "" new`

	cat <<EOF >$TOG_TEST_SCRIPT
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
[1/16] diff $commit_id1 $head_id_truncated
commit - $commit_id1
commit + $head_id
blob - $alpha_id_old
blob + $alpha_id
--- alpha
+++ alpha
@@ -1 +1 @@
-alpha
+modified alpha again
blob - /dev/null
blob + $new_id (mode 644)
--- /dev/null
+++ new
@@ -0,0 +1 @@
+new file

(END)
EOF

	cd $testroot/repo && tog diff $commit_id1 $head_id
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
run_test test_diff_contiguous_commits
run_test test_diff_arbitrary_commits
