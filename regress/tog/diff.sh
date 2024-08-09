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
	local head_id_truncated=`trim_obj_id 27 $head_id`
	local alpha_id=`get_blob_id $testroot/repo "" alpha`

	cat <<EOF >$TOG_TEST_SCRIPT
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
$(trim 80 "[1/20] diff $commit_id1 $head_id_truncated")
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
	local head_id_truncated=`trim_obj_id 27 $head_id`
	local alpha_id=`get_blob_id $testroot/repo "" alpha`
	local new_id=`get_blob_id $testroot/repo "" new`

	cat <<EOF >$TOG_TEST_SCRIPT
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
$(trim 80 "[1/16] diff $commit_id1 $head_id_truncated")
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
$(trim 80 "blob + $new_id (mode 644)")
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

test_diff_J_keymap()
{
	test_init diff_J_keymap 94 24

	local i=0

	cd $testroot/repo

	while [ "$i" -lt 32 ]; do
		echo $i > alpha
		git commit -aqm $i
		# Get timestamp, and blob and commit IDs
		# of the diff views to be screendumped.
		if [ $i -eq 6 ]; then
			local id6=$(git_show_head .)
			local blobid6=$(get_blob_id . "" alpha)
		elif [ $i -eq 7 ]; then
			local id7=$(git_show_head .)
			local blobid7=$(get_blob_id . "" alpha)
			local author_time7=$(git_show_author_time .)
		elif [ $i -eq 25 ]; then
			local id25=$(git_show_head .)
			local blobid25=$(get_blob_id . "" alpha)
		elif [ $i -eq 26 ]; then
			local id26=$(git_show_head .)
			local blobid26=$(get_blob_id . "" alpha)
			local author_time26=$(git_show_author_time .)
		fi
		i=$(( i + 1 ))
	done

	local date7=`date -u -r $author_time7 +"%a %b %e %X %Y UTC"`
	local date26=`date -u -r $author_time26 +"%a %b %e %X %Y UTC"`

	# Test that J loads the diff view of the next commit when
	# currently viewing the last commit loaded in the log view.

	cat <<EOF >$TOG_TEST_SCRIPT
KEY_ENTER	open diff view of selected commit
S		toggle horizontal split
TAB		tab back to log view
23j		move to last loaded commit
KEY_ENTER	select last loaded commit
F		toggle fullscreen
J		move down to next commit in the log
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
$(trim 94 "[1/20] diff $id6 $id7")
commit $id7
from: Flan Hacker <flan_hacker@openbsd.org>
date: $date7

7

M  alpha  |  1+  1-

1 file changed, 1 insertion(+), 1 deletion(-)

commit - $id6
commit + $id7
blob - $blobid6
blob + $blobid7
--- alpha
+++ alpha
@@ -1 +1 @@
-6
+7



(END)
EOF

	tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	# Test that J loads the diff view of the next commit when currently
	# viewing the last visible commit in the horizontally split log view.

	cat <<EOF >$TOG_TEST_SCRIPT
S		toggle horizontal split
4j		move to last visible commit when in horizontal split
KEY_ENTER	open diff view of selected commit
F		toggle fullscreen
J		move down to next commit in the log
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
$(trim 94 "[1/20] diff $id25 $id26")
commit $id26
from: Flan Hacker <flan_hacker@openbsd.org>
date: $date26

26

M  alpha  |  1+  1-

1 file changed, 1 insertion(+), 1 deletion(-)

commit - $id25
commit + $id26
blob - $blobid25
blob + $blobid26
--- alpha
+++ alpha
@@ -1 +1 @@
-25
+26



(END)
EOF

	tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	# Test J correctly requests the log to load more commits when
	# scrolling beyond the last loaded commit from the diff view.

	cat <<EOF >$TOG_TEST_SCRIPT
S		toggle horizontal split
4j		move to the 5th commit
KEY_ENTER	open diff view of selected commit
F		toggle fullscreen
20J		scroll down and load diff of the 25th commit
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
$(trim 94 "[1/20] diff $id6 $id7")
commit $id7
from: Flan Hacker <flan_hacker@openbsd.org>
date: $date7

7

M  alpha  |  1+  1-

1 file changed, 1 insertion(+), 1 deletion(-)

commit - $id6
commit + $id7
blob - $blobid6
blob + $blobid7
--- alpha
+++ alpha
@@ -1 +1 @@
-6
+7



(END)
EOF

	tog log
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_diff_commit_keywords()
{
	test_init diff_commit_keywords 120 24
	local repo="$testroot/repo"
	local wt="$testroot/wt"
	local id=$(git_show_head "$repo")
	local author_time=$(git_show_author_time "$repo")
	local ids="$id"
	local alpha_ids="$(get_blob_id "$repo" "" alpha)"

	set -- "$author_time"

	got checkout "$repo" "$wt" > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# move into the work tree (test is run in a subshell)
	cd "$wt"

	for i in $(seq 8); do
		echo "alpha $i" > alpha

		got ci -m "commit $i" > /dev/null
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "commit failed unexpectedly" >&2
			test_done "$testroot" "$ret"
			return 1
		fi

		id=$(git_show_head "$repo")
		ids="$ids $id"
		alpha_ids="$alpha_ids $(get_blob_id "$repo" "" alpha)"
		set -- "$@" $(git_show_author_time "$repo")
	done

	cat <<-EOF >$TOG_TEST_SCRIPT
	SCREENDUMP
	EOF

	# diff consecutive commits with keywords
	local lhs_id=$(pop_idx 1 $ids)
	local rhs_id=$(pop_idx 2 $ids)
	local date=$(date -u -r $(pop_idx 2 $@) +"%a %b %e %X %Y UTC")

	cat <<-EOF >$testroot/view.expected
	$(trim 120 "[1/20] diff $lhs_id $rhs_id")
	commit $rhs_id
	from: Flan Hacker <flan_hacker@openbsd.org>
	date: $date

	commit 1

	M  alpha  |  1+  1-

	1 file changed, 1 insertion(+), 1 deletion(-)

	commit - $lhs_id
	commit + $rhs_id
	blob - $(pop_idx 1 $alpha_ids)
	blob + $(pop_idx 2 $alpha_ids)
	--- alpha
	+++ alpha
	@@ -1 +1 @@
	-alpha
	+alpha 1



	(END)
	EOF

	tog diff :base:-99 :head:-7
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
		test_done "$testroot" "$ret"
		return 1
	fi

	# diff arbitrary commits with keywords
	lhs_id=$(pop_idx 5 $ids)
	rhs_id=$(pop_idx 8 $ids)

	cat <<-EOF >$testroot/view.expected
	$(trim 120 "[1/10] diff $lhs_id $rhs_id")
	commit - $lhs_id
	commit + $rhs_id
	blob - $(pop_idx 5 $alpha_ids)
	blob + $(pop_idx 8 $alpha_ids)
	--- alpha
	+++ alpha
	@@ -1 +1 @@
	-alpha 4
	+alpha 7













	(END)
	EOF

	tog diff master:-4 :head:-
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
		test_done "$testroot" "$ret"
		return 1
	fi

	# diff consecutive commits using keywords with -r repository
	lhs_id=$(pop_idx 8 $ids)
	rhs_id=$(pop_idx 9 $ids)
	date=$(date -u -r $(pop_idx 9 $@) +"%a %b %e %X %Y UTC")

	cat <<-EOF >$testroot/view.expected
	[1/20] diff $lhs_id refs/heads/master
	commit $rhs_id (master)
	from: Flan Hacker <flan_hacker@openbsd.org>
	date: $date

	commit 8

	M  alpha  |  1+  1-

	1 file changed, 1 insertion(+), 1 deletion(-)

	commit - $lhs_id
	commit + $rhs_id
	blob - $(pop_idx 8 $alpha_ids)
	blob + $(pop_idx 9 $alpha_ids)
	--- alpha
	+++ alpha
	@@ -1 +1 @@
	-alpha 7
	+alpha 8



	(END)
	EOF

	tog diff -r "$repo" :head:- master
	cmp -s "$testroot/view.expected" "$testroot/view"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/view.expected" "$testroot/view"
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_diff_horizontal_scroll()
{
	test_init diff_horizontal_scroll

	local commit_id1=`git_show_head $testroot/repo`
	local alpha_id_old=`get_blob_id $testroot/repo "" alpha`

	{
		echo -n "01234567890123456789012345678901234567890123456789"
		echo "0123456789012345678901234567890123"
	} >> $testroot/repo/alpha

	git_commit $testroot/repo -m "scroll"
	local author_time=`git_show_author_time $testroot/repo`
	local date=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	local head_id=`git_show_head $testroot/repo`
	local head_id_truncated=`trim_obj_id 27 $head_id`
	local alpha_id=`get_blob_id $testroot/repo "" alpha`

	cat <<EOF >$TOG_TEST_SCRIPT
3l
SCREENDUMP
EOF

	cat <<EOF >$testroot/view.expected
$(trim 80 "[1/20] diff $commit_id1 $head_id_truncated")
 $head_id (master)
Flan Hacker <flan_hacker@openbsd.org>
$date



ha  |  1+  0-

 changed, 1 insertion(+), 0 deletions(-)

 - $commit_id1
 + $head_id
 $alpha_id_old
 $alpha_id
pha
pha
+1,2 @@

5678901234567890123456789012345678901234567890123456789012345678901234567890123



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
run_test test_diff_J_keymap
run_test test_diff_commit_keywords
run_test test_diff_horizontal_scroll
