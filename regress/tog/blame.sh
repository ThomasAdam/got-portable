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

test_blame_commit_keywords()
{
	test_init blame_commit_keywords 80 10
	local repo="$testroot/repo"
	local wt="$testroot/wt"
	local id=$(git_show_head "$repo")
	local author_time=$(git_show_author_time "$repo")
	local ymd=$(date -u -r $author_time +"%G-%m-%d")

	set -- "$id"

	cat <<-EOF >$TOG_TEST_SCRIPT
	WAIT_FOR_UI	wait for blame to finish
	SCREENDUMP
	EOF

	# :base requires work tree
	echo "tog: '-c :base' requires work tree" > "$testroot/stderr.expected"
	tog blame -r "$repo" -c:base alpha 2> "$testroot/stderr"
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "blame command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s "$testroot/stderr.expected" "$testroot/stderr"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/stderr.expected" "$testroot/stderr"
		test_done "$testroot" "$ret"
		return 1
	fi

	# :head keyword in repo
	cat <<-EOF >$testroot/view.expected
	commit $id
	[1/1] /alpha
	$(trim_obj_id 32 $(pop_idx 1 $@)) alpha







	EOF

	tog blame -r "$repo" -c:head alpha
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "blame command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	got checkout "$repo" "$wt" > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# move into the work tree (test is run in a subshell)
	cd "$wt"
	echo -n > alpha

	for i in $(seq 8); do
		echo "alpha $i" >> alpha

		got ci -m "commit $i" > /dev/null
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "commit failed unexpectedly" >&2
			test_done "$testroot" "$ret"
			return 1
		fi

		id=$(git_show_head "$repo")
		set -- "$@" "$id"
	done

	author_time=$(git_show_author_time "$repo")
	ymd=$(date -u -r $author_time +"%G-%m-%d")

	# :base:- keyword in work tree
	cat <<-EOF >$testroot/view.expected
	commit $(pop_idx 8 $@)
	[1/7] /alpha
	$(trim_obj_id 32 $(pop_idx 2 $@)) alpha 1
	$(trim_obj_id 32 $(pop_idx 3 $@)) alpha 2
	$(trim_obj_id 32 $(pop_idx 4 $@)) alpha 3
	$(trim_obj_id 32 $(pop_idx 5 $@)) alpha 4
	$(trim_obj_id 32 $(pop_idx 6 $@)) alpha 5
	$(trim_obj_id 32 $(pop_idx 7 $@)) alpha 6
	$(trim_obj_id 32 $(pop_idx 8 $@)) alpha 7

	EOF

	tog blame -c:base:- alpha
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "blame command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	# :head:-4 keyword in work tree
	cat <<-EOF >$testroot/view.expected
	commit $(pop_idx 5 $@)
	[1/4] /alpha
	$(trim_obj_id 32 $(pop_idx 2 $@)) alpha 1
	$(trim_obj_id 32 $(pop_idx 3 $@)) alpha 2
	$(trim_obj_id 32 $(pop_idx 4 $@)) alpha 3
	$(trim_obj_id 32 $(pop_idx 5 $@)) alpha 4




	EOF

	tog blame -c:head:-4 alpha
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "blame command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	# :base:+2 keyword in work tree
	cat <<-EOF >$testroot/view.expected
	commit $(pop_idx 5 $@)
	[1/4] /alpha
	$(trim_obj_id 32 $(pop_idx 2 $@)) alpha 1
	$(trim_obj_id 32 $(pop_idx 3 $@)) alpha 2
	$(trim_obj_id 32 $(pop_idx 4 $@)) alpha 3
	$(trim_obj_id 32 $(pop_idx 5 $@)) alpha 4




	EOF

	got up -c:head:-6 > /dev/null
	if [ $ret -ne 0 ]; then
		echo "update command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	tog blame -c:base:+2 alpha
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "blame command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	# master:-99 keyword in work tree
	cat <<-EOF >$testroot/view.expected
	commit $(pop_idx 1 $@)
	[1/1] /alpha
	$(trim_obj_id 32 $(pop_idx 1 $@)) alpha







	EOF

	tog blame -cmaster:-99 alpha
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "blame command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

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
run_test test_blame_commit_keywords
