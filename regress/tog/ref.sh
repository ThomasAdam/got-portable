#!/bin/sh
#
# Copyright (c) 2024 Mark Jamsek <mark@jamsek.dev>
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

test_ref_basic()
{
	test_init ref_basic 32 3

	cat <<-EOF >$TOG_TEST_SCRIPT
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	references [1/2]
	HEAD -> refs/heads/master
	refs/heads/master
	EOF

	cd $testroot/repo && tog ref
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_ref_id_keymap()
{
	test_init ref_id_keymap 83 3

	local id=$(git_show_head $testroot/repo)

	cat <<-EOF >$TOG_TEST_SCRIPT
	i		# toggle IDs
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	references [1/2]
	HEAD -> refs/heads/master
	refs/heads/master: $id
	EOF

	cd $testroot/repo && tog ref
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_ref_date_keymap()
{
	test_init ref_date_keymap 40 3

	local author_time=$(git_show_author_time $testroot/repo)
	local date=$(date -u -r $author_time +"%a %b %e %X %Y UTC")
	local ymd=$(date -u -r $author_time +"%F")

	cat <<-EOF >$TOG_TEST_SCRIPT
	m		# toggle last modified date
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	references [1/2]
	$ymd  HEAD -> refs/heads/master
	$ymd  refs/heads/master
	EOF

	cd $testroot/repo && tog ref
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_ref_id_date_keymaps()
{
	test_init ref_id_date_keymaps 95 3

	local author_time=$(git_show_author_time $testroot/repo)
	local date=$(date -u -r $author_time +"%a %b %e %X %Y UTC")
	local ymd=$(date -u -r $author_time +"%F")
	local id=$(git_show_head $testroot/repo)

	cat <<-EOF >$TOG_TEST_SCRIPT
	i		# toggle IDs
	m		# toggle last modified date
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	references [1/2]
	$ymd  HEAD -> refs/heads/master
	$ymd  refs/heads/master: $id
	EOF

	cd $testroot/repo && tog ref
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_ref_nested_tag_to_commit()
{
	test_init ref_nested_tag_to_commit 142 5

	local author_time=$(git_show_author_time $testroot/repo)
	local date=$(date -u -r $author_time +"%a %b %e %X %Y UTC")
	local ymd=$(date -u -r $author_time +"%F")
	local id=$(git_show_head $testroot/repo)

	cd $testroot/repo

	git tag -a tagref -m "tag to commit" > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git tag failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	git tag -a nestedtag -m "nested tag" tagref > /dev/null 2>&1
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git tag failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<-EOF >$TOG_TEST_SCRIPT
	2j		# select nested tag ref
	KEY_ENTER	# open log view
	35+		# grow log view vsplit
	SCREENDUMP
	EOF

	cat <<EOF >$testroot/view.expected
references [3/4]          |commit $id  [1/1] master, tags/tagref
HEAD -> refs/heads/master |$ymd flan_hacker  [master, tags/tagref] adding the test tree
refs/heads/master         |
refs/tags/nestedtag       |
refs/tags/tagref          |
EOF

	cd $testroot/repo && tog ref
	cmp -s $testroot/view.expected $testroot/view
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/view.expected $testroot/view
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_ref_non_commit_tag()
{
	test_init ref_non_commit_tag 32 5

	local blobid_alpha=$(get_blob_id $testroot/repo "" alpha)

	cd $testroot/repo

	git tag blobtag $blobid_alpha > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git tag failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<-EOF >$TOG_TEST_SCRIPT
	2j		# select tag to blob entry
	KEY_ENTER
	SCREENDUMP
	EOF

	cat <<-EOF >$testroot/view.expected
	references [3/3]
	HEAD -> refs/heads/master
	refs/heads/master
	refs/tags/blobtag
	:commit reference required
	EOF

	cd $testroot/repo && tog ref
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
run_test test_ref_basic
run_test test_ref_id_keymap
run_test test_ref_date_keymap
run_test test_ref_id_date_keymaps
run_test test_ref_nested_tag_to_commit
run_test test_ref_non_commit_tag
