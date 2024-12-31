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

test_parseargs "$@"
run_test test_ref_basic
run_test test_ref_id_keymap
run_test test_ref_date_keymap
run_test test_ref_id_date_keymaps
