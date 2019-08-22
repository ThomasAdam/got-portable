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

function test_cat_basic {
	local testroot=`test_init cat_basic`
	local commit_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local alpha_id=`got tree -r $testroot/repo -i | grep 'alpha$' | cut -d' ' -f 1`
	local gamma_id=`got tree -r $testroot/repo -i | grep 'gamma/$' | cut -d' ' -f 1`
	local delta_id=`got tree -r $testroot/repo -i gamma | grep 'delta$' | cut -d' ' -f 1`

	# cat blob
	echo "alpha" > $testroot/stdout.expected
	got cat -r $testroot/repo $alpha_id > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# cat tree
	echo "$delta_id 0100644 delta" > $testroot/stdout.expected
	got cat -r $testroot/repo $gamma_id > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# cat commit
	echo -n "tree: " > $testroot/stdout.expected
	git_show_tree $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	echo "parents: 0" >> $testroot/stdout.expected
	echo "author: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo "author-time: $author_time" >> $testroot/stdout.expected
	echo "committer: Flan Hacker <flan_hacker@openbsd.org>" >> $testroot/stdout.expected
	echo "committer-time: $author_time" >> $testroot/stdout.expected
	echo "log-message: 22 bytes" >> $testroot/stdout.expected
	printf "\nadding the test tree\n" >> $testroot/stdout.expected

	got cat -r $testroot/repo $commit_id > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# TODO: test cat tag

	test_done "$testroot" "$ret"
	
}

run_test test_cat_basic
