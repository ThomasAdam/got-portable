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
	echo -n "tree " > $testroot/stdout.expected
	git_show_tree $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	echo "numparents 0" >> $testroot/stdout.expected
	echo "author $GOT_AUTHOR $author_time +0000" >> $testroot/stdout.expected
	echo "committer $GOT_AUTHOR $author_time +0000" \
		>> $testroot/stdout.expected
	echo "messagelen 22" >> $testroot/stdout.expected
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

function test_cat_path {
	local testroot=`test_init cat_path`
	local commit_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local alpha_id=`got tree -r $testroot/repo -i | grep 'alpha$' | cut -d' ' -f 1`
	local gamma_id=`got tree -r $testroot/repo -i | grep 'gamma/$' | cut -d' ' -f 1`
	local delta_id=`got tree -r $testroot/repo -i gamma | grep 'delta$' | cut -d' ' -f 1`

	# cat blob by path
	echo "alpha" > $testroot/stdout.expected
	got cat -r $testroot/repo alpha > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# cat tree by path
	echo "$delta_id 0100644 delta" > $testroot/stdout.expected
	got cat -r $testroot/repo gamma > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot && got checkout repo wt > /dev/null)
	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "changed alpha" > /dev/null)
	local commit_id2=`git_show_head $testroot/repo`
	local author_time2=`git_show_author_time $testroot/repo`
	local tree_commit2=`git_show_tree $testroot/repo`

	# cat blob by path in specific commit
	echo "alpha" > $testroot/stdout.expected
	got cat -r $testroot/repo -c $commit_id alpha > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	echo "modified alpha" > $testroot/stdout.expected
	got cat -r $testroot/repo -c $commit_id2 alpha > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# resolve ambiguities between paths and other arguments
	echo "new file called master" > $testroot/wt/master
	echo "new file called $commit_id2" > $testroot/wt/$commit_id2
	(cd $testroot/wt && got add master $commit_id2 > /dev/null)
	(cd $testroot/wt && got commit -m "added clashing paths" > /dev/null)
	local commit_id3=`git_show_head $testroot/repo`
	local author_time3=`git_show_author_time $testroot/repo`

	# references and object IDs override paths:
	echo -n "tree " > $testroot/stdout.expected
	git_show_tree $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	echo "numparents 1" >> $testroot/stdout.expected
	echo "parent $commit_id2" >> $testroot/stdout.expected
	echo "author $GOT_AUTHOR $author_time3 +0000" >> $testroot/stdout.expected
	echo "committer $GOT_AUTHOR $author_time3 +0000" \
		>> $testroot/stdout.expected
	echo "messagelen 22" >> $testroot/stdout.expected
	printf "\nadded clashing paths\n" >> $testroot/stdout.expected

	for arg in master $commit_id3; do
		got cat -r $testroot/repo $arg > $testroot/stdout
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret="$?"
		if [ "$ret" != "0" ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	echo "tree $tree_commit2" > $testroot/stdout.expected
	echo "numparents 1" >> $testroot/stdout.expected
	echo "parent $commit_id" >> $testroot/stdout.expected
	echo "author $GOT_AUTHOR $author_time2 +0000" >> $testroot/stdout.expected
	echo "committer $GOT_AUTHOR $author_time2 +0000" \
		>> $testroot/stdout.expected
	echo "messagelen 15" >> $testroot/stdout.expected
	printf "\nchanged alpha\n" >> $testroot/stdout.expected

	got cat -r $testroot/repo $commit_id2 > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# force resolution of path 'master'
	echo "new file called master" > $testroot/stdout.expected
	got cat -r $testroot/repo -P master > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# force resolution of path "$commit_id2"
	echo "new file called $commit_id2" > $testroot/stdout.expected
	got cat -r $testroot/repo -P $commit_id2 > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	test_done "$testroot" "$ret"
}

run_test test_cat_basic
run_test test_cat_path
