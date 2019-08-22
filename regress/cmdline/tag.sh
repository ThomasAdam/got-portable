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

function test_tag_create {
	local testroot=`test_init tag_create`
	local commit_id=`git_show_head $testroot/repo`
	local tag=1.0.0
	local tag2=2.0.0

	# Create a tag based on repository's HEAD reference
	got tag -m 'test' -r $testroot/repo $tag HEAD > $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got ref command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`
	echo "Created tag $tag_id" > $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure that Git recognizes the tag Got has created
	(cd $testroot/repo && git checkout -q $tag)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "git checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure Got recognizes the new tag
	got checkout -c $tag $testroot/repo $testroot/wt >/dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Create a tag based on implied worktree HEAD ref
	(cd $testroot/wt && got tag -m 'test' $tag2 > $testroot/stdout)
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	tag_id2=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag2" | tr -d ' ' | cut -d: -f2`
	echo "Created tag $tag_id2" > $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git checkout -q $tag2)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "git checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
	fi

	# Attempt to create a tag pointing at a non-commit
	local tree_id=`git_show_tree $testroot/repo`
	(cd $testroot/wt && got tag -m 'test' foobar $tree_id \
		2> $testroot/stderr)
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "git tag command succeeded unexpectedly"
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: object not found" > $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -r $testroot/repo -l > $testroot/stdout
	echo "HEAD: $commit_id" > $testroot/stdout.expected
	echo -n "refs/got/worktree/base-" >> $testroot/stdout.expected
	cat $testroot/wt/.got/uuid | tr -d '\n' >> $testroot/stdout.expected
	echo ": $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/tags/$tag: $tag_id" >> $testroot/stdout.expected
	echo "refs/tags/$tag2: $tag_id2" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_tag_list {
	local testroot=`test_init tag_list`
	local commit_id=`git_show_head $testroot/repo`
	local tag=1.0.0
	local tag2=2.0.0

	(cd $testroot/repo && git tag -a -m 'test' $tag)
	(cd $testroot/repo && git tag -a -m 'test' $tag2)

	tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`
	local tagger_time=`git_show_tagger_time $testroot/repo $tag`
	d1=`env TZ=UTC date -r $tagger_time +"%a %b %d %X %Y UTC"`
	tag_id2=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag2" | tr -d ' ' | cut -d: -f2`
	local tagger_time2=`git_show_tagger_time $testroot/repo $tag2`
	d2=`env TZ=UTC date -r $tagger_time2 +"%a %b %d %X %Y UTC"`

	got tag -r $testroot/repo -l > $testroot/stdout

	echo "-----------------------------------------------" \
		> $testroot/stdout.expected
	echo "tag $tag $tag_id" >> $testroot/stdout.expected
	echo "commit $commit_id" >> $testroot/stdout.expected
	echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo "date: $d1" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo " test" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo "-----------------------------------------------" \
		>> $testroot/stdout.expected
	echo "tag $tag2 $tag_id2" >> $testroot/stdout.expected
	echo "commit $commit_id" >> $testroot/stdout.expected
	echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo "date: $d2" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo " test" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

run_test test_tag_create
run_test test_tag_list
