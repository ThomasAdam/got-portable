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

function test_ref_create {
	local testroot=`test_init ref_create`
	local commit_id=`git_show_head $testroot/repo`

	# Create a head ref based on repository's HEAD reference
	got ref -r $testroot/repo refs/heads/newref HEAD
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got ref command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure that Git recognizes the ref Got has created
	(cd $testroot/repo && git checkout -q newref)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "git checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure Got recognizes the new ref
	got checkout -b newref $testroot/repo $testroot/wt >/dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Create a head ref based on another specific ref
	(cd $testroot/wt && got ref refs/heads/anotherref refs/heads/master)
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git checkout -q anotherref)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "git checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
	fi

	# Create a symbolic ref
	(cd $testroot/wt && got ref -s refs/heads/symbolicref refs/heads/master)
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git checkout -q symbolicref)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "git checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Attempt to create a symbolic ref pointing at a non-reference
	(cd $testroot/wt && got ref -s refs/heads/symbolicref $commit_id \
		2> $testroot/stderr)
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "git ref command succeeded unexpectedly"
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: reference $commit_id not found" > $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -r $testroot/repo -l > $testroot/stdout
	echo "HEAD: refs/heads/symbolicref" > $testroot/stdout.expected
	echo -n "refs/got/worktree/base-" >> $testroot/stdout.expected
	cat $testroot/wt/.got/uuid | tr -d '\n' >> $testroot/stdout.expected
	echo ": $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/anotherref: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/newref: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/symbolicref: refs/heads/master" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_ref_delete {
	local testroot=`test_init ref_delete`
	local commit_id=`git_show_head $testroot/repo`

	for b in ref1 ref2 ref3; do
		got ref -r $testroot/repo refs/heads/$b refs/heads/master
		ret="$?"
		if [ "$ret" != "0" ]; then
			echo "got ref command failed unexpectedly"
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	got ref -d refs/heads/ref2 -r $testroot/repo > $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got ref command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo > $testroot/stdout
	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/ref1: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/ref3: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -d refs/heads/bogus_ref_name -r $testroot/repo \
		> $testroot/stdout 2> $testroot/stderr
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "got ref succeeded unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: reference refs/heads/bogus_ref_name not found" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

run_test test_ref_create
run_test test_ref_delete
