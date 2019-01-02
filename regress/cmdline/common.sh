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

function git_init
{
	git init -q "$@"
}

function git_commit
{
	local repo="$1"
	shift
	(cd $repo && git commit -q -a "$@")
}

function make_test_tree
{
	repo="$1"

	echo alpha > $repo/alpha
	echo beta > $repo/beta
	mkdir $repo/gamma
	echo delta > $repo/gamma/delta
	mkdir $repo/epsilon
	echo zeta > $repo/epsilon/zeta
	(cd $repo && git add .)
}

function test_init
{
	local testname="$1"
	if [ -z "$testname" ]; then
		echo "No test name provided" >&2
		return 1
	fi
	local testroot=`mktemp -p /tmp -d got-test-$testname-XXXXXXXX`
	mkdir $testroot/repo
	git_init $testroot/repo
	make_test_tree $testroot/repo
	git_commit $testroot/repo -m "adding the test tree"
	echo "$testroot"
}

function test_cleanup
{
	local testroot="$1"
	rm -rf "$testroot"
}

function run_test
{
	testfunc="$1"
	echo "$testfunc"
	$testfunc
}

function test_done
{
	local testroot="$1"
	local result="$2"
	if [ "$result" == "0" ]; then
		test_cleanup "$testroot"
	else
		echo "test failed; leaving test data in $testroot"
	fi
}
