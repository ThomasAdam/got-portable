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

function test_rm_basic {
	local testroot=`test_init rm_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'D  beta' > $testroot/stdout.expected
	(cd $testroot/wt && got rm beta > $testroot/stdout)

	cmp $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	if [ -e $testroot/wt/beta ]; then
		echo "removed file beta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "$ret"
}

function test_rm_with_local_mods {
	local testroot=`test_init rm_with_local_mods`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified beta" > $testroot/wt/beta
	echo 'got: file contains modifications' > $testroot/stderr.expected
	(cd $testroot/wt && got rm beta 2>$testroot/stderr)

	cmp $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'D  beta' > $testroot/stdout.expected
	(cd $testroot/wt && got rm -f beta > $testroot/stdout)

	cmp $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	if [ -e $testroot/wt/beta ]; then
		echo "removed file beta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "$ret"
}

function test_double_rm {
	local testroot=`test_init double_rm`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rm beta > /dev/null)

	for fflag in "" "-f"; do
		(cd $testroot/wt && got rm $fflag beta 2> $testroot/stderr)
		ret="$?"
		if [ "$ret" == "0" ]; then
			echo "got rm command succeeded unexpectedly" >&2
			test_done "$testroot" 1
		fi

		grep "No such file or directory" $testroot/stderr > \
			$testroot/stderr.actual
		ret="$?"
		if [ "$ret" != "0" ]; then
			cat $testroot/stderr
			test_done "$testroot" "$ret"
		fi
	done
	test_done "$testroot" "0"
}

run_test test_rm_basic
run_test test_rm_with_local_mods
run_test test_double_rm
