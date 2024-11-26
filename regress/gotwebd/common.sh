#!/bin/sh
#
# Copyright (c) 2019, 2020 Stefan Sperling <stsp@openbsd.org>
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

. ${GOTWEBD_TEST_DATA_DIR}/../cmdline/common.sh

interpolate()
{
	perl -p -e \
	    's/\$\{(\w+)\}/(exists $ENV{$1} ? $ENV{$1} : "UNDEFINED $1")/eg' \
	    < "$1"
}

test_cleanup()
{
	local testroot="$1"
	local repo="$2"

	if [ -n "$repo" ]; then
		git_fsck $testroot $repo
		ret=$?
		if [ $ret -ne 0 ]; then
			return $ret
		fi
	fi

	rm -rf "$testroot"
}

test_done()
{
	local testroot="$1"
	local repo="$2"
	local result="$3"

	if [ "$result" = "0" ]; then
		test_cleanup "$testroot" "$repo" || return 1
		if [ -z "$GOT_TEST_QUIET" ]; then
			echo "ok"
		fi
	elif echo "$result" | grep -q "^xfail"; then
		# expected test failure; test reproduces an unfixed bug
		echo "$result"
		test_cleanup "$testroot" "$repo" || return 1
	else
		echo "test failed; leaving test data in $testroot"
	fi
}

test_init()
{
	local testname="$1"
	local no_repo="$2"

	if [ -z "$testname" ]; then
		echo "No test name provided" >&2
		return 1
	fi

	local testroot=$(mktemp -d \
	    "$GOTWEBD_TEST_ROOT/gotwebd-test-$testname-XXXXXXXXXX")

	if [ -z "$no_repo" ]; then
		mkdir $testroot/repo
		git_init $testroot/repo
		make_test_tree $testroot/repo
		git -C $repo add .
		git_commit $testroot/repo -m "adding the test tree"
	fi

	echo "$testroot"
}

run_test()
{
	testfunc="$1"

	if [ -n "$regress_run_only" ]; then
		case "$regress_run_only" in
		*$testfunc*) ;;
		*) return ;;
		esac
	fi

	if [ -z "$GOT_TEST_QUIET" ]; then
		echo -n "$testfunc "
	fi

	$testfunc
}
