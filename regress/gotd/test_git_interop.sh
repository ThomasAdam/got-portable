#!/bin/sh
#
# Copyright (c) 2024 Stefan Sperling <stsp@openbsd.org>
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

. ../cmdline/common.sh
. ./common.sh

test_fetch_with_git_history_walk() {
	local testroot=`test_init fetch_with_git_history_walk 1`

	git clone -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git clone failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# Create new commits on a branch which doesn't exist in gotd repo.
	# We want Git to send a flush-pkt followed by more have-lines. This
	# requires at least 16 commits (fetch-pack.c:INITIAL_FLUSH 16).
	git -C $testroot/repo-clone branch newbranch
	for i in `seq 24`; do
		echo $i >> $testroot/repo-clone/file$i
		git -C $testroot/repo-clone add file$i
		git_commit $testroot/repo-clone -m "add file$i"
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "git commit failed unexpectedly" >&2
			test_done "$testroot" "1"
			return 1
		fi
	done

	git clone -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone2 \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git clone failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# create new commits on main branch, and push to gotd
	for i in `seq 2`; do
		echo $i >> $testroot/repo-clone2/file$i
		git -C $testroot/repo-clone2 add file$i
		git_commit $testroot/repo-clone2 -m "add file$i"
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "git commit failed unexpectedly" >&2
			test_done "$testroot" "1"
			return 1
		fi
	done

	git -C $testroot/repo-clone2 push -q origin main
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git push failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# Fetching changes into the first repository clone should work.
	# This used to fail because gotd rejected additional have-lines
	# once Git had sent a flush-pkt.
	git -C $testroot/repo-clone fetch -q 2> $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git fetch failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

run_test test_fetch_with_git_history_walk
