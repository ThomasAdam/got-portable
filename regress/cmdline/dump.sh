#!/bin/sh
#
# Copyright (c) 2023 Omar Polo <op@openbsd.org>
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

test_dump_bundle() {
	local testroot=`test_init test_dump_bundle`

	# add a fake reference so that `got log' appears the same in
	# the cloned repository
	(cd "$testroot/repo" && got branch -n origin/master)

	(cd "$testroot/repo" && got log -p >$testroot/repo.log)

	(cd "$testroot/repo" && gotadmin dump -q master >$testroot/r.bundle)
	if [ $? -ne 0 ]; then
		echo "gotadmin dump failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	if ! (cd "$testroot" && git clone -b master -q r.bundle); then
		echo "failed to git clone from the generated bundle" >&2
		test_done "$testroot" 1
		return 1
	fi

	if ! (cd "$testroot/r" && got log -p >$testroot/r.log); then
		echo "got log failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	if ! cmp -s "$testroot/repo.log" "$testroot/r.log"; then
		echo "history differs after clone" >&2
		diff -u "$testroot/repo.log" "$testroot/r.log"
		test_done "$testroot" 1
		return 1
	fi

	(cd "$testroot/repo" && git checkout -q -b newbranch)

	# commit some changes in the repo
	for i in `seq 5`; do
		echo "alpha edit #$i" > $testroot/repo/alpha
		git_commit "$testroot/repo" -m "edit alpha"
	done

	(cd "$testroot/repo" && \
	    gotadmin dump -q -x master newbranch >$testroot/r.bundle)
	if [ $? -ne 0 ]; then
		echo "gotadmin dump failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	(cd "$testroot/r" && git checkout -q -b newbranch && \
	    git pull -q "$testroot/r.bundle" newbranch)
	if [ $? -ne 0 ]; then
		echo "git pull failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	(cd "$testroot/repo" && got log -p >$testroot/repo.log)

	if ! (cd "$testroot/r" && got log -p >$testroot/r.log); then
		echo "got log failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	if ! cmp -s "$testroot/repo.log" "$testroot/r.log"; then
		echo "history differs after pull" >&2
		diff -u "$testroot/repo.log" "$testroot/r.log"
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" 0
}

test_parseargs "$@"
run_test test_dump_bundle
