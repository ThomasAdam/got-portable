#!/bin/sh
#
# Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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

test_send_basic() {
	local testroot=`test_init send_basic 1`

	ls -R ${GOTD_TEST_REPO} > $testroot/repo-list.before

	got clone -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# create a second clone to test an incremental fetch with later
	got clone -q -m ${GOTD_TEST_REPO_URL} $testroot/repo-clone2
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	mkdir $testroot/wt/psi
	echo "new" > $testroot/wt/psi/new
	(cd $testroot/wt && got add psi/new > /dev/null)
	echo "more alpha" >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'make changes' > /dev/null)

	got send -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# Verify that the send operation worked fine.
	got fetch -q -r $testroot/repo-clone2
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got fetch failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	got tree -R -r $testroot/repo-clone2 > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
alpha
beta
epsilon/
epsilon/zeta
gamma/
gamma/delta
psi/
psi/new
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# sending to a repository should result in a new pack file
	ls -R ${GOTD_TEST_REPO} > $testroot/repo-list.after
	diff -u $testroot/repo-list.before $testroot/repo-list.after \
		> $testroot/repo-list.diff
	grep '^+[^+]' < $testroot/repo-list.diff > $testroot/repo-list.newlines
	nplus=`wc -l < $testroot/repo-list.newlines | tr -d ' '`
	if [ "$nplus" != "2" ]; then
		echo "$nplus new files created"
		test_done "$testroot" "$ret"
		return 1
	fi
	egrep -q '\+pack-[a-f0-9]{40}.pack' $testroot/repo-list.newlines
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "new pack file not found in ${GOTD_TEST_REPO}"
		cat $testroot/repo-list.newlines
		test_done "$testroot" "$ret"
		return 1
	fi
	egrep -q '\+pack-[a-f0-9]{40}.idx' $testroot/repo-list.newlines
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "new pack index not found in ${GOTD_TEST_REPO}"
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_send_basic
