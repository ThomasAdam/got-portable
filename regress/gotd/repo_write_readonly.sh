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

test_send_empty_readonly() {
	local testroot=`test_init send_empty`
	local commit_id=`git_show_head $testroot/repo`

	(cd ${GOTD_TEST_REPO} && find . > $testroot/repo-list.before)

	# The gotd-controlled test repository starts out empty.
	got ref -l -r ${GOTD_TEST_REPO} > $testroot/ref-list.before
	echo "HEAD: refs/heads/main" > $testroot/ref-list.expected
	cmp -s $testroot/ref-list.expected $testroot/ref-list.before
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/ref-list.expected $testroot/ref-list.before
		test_done "$testroot" "$ret"
		return 1
	fi

	got checkout -q $testroot/repo $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# send contents of $testroot/repo to ${GOTD_TEST_REPO}
	cat >> $testroot/wt/.got/got.conf <<EOF
remote "gotd" {
	server ${GOTD_DEVUSER}@127.0.0.1
	repository "test-repo"
	protocol ssh
}
EOF
	(cd $testroot/wt && got send -q -a gotd 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Verify that the send operation failed.
	# The error returned will differ depending on whether read access
	# is denied explicitly for GOTD_DEVUSER.
	if grep -q "permit.*${GOTD_DEVUSER}$" $GOTD_CONF; then
		echo "got-send-pack: test-repo: Permission denied" \
			> $testroot/stderr.expected
	else
		echo 'got-send-pack: no git repository found' \
			> $testroot/stderr.expected
	fi
	grep '^got-send-pack:' $testroot/stderr > $testroot/stderr.filtered
	cmp -s $testroot/stderr.expected $testroot/stderr.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	# Server should not have created a new reference.
	got ref -l -r ${GOTD_TEST_REPO} > $testroot/ref-list.after
	echo "HEAD: refs/heads/main" > $testroot/ref-list.expected
	cmp -s $testroot/ref-list.expected $testroot/ref-list.after
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/ref-list.expected $testroot/ref-list.after
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_send_empty_readonly
