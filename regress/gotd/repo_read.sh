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

test_clone_basic() {
	local testroot=`test_init clone_basic 1`

	cp -r ${GOTD_TEST_REPO} $testroot/repo-copy

	got clone -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# Verify that the clone operation worked fine.
	git_fsck "$testroot" "$testroot/repo-clone"
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "1"
		return 1
	fi

	got tree -R -r "$testroot/repo-clone" > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
alpha
beta
epsilon/
epsilon/zeta
gamma/
gamma/delta
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# cloning a repository should not result in modifications
	diff -urN ${GOTD_TEST_REPO} $testroot/repo-copy \
		> $testroot/stdout
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_send_to_read_only_repo() {
	local testroot=`test_init send_to_read_only_repo 1`

	ls -R ${GOTD_TEST_REPO} > $testroot/repo-list.before

	got clone -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
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

	got send -q -r $testroot/repo-clone 2>$testroot/stderr.raw
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got send succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	grep -v ^gotsh: $testroot/stderr.raw > $testroot/stderr

	echo 'got-send-pack: test-repo: Permission denied' \
		> $testroot/stderr.expected
	echo 'got: could not send pack file' >> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_clone_basic
run_test test_send_to_read_only_repo
