#!/bin/sh
#
# Copyright (c) 2024 Omar Polo <op@openbsd.org>
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

# flan:password encoded in base64
AUTH="ZmxhbjpwYXNzd29yZA=="

test_file_changed() {
	local testroot=`test_init file_changed 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "change alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'make changes' > /dev/null)
	local commit_id=`git_show_head $testroot/repo-clone`
	local author_time=`git_show_author_time $testroot/repo-clone`

	timeout 5 ./http-server -a $AUTH -p $GOTD_TEST_HTTP_PORT \
		-s "$GOTD_TEST_HMAC_SECRET" > $testroot/stdout &

	sleep 1 # server starts up

	got send -b main -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for the http "server"

	touch "$testroot/stdout.expected"
	ed -s "$testroot/stdout.expected" <<-EOF
	a
	{"notifications":[{
		"type":"commit",
		"short":false,
		"repo":"test-repo",
		"authenticated_user":"${GOTD_DEVUSER}",
		"id":"$commit_id",
		"author":{
			"full":"$GOT_AUTHOR",
			"name":"$GIT_AUTHOR_NAME",
			"mail":"$GIT_AUTHOR_EMAIL",
			"user":"$GOT_AUTHOR_11"
		},
		"committer":{
			"full":"$GOT_AUTHOR",
			"name":"$GIT_AUTHOR_NAME",
			"mail":"$GIT_AUTHOR_EMAIL",
			"user":"$GOT_AUTHOR_11"
		},
		"date":$author_time,
		"short_message":"make changes",
		"message":"make changes\n",
		"diffstat":{
			"files":[{
				"action":"modified",
				"file":"alpha",
				"added":1,
				"removed":1
			}],
			"total":{
				"added":1,
				"removed":1
			}
		}
	}]}
	.
	,j
	w
	EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_file_changed
