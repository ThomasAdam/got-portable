#!/bin/sh
#
# Copyright (c) 2024 Omar Polo <op@openbsd.org>
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
	    > $testroot/stdout &

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
		test_done "$testroot" "$ret"
		return 1
	fi

	# Try the same thing again with 'git push' instead of 'got send'
	echo "change alpha once more" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'make more changes' > /dev/null)
	local commit_id=`git_show_head $testroot/repo-clone`
	local author_time=`git_show_author_time $testroot/repo-clone`

	timeout 5 ./http-server -a $AUTH -p $GOTD_TEST_HTTP_PORT \
	    > $testroot/stdout &

	sleep 1 # server starts up

	git -C $testroot/repo-clone push -q origin main
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git push failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for the http "server"

	echo -n > "$testroot/stdout.expected"
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
		"short_message":"make more changes",
		"message":"make more changes\n",
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

test_bad_utf8() {
	local testroot=`test_init bad_utf8 1`

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
	fi

	# invalid utf8 sequence
	commit_msg="make$(printf '\xED\xA0\x80')changes"

	echo "changed" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "$commit_msg" > /dev/null)
	local commit_id=`git_show_head $testroot/repo-clone`
	local author_time=`git_show_author_time $testroot/repo-clone`

	timeout 5 ./http-server -a $AUTH -p $GOTD_TEST_HTTP_PORT \
	    > $testroot/stdout &

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
		"short_message":"make\uFFFD\uFFFDchanges",
		"message":"make\uFFFD\uFFFDchanges\n",
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
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_many_commits_not_summarized() {
	local testroot=`test_init many_commits_not_summarized 1`

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

	for i in `seq 1 24`; do
		echo "alpha $i" > $testroot/wt/alpha
		(cd $testroot/wt && got commit -m 'make changes' > /dev/null)
		local commit_id=`git_show_head $testroot/repo-clone`
		local author_time=`git_show_author_time $testroot/repo-clone`
		set -- "$@" "$commit_id $author_time"
	done

	timeout 5 ./http-server -a $AUTH -p "$GOTD_TEST_HTTP_PORT" \
	    > $testroot/stdout &

	sleep 1 # server starts up

	got send -b main -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for the http "server"

	printf '{"notifications":[' > $testroot/stdout.expected
	comma=""
	for i in `seq 1 24`; do
		s=`pop_idx $i "$@"`
		commit_id=$(echo $s | cut -d' ' -f1)
		commit_time=$(echo "$s" | sed -e "s/^$commit_id //g")

		echo "$comma"
		comma=','

		cat <<-EOF
		{
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
			"date":$commit_time,
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
		}
		EOF
	done >> $testroot/stdout.expected
	echo "]}" >> $testroot/stdout.expected
	ed -s "$testroot/stdout.expected" <<-EOF
	,j
	w
	EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_many_commits_summarized() {
	local testroot=`test_init many_commits_summarized 1`

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

	for i in `seq 1 51`; do
		echo "alpha $i" > $testroot/wt/alpha
		(cd $testroot/wt && got commit -m 'make changes' > /dev/null)
		local commit_id=`git_show_head $testroot/repo-clone`
		local short_commit_id=`trim_obj_id 7 $commit_id`
		local author_time=`git_show_author_time $testroot/repo-clone`
		set -- "$@" "$short_commit_id $author_time"
	done

	timeout 5 ./http-server -a $AUTH -p "$GOTD_TEST_HTTP_PORT" \
	    > $testroot/stdout &

	sleep 1 # server starts up

	got send -b main -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for the http "server"

	printf '{"notifications":[' > $testroot/stdout.expected
	comma=""
	for i in `seq 1 51`; do
		s=`pop_idx $i "$@"`
		commit_id=$(echo $s | cut -d' ' -f1)
		commit_time=$(echo "$s" | cut -d' ' -f2)

		echo "$comma"
		comma=','

		cat <<-EOF
		{
			"type":"commit",
			"short":true,
			"repo":"test-repo",
			"authenticated_user":"${GOTD_DEVUSER}",
			"id":"$commit_id",
			"committer":{
				"user":"$GOT_AUTHOR_8"
			},
			"date":$commit_time,
			"short_message":"make changes"
		}
		EOF
	done >> $testroot/stdout.expected
	echo "]}" >> $testroot/stdout.expected
	ed -s "$testroot/stdout.expected" <<-EOF
	,j
	w
	EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_branch_created() {
	local testroot=`test_init branch_created 1`

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

	(cd $testroot/wt && got branch newbranch > /dev/null)

	echo "change alpha on branch" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'newbranch' > /dev/null)
	local commit_id=`git_show_branch_head $testroot/repo-clone newbranch`
	local author_time=`git_show_author_time $testroot/repo-clone $commit_id`

	timeout 5 ./http-server -a $AUTH -p "$GOTD_TEST_HTTP_PORT" \
	    > $testroot/stdout &

	sleep 1 # server starts up

	got send -b newbranch -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for the http "server"

	# in the future it should contain something like this too
	# {
	# 	"type":"new-branch",
	# 	"user":"${GOTD_DEVUSER}",
	# 	"ref":"refs/heads/newbranch"
	# },

	touch "$testroot/stdout.expected"
	ed -s "$testroot/stdout.expected" <<-EOF
	a
	{"notifications":[
	{
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
		"short_message":"newbranch",
		"message":"newbranch\n",
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
	}
	]}
	.
	,j
	w
	EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_branch_removed() {
	local testroot=`test_init branch_removed 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	timeout 5 ./http-server -a $AUTH -p "$GOTD_TEST_HTTP_PORT" \
	    > $testroot/stdout &

	sleep 1 # server starts up

	local commit_id=`git_show_branch_head $testroot/repo-clone newbranch`

	got send -d newbranch -q -r $testroot/repo-clone
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
		"type":"branch-deleted",
		"repo":"test-repo",
		"authenticated_user":"${GOTD_DEVUSER}",
		"ref":"refs/heads/newbranch",
		"id":"$commit_id"
	}]}
	.
	,j
	w
	EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_tag_created() {
	local testroot=`test_init tag_created 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got tag -r $testroot/repo-clone -m "new tag" 1.0 > /dev/null
	local commit_id=`git_show_head $testroot/repo-clone`
	local tagger_time=`git_show_tagger_time $testroot/repo-clone 1.0`

	timeout 5 ./http-server -a $AUTH -p "$GOTD_TEST_HTTP_PORT" \
	    >$testroot/stdout &

	sleep 1 # server starts up

	got send -t 1.0 -q -r $testroot/repo-clone
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
		"type":"tag",
		"repo":"test-repo",
		"authenticated_user":"${GOTD_DEVUSER}",
		"tag":"refs/tags/1.0",
		"tagger":{
			"full":"$GOT_AUTHOR",
			"name":"$GIT_AUTHOR_NAME",
			"mail":"$GIT_AUTHOR_EMAIL",
			"user":"$GOT_AUTHOR_11"
		},
		"date":$tagger_time,
		"object":{
			"type":"commit",
			"id":"$commit_id"
		},
		"message":"new tag\n\n"
	}]}
	.
	,j
	w
	EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_tag_changed() {
	local testroot=`test_init tag_changed 1`

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

	got ref -r $testroot/repo-clone -d refs/tags/1.0 >/dev/null
	got tag -r $testroot/repo-clone -m "new tag" 1.0 > /dev/null
	local tagger_time=`git_show_tagger_time $testroot/repo-clone 1.0`

	timeout 5 ./http-server -a $AUTH -p "$GOTD_TEST_HTTP_PORT" \
	    > $testroot/stdout &

	sleep 1 # server starts up

	got send -f -t 1.0 -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for the http "server"

	# XXX: at the moment this is exactly the same as the "new tag"
	# notification

	touch "$testroot/stdout.expected"
	ed -s "$testroot/stdout.expected" <<-EOF
	a
	{"notifications":[{
		"type":"tag",
		"repo":"test-repo",
		"authenticated_user":"${GOTD_DEVUSER}",
		"tag":"refs/tags/1.0",
		"tagger":{
			"full":"$GOT_AUTHOR",
			"name":"$GIT_AUTHOR_NAME",
			"mail":"$GIT_AUTHOR_EMAIL",
			"user":"$GOT_AUTHOR_11"
		},
		"date":$tagger_time,
		"object":{
			"type":"commit",
			"id":"$commit_id"
		},
		"message":"new tag\n\n"
	}]}
	.
	,j
	w
	EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_file_changed
run_test test_bad_utf8
run_test test_many_commits_not_summarized
run_test test_many_commits_summarized
run_test test_branch_created
run_test test_branch_removed
run_test test_tag_created
run_test test_tag_changed
