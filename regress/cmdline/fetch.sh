#!/bin/sh
#
# Copyright (c) 2020 Stefan Sperling <stsp@openbsd.org>
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

function test_fetch_basic {
	local testroot=`test_init fetch_basic`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	got ref -l -r $testroot/repo-clone > $testroot/stdout
	if [ "$ret" != "0" ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -q -r $testroot/repo-clone > $testroot/stdout \
		2> $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got log -l0 -p -r $testroot/repo > $testroot/log-repo
	if [ "$ret" != "0" ]; then
		echo "got log command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	got log -l0 -p -r $testroot/repo > $testroot/log-repo-clone
	if [ "$ret" != "0" ]; then
		echo "got log command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/log-repo $testroot/log-repo-clone
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "log -p output of cloned repository differs" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo > $testroot/stdout
	if [ "$ret" != "0" ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id2" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout
	if [ "$ret" != "0" ]; then
		echo "got ref command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_fetch_list {
	local testroot=`test_init fetch_list`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null

	got clone -q $testurl/repo $testroot/repo-clone
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo-clone && got fetch -l \
		> $testroot/stdout 2>$testroot/stderr)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "Connected to \"origin\" 127.0.0.1" > $testroot/stdout.expected
	got ref -l -r $testroot/repo >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_fetch_branch {
	local testroot=`test_init fetch_branch`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	(cd $testroot/repo && git checkout -q foo)
	echo "modified alpha on foo" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id3=`git_show_head $testroot/repo`

	got fetch -q -r $testroot/repo-clone -b foo > $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/foo" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id3" >> $testroot/stdout.expected
	# refs/remotes/origin/master is umodified because it wasn't fetched
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -q -r $testroot/repo-clone -b master > $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/foo" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id3" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_fetch_all {
	local testroot=`test_init fetch_all`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -q -a -r $testroot/repo-clone
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_fetch_empty_packfile {
	local testroot=`test_init fetch_empty_packfile`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got clone -q $testurl/repo $testroot/repo-clone
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -q -a -r $testroot/repo-clone
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_fetch_delete_branch {
	local testroot=`test_init fetch_delete_branch`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`


	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got clone -a -q $testurl/repo $testroot/repo-clone
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -r $testroot/repo -d foo

	got fetch -q -r $testroot/repo-clone
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -d -q -r $testroot/repo-clone > $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	# refs/heads/foo is now deleted
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	# refs/remotes/origin/foo is now deleted
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

function test_fetch_update_tag {
	local testroot=`test_init fetch_update_tag`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`


	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got clone -a -q $testurl/repo $testroot/repo-clone
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	got ref -r $testroot/repo -d "refs/tags/1.0"  >/dev/null
	got tag -r $testroot/repo -c $commit_id2 -m tag "1.0" >/dev/null
	local tag_id2=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -q -r $testroot/repo-clone
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -r $testroot/repo-clone 2> $testroot/stderr | \
		tail -n 1 > $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "Rejecting update of existing tag refs/tags/1.0: $tag_id2" \
		> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -q -t -r $testroot/repo-clone > $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected
	# refs/hoo/boo/zoo is missing because it is outside of refs/heads
	echo "refs/tags/1.0: $tag_id2" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_fetch_reference {
	local testroot=`test_init fetch_reference`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got branch -r $testroot/repo -c $commit_id foo
	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got tag -r $testroot/repo -c $commit_id -m tag "1.0" >/dev/null
	local tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`

	echo "modified alpha on master" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id2=`git_show_head $testroot/repo`

	(cd $testroot/repo && git checkout -q foo)
	echo "modified alpha on foo" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id3=`git_show_head $testroot/repo`
	(cd $testroot/repo && git checkout -q master)

	got fetch -q -r $testroot/repo-clone -R refs/remotes/origin/main \
		> $testroot/stdout 2> $testroot/stderr
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "got fetch command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: refs/remotes/origin/main: reference cannot be fetched" \
		> $testroot/stderr.expected

	cmp -s $testroot/stderr $testroot/stderr.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -q -r $testroot/repo-clone -R refs/hoo
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/hoo/boo/zoo: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id2" \
		>> $testroot/stdout.expected
	echo "refs/tags/1.0: $tag_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

function test_fetch_replace_symref {
	local testroot=`test_init fetch_replace_symref`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -m -q $testurl/repo $testroot/repo-clone
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -r $testroot/repo -c $commit_id refs/hoo/boo/zoo
	got ref -r $testroot/repo-clone -s refs/heads/master refs/hoo/boo/zoo

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/hoo/boo/zoo: refs/heads/master" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -r $testroot/repo-clone -R refs/hoo \
		2> $testroot/stderr | grep ^Replacing > $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got fetch command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "Replacing reference refs/hoo/boo/zoo: refs/heads/master" \
		> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/hoo/boo/zoo: $commit_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

function test_fetch_update_headref {
	local testroot=`test_init fetch_update_headref`
	local testurl=ssh://127.0.0.1/$testroot
	local commit_id=`git_show_head $testroot/repo`

	got clone -q $testurl/repo $testroot/repo-clone
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got clone command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/master" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -r $testroot/repo -c refs/heads/master refs/heads/foo
	got ref -r $testroot/repo -s refs/heads/foo HEAD
	got ref -l -r $testroot/repo > $testroot/stdout

	echo "HEAD: refs/heads/foo" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got fetch -q -r $testroot/repo-clone

	got ref -l -r $testroot/repo-clone > $testroot/stdout

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/remotes/origin/HEAD: refs/remotes/origin/foo" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/foo: $commit_id" \
		>> $testroot/stdout.expected
	echo "refs/remotes/origin/master: $commit_id" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

run_test test_fetch_basic
run_test test_fetch_list
run_test test_fetch_branch
run_test test_fetch_all
run_test test_fetch_empty_packfile
run_test test_fetch_delete_branch
run_test test_fetch_update_tag
run_test test_fetch_reference
run_test test_fetch_replace_symref
run_test test_fetch_update_headref
