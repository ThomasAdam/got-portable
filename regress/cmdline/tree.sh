#!/bin/sh
#
# Copyright (c) 2020 Tracey Emery <tracey@openbsd.org>
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

test_tree_basic() {
	local testroot=`test_init tree_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null

	echo "new file" > $testroot/wt/foo

	(cd $testroot/wt && got add foo > /dev/null)
	(cd $testroot/wt && got commit -m "add foo" foo > /dev/null)

	echo 'alpha' > $testroot/stdout.expected
	echo 'beta' >> $testroot/stdout.expected
	echo 'epsilon/' >> $testroot/stdout.expected
	echo 'foo' >> $testroot/stdout.expected
	echo 'gamma/' >> $testroot/stdout.expected

	for p in "" "." "/"; do
		(cd $testroot/wt && got tree $p > $testroot/stdout)
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	test_done "$testroot" "0"
}

test_tree_branch() {
	local testroot=`test_init tree_branch`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got br foo > $testroot/stdout)

	echo "new file" > $testroot/wt/foo

	(cd $testroot/wt && got add foo > /dev/null)
	(cd $testroot/wt && got commit -m "add foo" foo > /dev/null)

	echo 'alpha' > $testroot/stdout.expected
	echo 'beta' >> $testroot/stdout.expected
	echo 'epsilon/' >> $testroot/stdout.expected
	echo 'foo' >> $testroot/stdout.expected
	echo 'gamma/' >> $testroot/stdout.expected

	(cd $testroot/wt && got tree > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	test_done "$testroot" "$ret"
}

test_tree_submodule() {
	local testroot=`test_init tree_submodule`

	make_single_file_repo $testroot/repo2 foo
	(cd $testroot/repo && git -c protocol.file.allow=always \
		submodule -q add ../repo2)
	(cd $testroot/repo && git commit -q -m 'adding submodule')

	local submodule_id=$(got tree -r $testroot/repo -i | \
		grep 'repo2\$$' | cut -d ' ' -f1)
	local objpath=`get_loose_object_path $testroot/repo $submodule_id`

	# Currently fails in open(2)
	got tree -r $testroot/repo repo2 > $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "tree command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "got: open: $objpath: No such file or directory" \
		> $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_tree_submodule_of_same_repo() {
	local testroot=`test_init tree_submodule_of_same_repo`

	(cd $testroot && git clone -q repo repo2 >/dev/null)
	(cd $testroot/repo && git -c protocol.file.allow=always \
		submodule -q add ../repo2)
	(cd $testroot/repo && git commit -q -m 'adding submodule')

	# Currently fails with "bad object data"
	got tree -r $testroot/repo repo2 > $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "tree command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	if [ -n "$GOT_TEST_PACK" ]; then
		echo "got-read-pack: bad object data" \
			> $testroot/stderr.expected
	else
		echo "got-read-tree: bad object data" \
			> $testroot/stderr.expected
	fi
	echo "got: bad object data" >> $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_tree_commit_keywords() {
	local testroot=$(test_init tree_commit_keywords)
	local wt="$testroot/wt"

	# :base requires work tree
	echo "got: '-c :base' requires work tree" > "$testroot/stderr.expected"
	got tree -r "$testroot/repo" -c:base 2> "$testroot/stderr"
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "tree command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s "$testroot/stderr.expected" "$testroot/stderr"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/stderr.expected" "$testroot/stderr"
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'alpha' > $testroot/stdout.expected
	echo 'beta' >> $testroot/stdout.expected
	echo 'epsilon/' >> $testroot/stdout.expected
	echo 'gamma/' >> $testroot/stdout.expected

	got tree -r "$testroot/repo" -c:head > "$testroot/stdout"
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got checkout "$testroot/repo" "$wt" > /dev/null

	(
		cd "$wt"
		mkdir bing
		echo "foo" > foo
		echo "bar" > bar
		echo "baz" > baz
		echo "bob" > bing/bob
		got add foo bar baz bing/bob > /dev/null
		got commit -m "add foo" foo > /dev/null
		got commit -m "add bar" bar > /dev/null
		got commit -m "add baz" baz > /dev/null
		got commit -m "add bing/bob" > /dev/null
	)

	echo 'alpha' > $testroot/stdout.expected
	echo 'beta' >> $testroot/stdout.expected
	echo 'epsilon/' >> $testroot/stdout.expected
	echo 'foo' >> $testroot/stdout.expected
	echo 'gamma/' >> $testroot/stdout.expected

	(cd "$wt" && got tree -c:base:-3 > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'alpha' > $testroot/stdout.expected
	echo 'bar' >> $testroot/stdout.expected
	echo 'beta' >> $testroot/stdout.expected
	echo 'epsilon/' >> $testroot/stdout.expected
	echo 'foo' >> $testroot/stdout.expected
	echo 'gamma/' >> $testroot/stdout.expected

	(cd "$wt" && got tree -cmaster:-2 > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'alpha' > $testroot/stdout.expected
	echo 'bar' >> $testroot/stdout.expected
	echo 'baz' >> $testroot/stdout.expected
	echo 'beta' >> $testroot/stdout.expected
	echo 'epsilon/' >> $testroot/stdout.expected
	echo 'foo' >> $testroot/stdout.expected
	echo 'gamma/' >> $testroot/stdout.expected

	(cd "$wt" && got tree -c:head:- > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'alpha' > $testroot/stdout.expected
	echo 'bar' >> $testroot/stdout.expected
	echo 'baz' >> $testroot/stdout.expected
	echo 'beta' >> $testroot/stdout.expected
	echo 'bing/' >> $testroot/stdout.expected
	echo 'epsilon/' >> $testroot/stdout.expected
	echo 'foo' >> $testroot/stdout.expected
	echo 'gamma/' >> $testroot/stdout.expected

	(cd "$wt" && got up -c:base:-4 > $testroot/stdout)
	(cd "$wt" && got tree -c:base:+4 > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "0"
}

test_parseargs "$@"
run_test test_tree_basic
run_test test_tree_branch
run_test test_tree_submodule
run_test test_tree_submodule_of_same_repo
run_test test_tree_commit_keywords
