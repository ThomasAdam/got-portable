#!/bin/sh
#
# Copyright (c) 2019 Stefan Sperling <stsp@openbsd.org>
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

test_cat_basic() {
	local testroot=`test_init cat_basic`
	local commit_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local gmtoff=`date +%z`
	local alpha_id=`got tree -r $testroot/repo -i | grep 'alpha$' | cut -d' ' -f 1`
	local gamma_id=`got tree -r $testroot/repo -i | grep 'gamma/$' | cut -d' ' -f 1`
	local delta_id=`got tree -r $testroot/repo -i gamma | grep 'delta$' | cut -d' ' -f 1`

	# cat blob
	echo "alpha" > $testroot/stdout.expected
	got cat -r $testroot/repo $alpha_id > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# cat tree
	echo "$delta_id 0100644 delta" > $testroot/stdout.expected
	got cat -r $testroot/repo $gamma_id > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# cat commit
	echo -n "tree " > $testroot/stdout.expected
	git_show_tree $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	echo "numparents 0" >> $testroot/stdout.expected
	echo "author $GOT_AUTHOR $author_time $gmtoff" >> $testroot/stdout.expected
	echo "committer $GOT_AUTHOR $author_time $gmtoff" \
		>> $testroot/stdout.expected
	echo "messagelen 22" >> $testroot/stdout.expected
	printf "\nadding the test tree\n" >> $testroot/stdout.expected

	got cat -r $testroot/repo $commit_id > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# TODO: test cat tag

	test_done "$testroot" "$ret"
}

test_cat_path() {
	local testroot=`test_init cat_path`
	local commit_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local alpha_id=`got tree -r $testroot/repo -i | grep 'alpha$' | cut -d' ' -f 1`
	local gamma_id=`got tree -r $testroot/repo -i | grep 'gamma/$' | cut -d' ' -f 1`
	local delta_id=`got tree -r $testroot/repo -i gamma | grep 'delta$' | cut -d' ' -f 1`

	# cat blob by path
	echo "alpha" > $testroot/stdout.expected
	got cat -r $testroot/repo alpha > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# cat tree by path
	echo "$delta_id 0100644 delta" > $testroot/stdout.expected
	got cat -r $testroot/repo gamma > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot && got checkout repo wt > /dev/null)
	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "changed alpha" > /dev/null)
	local commit_id2=`git_show_head $testroot/repo`
	local author_time2=`git_show_author_time $testroot/repo`
	local tree_commit2=`git_show_tree $testroot/repo`

	# cat blob by path in specific commit
	echo "alpha" > $testroot/stdout.expected
	got cat -r $testroot/repo -c $commit_id alpha > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	echo "modified alpha" > $testroot/stdout.expected
	got cat -r $testroot/repo -c $commit_id2 alpha > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# resolve ambiguities between paths and other arguments
	echo "new file called master" > $testroot/wt/master
	echo "new file called $commit_id2" > $testroot/wt/$commit_id2
	(cd $testroot/wt && got add master $commit_id2 > /dev/null)
	(cd $testroot/wt && got commit -m "added clashing paths" > /dev/null)
	local commit_id3=`git_show_head $testroot/repo`
	local author_time3=`git_show_author_time $testroot/repo`

	# references and object IDs override paths:
	echo -n "tree " > $testroot/stdout.expected
	git_show_tree $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	echo "numparents 1" >> $testroot/stdout.expected
	echo "parent $commit_id2" >> $testroot/stdout.expected
	echo "author $GOT_AUTHOR $author_time3 +0000" >> $testroot/stdout.expected
	echo "committer $GOT_AUTHOR $author_time3 +0000" \
		>> $testroot/stdout.expected
	echo "messagelen 22" >> $testroot/stdout.expected
	printf "\nadded clashing paths\n" >> $testroot/stdout.expected

	for arg in master $commit_id3; do
		got cat -r $testroot/repo $arg > $testroot/stdout
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	echo "tree $tree_commit2" > $testroot/stdout.expected
	echo "numparents 1" >> $testroot/stdout.expected
	echo "parent $commit_id" >> $testroot/stdout.expected
	echo "author $GOT_AUTHOR $author_time2 +0000" >> $testroot/stdout.expected
	echo "committer $GOT_AUTHOR $author_time2 +0000" \
		>> $testroot/stdout.expected
	echo "messagelen 15" >> $testroot/stdout.expected
	printf "\nchanged alpha\n" >> $testroot/stdout.expected

	got cat -r $testroot/repo $commit_id2 > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# force resolution of path 'master'
	echo "new file called master" > $testroot/stdout.expected
	got cat -r $testroot/repo -P master > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# force resolution of path "$commit_id2"
	echo "new file called $commit_id2" > $testroot/stdout.expected
	got cat -r $testroot/repo -P $commit_id2 > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_cat_submodule() {
	local testroot=`test_init cat_submodule`

	make_single_file_repo $testroot/repo2 foo

	(cd $testroot/repo && git -c protocol.file.allow=always \
		submodule -q add ../repo2)
	(cd $testroot/repo && git commit -q -m 'adding submodule')

	got cat -r $testroot/repo repo2 > $testroot/stdout \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "cat command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	local submodule_id=$(got tree -r $testroot/repo -i | \
		grep 'repo2\$$' | cut -d ' ' -f1)
	echo "got: object $submodule_id not found" > $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_cat_submodule_of_same_repo() {
	local testroot=`test_init cat_submodule_of_same_repo`
	local commit_id0=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`
	local gmtoff=`date +%z`

	(cd $testroot && git clone -q repo repo2 >/dev/null)
	(cd $testroot/repo && git -c protocol.file.allow=always \
		submodule -q add ../repo2)
	(cd $testroot/repo && git commit -q -m 'adding submodule')

	# 'got cat' shows the commit object which the submodule points to
	# because a commit with the same ID exists in the outer repository
	got cat -r $testroot/repo $commit_id0 | grep ^tree > $testroot/stdout.expected
	echo "numparents 0" >> $testroot/stdout.expected
	echo "author $GOT_AUTHOR $author_time $gmtoff" >> $testroot/stdout.expected
	echo "committer $GOT_AUTHOR $author_time $gmtoff" \
		>> $testroot/stdout.expected
	echo "messagelen 22" >> $testroot/stdout.expected
	printf "\nadding the test tree\n" >> $testroot/stdout.expected

	got cat -r $testroot/repo repo2 > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	test_done "$testroot" "$ret"
}

test_cat_symlink() {
	local testroot=`test_init cat_symlink`
	local commit_id=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`

	(cd $testroot/repo && ln -s alpha alpha.link)
	(cd $testroot/repo && ln -s epsilon epsilon.link)
	(cd $testroot/repo && ln -s /etc/passwd passwd.link)
	(cd $testroot/repo && ln -s ../beta epsilon/beta.link)
	(cd $testroot/repo && ln -s nonexistent nonexistent.link)
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "add symlinks"

	local alpha_link_id=`got tree -r $testroot/repo -i | grep 'alpha.link@ -> alpha$' | cut -d' ' -f 1`
	local epsilon_link_id=`got tree -r $testroot/repo -i | grep 'epsilon.link@ -> epsilon$' | cut -d' ' -f 1`
	local passwd_link_id=`got tree -r $testroot/repo -i | grep 'passwd.link@ -> /etc/passwd$' | cut -d' ' -f 1`
	local epsilon_beta_link_id=`got tree -r $testroot/repo -i epsilon | grep 'beta.link@ -> ../beta$' | cut -d' ' -f 1`
	local nonexistent_link_id=`got tree -r $testroot/repo -i | grep 'nonexistent.link@ -> nonexistent$' | cut -d' ' -f 1`

	# cat symlink to regular file
	echo -n "alpha" > $testroot/stdout.expected
	got cat -r $testroot/repo $alpha_link_id > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# cat symlink with relative path to regular file
	echo -n "../beta" > $testroot/stdout.expected
	got cat -r $testroot/repo $epsilon_beta_link_id > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# cat symlink to a tree
	echo -n "epsilon" > $testroot/stdout.expected
	got cat -r $testroot/repo $epsilon_link_id > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# cat symlink to paths which don't exist in repository
	echo -n "/etc/passwd" > $testroot/stdout.expected
	got cat -r $testroot/repo $passwd_link_id > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n "nonexistent" > $testroot/stdout.expected
	got cat -r $testroot/repo $nonexistent_link_id > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_cat_commit_keywords() {
	local testroot=$(test_init cat_commit_keywords)
	local repo="$testroot/repo"
	local wt="$testroot/wt"

	# :base requires work tree
	echo "got: '-c :base' requires work tree" > "$testroot/stderr.expected"
	got cat -r "$repo" -c:base alpha 2> "$testroot/stderr"
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "cat command succeeded unexpectedly" >&2
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

	got checkout "$repo" "$wt" > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	for i in $(seq 8); do
		echo "change $i" > "$wt/alpha"
		echo "delta $i" > "$wt/gamma/delta"

		(cd "$wt" && got ci -m "commit $i" > /dev/null)
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "commit failed unexpectedly" >&2
			test_done "$testroot" "$ret"
			return 1
		fi

		local delta_id=$(got tree -r "$repo" -i gamma | \
		    grep 'delta$' | cut -d' ' -f 1)
		set -- "$delta_ids" "$delta_id"
		delta_ids=$*
	done

	# cat blob by path
	echo "change 6" > "$testroot/stdout.expected"
	(cd "$wt" && got cat -c:head:-2 alpha > "$testroot/stdout")
	cmp -s "$testroot/stdout.expected" "$testroot/stdout"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/stdout.expected" "$testroot/stdout"
		test_done "$testroot" "$ret"
		return 1
	fi

	# cat blob by path with -r repo
	echo "delta 7" > "$testroot/stdout.expected"
	got cat -r "$repo" -c:head:- gamma/delta > "$testroot/stdout"
	cmp -s "$testroot/stdout.expected" "$testroot/stdout"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/stdout.expected" "$testroot/stdout"
		test_done "$testroot" "$ret"
		return 1
	fi

	# cat tree by path
	echo "$(pop_id 4 $delta_ids) 0100644 delta" > \
	    "$testroot/stdout.expected"
	(cd "$wt" && got cat -c:base:-4 gamma > "$testroot/stdout")
	cmp -s "$testroot/stdout.expected" "$testroot/stdout"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/stdout.expected" "$testroot/stdout"
		test_done "$testroot" "$ret"
		return 1
	fi

	# cat blob by path with -P
	echo "delta 4" > "$testroot/stdout.expected"
	(cd "$wt" && got up -c:base:-8 > /dev/null)
	(cd "$wt" && got cat -c:base:+4 -P gamma/delta > "$testroot/stdout")
	cmp -s "$testroot/stdout.expected" "$testroot/stdout"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/stdout.expected" "$testroot/stdout"
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_cat_basic
run_test test_cat_path
run_test test_cat_submodule
run_test test_cat_submodule_of_same_repo
run_test test_cat_symlink
run_test test_cat_commit_keywords
