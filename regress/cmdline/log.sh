#!/bin/sh
#
# Copyright (c) 2019, 2020 Stefan Sperling <stsp@openbsd.org>
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

test_log_in_repo() {
	local testroot=`test_init log_in_repo`
	local head_rev=`git_show_head $testroot/repo`

	echo "commit $head_rev (master)" > $testroot/stdout.expected

	for p in "" "." alpha epsilon epsilon/zeta; do
		(cd $testroot/repo && got log $p | \
			grep ^commit > $testroot/stdout)
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	for p in "" "." zeta; do
		(cd $testroot/repo/epsilon && got log $p | \
			grep ^commit > $testroot/stdout)
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

test_log_in_bare_repo() {
	local testroot=`test_init log_in_bare_repo`
	local head_rev=`git_show_head $testroot/repo`

	echo "commit $head_rev (master)" > $testroot/stdout.expected

	for p in "" "." alpha epsilon epsilon/zeta; do
		(cd $testroot/repo/.git && got log $p | \
			grep ^commit > $testroot/stdout)
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

test_log_in_worktree() {
	local testroot=`test_init log_in_worktree 1`

	make_test_tree $testroot/repo
	mkdir -p $testroot/repo/epsilon/d
	echo foo > $testroot/repo/epsilon/d/foo
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding the test tree"
	local head_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "commit $head_commit (master)" > $testroot/stdout.expected

	for p in "" "." alpha epsilon; do
		(cd $testroot/wt && got log $p | \
			grep ^commit > $testroot/stdout)
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	for p in "" "." zeta; do
		(cd $testroot/wt/epsilon && got log $p | \
			grep ^commit > $testroot/stdout)
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	for p in "" "." foo; do
		(cd $testroot/wt/epsilon && got log d/$p | \
			grep ^commit > $testroot/stdout)
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

test_log_in_worktree_with_path_prefix() {
	local testroot=`test_init log_in_worktree_with_path_prefix`
	local head_rev=`git_show_head $testroot/repo`

	echo "modified zeta" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "modified zeta"
	local zeta_rev=`git_show_head $testroot/repo`

	echo "modified delta" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "modified delta"
	local delta_rev=`git_show_head $testroot/repo`

	got checkout -p epsilon $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "commit $delta_rev (master)" > $testroot/stdout.expected
	echo "commit $zeta_rev" >> $testroot/stdout.expected
	echo "commit $head_rev" >> $testroot/stdout.expected

	(cd $testroot/wt && got log | grep ^commit > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "commit $zeta_rev" > $testroot/stdout.expected
	echo "commit $head_rev" >> $testroot/stdout.expected

	for p in "." zeta; do
		(cd $testroot/wt && got log $p | \
			grep ^commit > $testroot/stdout)
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

test_log_tag() {
	local testroot=`test_init log_tag`
	local commit_id=`git_show_head $testroot/repo`
	local tag="1.0.0"
	local tag2="2.0.0"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo tag -a -m "test" $tag

	echo "commit $commit_id (master, tags/$tag)" > $testroot/stdout.expected
	(cd $testroot/wt && got log -l1 -c $tag | grep ^commit \
		> $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# test a "lightweight" tag
	git -C $testroot/repo tag $tag2

	echo "commit $commit_id (master, tags/$tag, tags/$tag2)" \
		> $testroot/stdout.expected
	(cd $testroot/wt && got log -l1 -c $tag2 | grep ^commit \
		> $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_log_limit() {
	local testroot=`test_init log_limit`
	local commit_id0=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'test log_limit' > /dev/null)
	local commit_id1=`git_show_head $testroot/repo`

	(cd $testroot/wt && got rm beta >/dev/null)
	(cd $testroot/wt && got commit -m 'test log_limit' > /dev/null)
	local commit_id2=`git_show_head $testroot/repo`

	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)
	(cd $testroot/wt && got commit -m 'test log_limit' > /dev/null)
	local commit_id3=`git_show_head $testroot/repo`

	# -l1 should print the first commit only
	echo "commit $commit_id3 (master)" > $testroot/stdout.expected
	(cd $testroot/wt && got log -l1 | grep ^commit > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# env var can be used to set a log limit without -l option
	echo "commit $commit_id3 (master)" > $testroot/stdout.expected
	echo "commit $commit_id2" >> $testroot/stdout.expected
	(cd $testroot/wt && env GOT_LOG_DEFAULT_LIMIT=2 got log | \
		grep ^commit > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# non-numeric env var is ignored
	(cd $testroot/wt && env GOT_LOG_DEFAULT_LIMIT=foobar got log | \
		grep ^commit > $testroot/stdout)
	echo "commit $commit_id3 (master)" > $testroot/stdout.expected
	echo "commit $commit_id2" >> $testroot/stdout.expected
	echo "commit $commit_id1" >> $testroot/stdout.expected
	echo "commit $commit_id0" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# -l option takes precedence over env var
	echo "commit $commit_id3 (master)" > $testroot/stdout.expected
	echo "commit $commit_id2" >> $testroot/stdout.expected
	echo "commit $commit_id1" >> $testroot/stdout.expected
	echo "commit $commit_id0" >> $testroot/stdout.expected
	(cd $testroot/wt && env GOT_LOG_DEFAULT_LIMIT=1 got log -l0 | \
		grep ^commit > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "0"
}

test_log_oneline() {
	local testroot=`test_init log_oneline`
	local commit_id0=`git_show_head $testroot/repo`
	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "test oneline
no" > /dev/null)
	local commit_id1=`git_show_head $testroot/repo`
	local author_time1=`git_show_author_time $testroot/repo`

	echo "modified beta" > $testroot/wt/beta
	(cd $testroot/wt && got commit -m "  test oneline
no" > /dev/null)
	local commit_id2=`git_show_head $testroot/repo`
	local author_time2=`git_show_author_time $testroot/repo`

	d=`date -u -r $author_time1 +"%F"`
	printf "$d %-7s test oneline\n" master > $testroot/stdout.expected
	d=`date -u -r $author_time2 +"%F"`
	printf "$d %.7s test oneline\n" $commit_id1 >> $testroot/stdout.expected

	(cd $testroot/repo && got log -s | head -n 2 > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	test_done "$testroot" "0"
}

test_log_patch_added_file() {
	local testroot=`test_init log_patch_added_file`
	local commit_id0=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)
	(cd $testroot/wt && got commit -m 'test log_limit' > /dev/null)
	local commit_id1=`git_show_head $testroot/repo`

	echo "commit $commit_id1 (master)" > $testroot/stdout.expected
	echo "commit - $commit_id0" >> $testroot/stdout.expected
	echo "commit + $commit_id1" >> $testroot/stdout.expected
	# This used to fail with 'got: no such entry found in tree'
	(cd $testroot/wt && got log -l1 -p new > $testroot/stdout.patch)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got log command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi
	grep ^commit $testroot/stdout.patch > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_log_nonexistent_path() {
	local testroot=`test_init log_nonexistent_path`
	local head_rev=`git_show_head $testroot/repo`

	echo "commit $head_rev (master)" > $testroot/stdout.expected

	(cd $testroot/repo && got log this/does/not/exist \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "log command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: this/does/not/exist: no such entry found in tree" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_log_end_at_commit() {
	local testroot=`test_init log_end_at_commit`
	local commit_id0=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'test log_limit' > /dev/null)
	local commit_id1=`git_show_head $testroot/repo`

	(cd $testroot/wt && got rm beta >/dev/null)
	(cd $testroot/wt && got commit -m 'test log_limit' > /dev/null)
	local commit_id2=`git_show_head $testroot/repo`

	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)
	(cd $testroot/wt && got commit -m 'test log_limit' > /dev/null)
	local commit_id3=`git_show_head $testroot/repo`

	# Print commit 3 only
	echo "commit $commit_id3 (master)" > $testroot/stdout.expected
	(cd $testroot/wt && got log -x $commit_id3 | grep ^commit \
		> $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Print commit 3 up to commit 1 inclusive
	echo "commit $commit_id3 (master)" > $testroot/stdout.expected
	echo "commit $commit_id2" >> $testroot/stdout.expected
	echo "commit $commit_id1" >> $testroot/stdout.expected
	(cd $testroot/wt && got log -c $commit_id3 -x $commit_id1 | \
		grep ^commit > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Create commits on an unrelated branch
	(cd $testroot/wt && got br foo > /dev/null)
	echo bar >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change on branch foo" >/dev/null)
	local commit_id4=`git_show_branch_head $testroot/repo foo`

	# Print commit 4 only (in work tree)
	echo "commit $commit_id4 (foo)" > $testroot/stdout.expected
	(cd $testroot/wt && got log -x foo | grep ^commit \
		> $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Print commit 4 only (in repository)
	echo "commit $commit_id4 (foo)" > $testroot/stdout.expected
	(cd $testroot/repo && got log -c foo -x foo | grep ^commit \
		> $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Repository's HEAD is on master branch so -x foo without an explicit
	# '-c foo' start commit has no effect there
	echo "commit $commit_id3 (master)" > $testroot/stdout.expected
	echo "commit $commit_id2" >> $testroot/stdout.expected
	echo "commit $commit_id1" >> $testroot/stdout.expected
	echo "commit $commit_id0" >> $testroot/stdout.expected
	(cd $testroot/repo && got log -x foo | grep ^commit \
		> $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# got will refuse -x with a non-existent commit
	(cd $testroot/wt && got log -x nonexistent \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "log command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo -n > $testroot/stdout.expected
	echo "got: reference nonexistent not found" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# try the same with the hash of an empty string which is very
	# unlikely to match any object
	local empty_sha1=da39a3ee5e6b4b0d3255bfef95601890afd80709
	(cd $testroot/wt && got log -x $empty_sha1 \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "log command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo -n > $testroot/stdout.expected
	echo "got: commit $empty_sha1: object not found" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "0"
}

test_log_reverse_display() {
	local testroot=`test_init log_reverse_display`
	local commit_id0=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'commit1' > /dev/null)
	local commit_id1=`git_show_head $testroot/repo`

	(cd $testroot/wt && got rm beta >/dev/null)
	(cd $testroot/wt && got commit -m 'commit2' > /dev/null)
	local commit_id2=`git_show_head $testroot/repo`

	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)
	(cd $testroot/wt && got commit -m 'commit3' > /dev/null)
	local commit_id3=`git_show_head $testroot/repo`

	# -R alone should display all commits in reverse
	echo "commit $commit_id0" > $testroot/stdout.expected
	echo "commit $commit_id1" >> $testroot/stdout.expected
	echo "commit $commit_id2" >> $testroot/stdout.expected
	echo "commit $commit_id3 (master)" >> $testroot/stdout.expected
	(cd $testroot/wt && got log -R | grep ^commit > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# -R takes effect after the -l commit traversal limit
	echo "commit $commit_id2" > $testroot/stdout.expected
	echo "commit $commit_id3 (master)" >> $testroot/stdout.expected
	(cd $testroot/wt && got log -R -l2 | grep ^commit > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# -R works with commit ranges specified via -c and -x
	echo "commit $commit_id1" > $testroot/stdout.expected
	echo "commit $commit_id2" >> $testroot/stdout.expected
	echo "commit $commit_id3 (master)" >> $testroot/stdout.expected
	(cd $testroot/wt && got log -R -c $commit_id3 -x $commit_id1 | \
		grep ^commit > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# commit matching with -s applies before -R
	echo "commit $commit_id1" > $testroot/stdout.expected
	echo "commit $commit_id2" >> $testroot/stdout.expected
	(cd $testroot/wt && got log -R -S 'commit[12]' | \
		grep ^commit > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# -R works in combination with -P
	echo "" > $testroot/stdout.expected
	(cd $testroot/wt && got log -R -P | grep -E '^(commit| [MDmA])' \
		> $testroot/stdout)
	echo "commit $commit_id0" > $testroot/stdout.expected
	echo " A  alpha" >> $testroot/stdout.expected
	echo " A  beta" >> $testroot/stdout.expected
	echo " A  epsilon/zeta" >> $testroot/stdout.expected
	echo " A  gamma/delta" >> $testroot/stdout.expected
	echo "commit $commit_id1" >> $testroot/stdout.expected
	echo " M  alpha" >> $testroot/stdout.expected
	echo "commit $commit_id2" >> $testroot/stdout.expected
	echo " D  beta" >> $testroot/stdout.expected
	echo "commit $commit_id3 (master)" >> $testroot/stdout.expected
	echo " A  new" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_log_in_worktree_different_repo() {
	local testroot=`test_init log_in_worktree_different_repo 1`

	make_test_tree $testroot/repo
	mkdir -p $testroot/repo/epsilon/d
	echo foo > $testroot/repo/epsilon/d/foo
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding the test tree"
	local head_commit=`git_show_head $testroot/repo`

	got init $testroot/other-repo
	mkdir -p $testroot/tree
	make_test_tree $testroot/tree
	got import -mm -b foo -r $testroot/other-repo $testroot/tree >/dev/null
	got checkout -b foo $testroot/other-repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "commit $head_commit (master)" > $testroot/stdout.expected

	# 'got log' used to fail with "reference refs/heads/foo not found"
	# even though that reference belongs to an unrelated repository
	# found via a worktree via the current working directory
	for p in "" alpha epsilon; do
		(cd $testroot/wt && got log -r $testroot/repo $p | \
			grep ^commit > $testroot/stdout)
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	for p in "" epsilon/zeta; do
		(cd $testroot/wt/epsilon && got log -r $testroot/repo $p | \
			grep ^commit > $testroot/stdout)
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	for p in "" foo; do
		(cd $testroot/wt/epsilon && got log -r $testroot/repo epsilon/d/$p | \
			grep ^commit > $testroot/stdout)
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

test_log_changed_paths() {
	local testroot=`test_init log_changed_paths`
	local commit_id0=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'test log_changed_paths' > /dev/null)
	local commit_id1=`git_show_head $testroot/repo`

	(cd $testroot/wt && got rm beta >/dev/null)
	(cd $testroot/wt && chmod +x epsilon/zeta >/dev/null)
	(cd $testroot/wt && got commit -m 'test log_changed_paths' > /dev/null)
	local commit_id2=`git_show_head $testroot/repo`

	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)
	(cd $testroot/wt && got commit -m 'test log_changed_paths' > /dev/null)
	local commit_id3=`git_show_head $testroot/repo`

	(cd $testroot/wt && got log -P | grep '^ [MDmA]' > $testroot/stdout)

	echo " A  new" > $testroot/stdout.expected
	echo " D  beta" >> $testroot/stdout.expected
	echo " m  epsilon/zeta" >> $testroot/stdout.expected
	echo " M  alpha" >> $testroot/stdout.expected
	echo " A  alpha" >> $testroot/stdout.expected
	echo " A  beta" >> $testroot/stdout.expected
	echo " A  epsilon/zeta" >> $testroot/stdout.expected
	echo " A  gamma/delta" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_log_merge_commit_nonexistent_path() {
	local testroot=`test_init log_merge_commit_corner_case 1`

        # Create the following commit graph (most recent commit shown first):
        #
        #   o  create dir/beta
        #   |
        #   o  merge (does not touch dir)
        #  / \
        # o   o  changes which don't touch the directory "dir"
        #  \ /
        #   o  initial commit, which includes directory "dir" but not dir/beta


	mkdir $testroot/repo/dir
	touch $testroot/repo/dir/alpha
	git -C $testroot/repo add dir/alpha
	git_commit $testroot/repo -m "initial commit"

	git -C $testroot/repo checkout -q -b aux
	touch $testroot/repo/gamma
	git -C $testroot/repo add gamma
	git_commit $testroot/repo -m "change on aux"

	git -C $testroot/repo checkout -q master
	touch $testroot/repo/delta
	git -C $testroot/repo add delta
	git_commit $testroot/repo -m "change on master"

	git -C $testroot/repo merge -q -m "merge" aux

	touch $testroot/repo/dir/beta
	git -C $testroot/repo add dir/beta
	git_commit $testroot/repo -m "add beta"

	head_commit=`git_show_head $testroot/repo`

	got log -r $testroot/repo -b dir/beta | grep ^commit > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "log command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "commit $head_commit (master)" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_log_submodule() {
	local testroot=`test_init log_submodule`

	make_single_file_repo $testroot/repo2 foo

	git -C $testroot/repo -c protocol.file.allow=always \
		submodule -q add ../repo2
	git -C $testroot/repo commit -q -m 'adding submodule'
	local head_commit=`git_show_head $testroot/repo`

	echo "commit $head_commit (master)" > $testroot/stdout.expected

	got log -r $testroot/repo -l1 repo2 | grep ^commit > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo " A  .gitmodules" > $testroot/stdout.expected

	got log -r $testroot/repo -l1 -P repo2 | grep '^ [MDmA]' \
		> $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got log -p -r $testroot/repo -l1 repo2 \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "log command succeeded unexpectedly" >&2
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
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified foo" > $testroot/repo2/foo
	git -C $testroot/repo2 commit -q -a -m 'modified a submodule'

	# Update the repo/repo2 submodule link
	git -C $testroot/repo/repo2 pull -q
	git -C $testroot/repo add repo2
	git_commit $testroot/repo -m "changed submodule link"

	# log -P does not show the changed submodule path
	got log -P -r $testroot/repo -l1 repo2 > $testroot/stdout.full
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "log command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	grep '^ [MDmA]' $testroot/stdout.full > $testroot/stdout

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_log_diffstat() {
	local testroot=`test_init log_diffstat`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	printf "modified\nalpha.\n" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'log_diffstat mod file' > /dev/null)

	(cd $testroot/wt && got rm beta >/dev/null)
	(cd $testroot/wt && chmod +x epsilon/zeta >/dev/null)
	(cd $testroot/wt && got commit -m 'log_diffstat rm file' > /dev/null)

	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)
	(cd $testroot/wt && got commit -m 'log_diffstat add file' > /dev/null)

	cat <<EOF >$testroot/stdout.expected
 A  new  |  1+  0-

1 file changed, 1 insertion(+), 0 deletions(-)
 D  beta          |  0+  1-
 m  epsilon/zeta  |  0+  0-

2 files changed, 0 insertions(+), 1 deletion(-)
 M  alpha  |  2+  1-

1 file changed, 2 insertions(+), 1 deletion(-)
 A  alpha         |  1+  0-
 A  beta          |  1+  0-
 A  epsilon/zeta  |  1+  0-
 A  gamma/delta   |  1+  0-

4 files changed, 4 insertions(+), 0 deletions(-)
EOF

	# try different -dPp combinations
	for flags in -d -dP -dp -dPp; do
		(cd $testroot/wt && got log $flags | grep -A2 '^ [MDmA]' | \
		    sed '/^--/d' > $testroot/stdout)

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

test_log_commit_keywords() {
	local testroot=$(test_init log_commit_keywords)
	local commit_time=`git_show_author_time $testroot/repo`
	local d=`date -u -r $commit_time +"%F"`

	set -- "$(git_show_head $testroot/repo)"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	for i in $(seq 16); do
		echo "alpha change $i" > "$testroot/wt/alpha"

		(cd "$testroot/wt" && got ci -m "commit number $i" > /dev/null)
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "commit failed unexpectedly" >&2
			test_done "$testroot" "$ret"
			return 1
		fi
		set -- "$@" "$(git_show_head $testroot/repo)"
	done

	for i in $(seq 16 -1 2); do
		printf '%s %.7s commit number %s\n' \
		    "$d" $(pop_idx $i $@) "$(( i-1 ))" \
		    >> $testroot/stdout.expected
	done

	got log -r "$testroot/repo" -s -cmaster:- -l15 > $testroot/stdout

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# request same set of commits now with log -x
	got log -r "$testroot/repo" -s -cmaster:- -xmaster:-15 > \
	    $testroot/stdout

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update -c:head:-8 > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > "$testroot/stdout.expected"

	for i in $(seq 9 -1 2); do
		printf '%s %.7s commit number %s\n' \
		    "$d" $(pop_idx $i $@) "$(( i-1 ))" \
		    >> $testroot/stdout.expected
	done
	printf '%s %.7s adding the test tree\n' "$d" $(pop_idx 1 $@) >> \
	    $testroot/stdout.expected

	(cd $testroot/wt && got log -s -c:base > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# from head to the base commit using -x
	printf '%s %-7s commit number 16\n' "$d" "master" > \
	    $testroot/stdout.expected
	for i in $(seq 16 -1 9); do
		printf '%s %.7s commit number %s\n' \
		    "$d" $(pop_idx $i $@) $(( i-1 )) \
		    >> $testroot/stdout.expected
	done

	(cd $testroot/wt && got log -s -c:head -x:base > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# if + modifier is too great, use HEAD commit
	printf '%s %-7s commit number %s\n' "$d" master 16 > \
	    $testroot/stdout.expected
	printf '%s %.7s commit number %s\n' "$d" $(pop_idx 16 $@) 15 >> \
	    $testroot/stdout.expected

	(cd $testroot/wt && got log -s -c:base:+20 -l2 > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# if - modifier is too great, use root commit
	printf '%s %.7s adding the test tree\n' "$d" $(pop_idx 1 $@) > \
	    $testroot/stdout.expected

	(cd $testroot/wt && got log -s -c:base:-10 > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got br -r "$testroot/repo" -c $(pop_idx 1 $@) base+

	printf '%s %.7s commit number 1\n' "$d" $(pop_idx 2 $@) > \
	    $testroot/stdout.expected

	(cd $testroot/wt && got log -s -cbase+:+ -l1 > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got br -r "$testroot/repo" -c $(pop_idx 3 $@) head-1

	printf '%s %.7s commit number 1\n' "$d" $(pop_idx 2 $@) > \
	    $testroot/stdout.expected

	(cd $testroot/wt && got log -s -chead-1:- -l1 > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got br -r "$testroot/repo" -c $(pop_idx 16 $@) base-1+2

	printf '%s %.7s commit number 12\n' "$d" $(pop_idx 13 $@) > \
	    $testroot/stdout.expected

	(cd $testroot/wt && got log -s -cbase-1+2:-3 -l1 > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: '::base:+': invalid commit keyword" > \
	    $testroot/stderr.expected

	(cd $testroot/wt && got log -c::base:+ 2> $testroot/stderr)

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: ':head:-:': invalid commit keyword" > \
	    $testroot/stderr.expected

	(cd $testroot/wt && got log -c:head:-: 2> $testroot/stderr)

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: 'master::+': invalid commit keyword" > \
	    $testroot/stderr.expected

	(cd $testroot/wt && got log -cmaster::+ 2> $testroot/stderr)

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: 'master:1+': invalid commit keyword" > \
	    $testroot/stderr.expected

	(cd $testroot/wt && got log -cmaster:1+ 2> $testroot/stderr)

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: ':base:-1:base:-1': invalid commit keyword" > \
	    $testroot/stderr.expected

	(cd $testroot/wt && got log -c:base:-1:base:-1 2> $testroot/stderr)

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: 'main:-main:-': invalid commit keyword" > \
	    $testroot/stderr.expected

	(cd $testroot/wt && got log -cmain:-main:- 2> $testroot/stderr)

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: ':base:*1': invalid commit keyword" > \
	    $testroot/stderr.expected

	(cd $testroot/wt && got log -c:base:*1 2> $testroot/stderr)

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: reference null not found" > $testroot/stderr.expected

	(cd $testroot/wt && got log -cnull:+ 2> $testroot/stderr)

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi

	test_done "$testroot" "$ret"
}

test_log_toposort() {
	local testroot=`test_init log_toposort`
	local commit0=`git_show_head $testroot/repo`
	local author_time0=`git_show_author_time $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo aaa > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'change alpha' >/dev/null)
	local commit1=`git_show_head $testroot/repo`
	local author_time1=`git_show_author_time $testroot/repo`

	got branch -r $testroot/repo -c $commit0 newbranch
	(cd $testroot/wt && got update -b newbranch > /dev/null)
	echo ddd > $testroot/wt/gamma/delta
	(cd $testroot/wt && got commit -m 'change delta' >/dev/null)
	local commit2=`git_show_branch_head $testroot/repo newbranch`
	local author_time2=`git_show_author_time $testroot/repo newbranch`

	echo zzz > $testroot/wt/epsilon/zeta
	(cd $testroot/wt && got commit -m 'change zeta' >/dev/null)
	local commit3=`git_show_head $testroot/repo`
	local author_time3=`git_show_author_time $testroot/repo newbranch`

	(cd $testroot/wt && got update -b master > /dev/null)
	(cd $testroot/wt && got merge newbranch > /dev/null)
	local merge_commit=`git_show_head $testroot/repo`
	local merge_time=`git_show_author_time $testroot/repo`

	local short_commit0=`trim_obj_id 7 $commit0`
	local short_commit1=`trim_obj_id 7 $commit1`
	local short_commit2=`trim_obj_id 7 $commit2`
	local short_commit3=`trim_obj_id 7 $commit3`

	d_0=`date -u -r $author_time0 +"%F"`
	d_1=`date -u -r $author_time1 +"%F"`
	d_2=`date -u -r $author_time2 +"%F"`
	d_3=`date -u -r $author_time3 +"%F"`
	d_m=`date -u -r $merge_time +"%F"`

	got log -r $testroot/repo -s -b -t > $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
$d_m master  merge refs/heads/newbranch into refs/heads/master
$d_1 $short_commit1 change alpha
$d_3 newbranch change zeta
$d_2 $short_commit2 change delta
$d_0 $short_commit0 adding the test tree
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}


test_parseargs "$@"
run_test test_log_in_repo
run_test test_log_in_bare_repo
run_test test_log_in_worktree
run_test test_log_in_worktree_with_path_prefix
run_test test_log_tag
run_test test_log_limit
run_test test_log_oneline
run_test test_log_patch_added_file
run_test test_log_nonexistent_path
run_test test_log_end_at_commit
run_test test_log_reverse_display
run_test test_log_in_worktree_different_repo
run_test test_log_changed_paths
run_test test_log_merge_commit_nonexistent_path
run_test test_log_submodule
run_test test_log_diffstat
run_test test_log_commit_keywords
run_test test_log_toposort
