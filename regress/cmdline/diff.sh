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

test_diff_basic() {
	local testroot=`test_init diff_basic`
	local head_rev=`git_show_head $testroot/repo`
	local alpha_blobid=`get_blob_id $testroot/repo "" alpha`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta >/dev/null)
	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)

	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $head_rev" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'alpha$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + alpha' >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified alpha' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'beta$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + /dev/null' >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-beta' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo 'file + new (mode 644)' >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# 'got diff' in a repository without any arguments is an error
	(cd $testroot/repo && got diff 2> $testroot/stderr)
	echo "got: no work tree found" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# 'got diff' in a repository with two arguments requires that
	# both named objects exist
	(cd $testroot/repo && got diff $head_rev foo 2> $testroot/stderr)
	echo "got: foo: object not found" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# diff non-existent path
	(cd $testroot/wt && got diff nonexistent > $testroot/stdout \
		2> $testroot/stderr)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: nonexistent: No such file or directory" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified zeta" > $testroot/wt/epsilon/zeta

	# diff several paths in a work tree
	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $head_rev" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'alpha$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + alpha' >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified alpha' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'beta$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + /dev/null' >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-beta' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i epsilon | grep 'zeta$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + epsilon/zeta' >> $testroot/stdout.expected
	echo '--- epsilon/zeta' >> $testroot/stdout.expected
	echo '+++ epsilon/zeta' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-zeta' >> $testroot/stdout.expected
	echo '+modified zeta' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo 'file + new (mode 644)' >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff new alpha epsilon beta > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# different order of arguments results in same output order
	(cd $testroot/wt && got diff alpha new epsilon beta \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# a branch 'new' should not collide with path 'new' if more
	# than two arguments are passed
	got br -r $testroot/repo -c master new > /dev/null
	(cd $testroot/wt && got diff new alpha epsilon beta \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Two arguments are interpreted as objects if a colliding path exists
	echo master > $testroot/wt/master
	(cd $testroot/wt && got add master > /dev/null)
	(cd $testroot/wt && got diff master new > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "diff refs/heads/master refs/heads/new" > $testroot/stdout.expected
	echo "commit - $head_rev" >> $testroot/stdout.expected
	echo "commit + $head_rev" >> $testroot/stdout.expected
	# diff between the branches is empty
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	# same without a work tree
	(cd $testroot/repo && got diff master new > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "diff refs/heads/master refs/heads/new" > $testroot/stdout.expected
	echo "commit - $head_rev" >> $testroot/stdout.expected
	echo "commit + $head_rev" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	# same with -r argument
	got diff -r $testroot/repo master new > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "diff refs/heads/master refs/heads/new" > $testroot/stdout.expected
	echo "commit - $head_rev" >> $testroot/stdout.expected
	echo "commit + $head_rev" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# -P can be used to force use of paths
	(cd $testroot/wt && got diff -P new master > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $head_rev" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo 'file + master (mode 644)' >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ master' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+master' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo 'file + new (mode 644)' >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# -P can only be used in a work tree
	got diff -r $testroot/repo -P new master 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "diff succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "got: -P option can only be used when diffing a work tree" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# a single argument which can be resolved to a path is not ambiguous
	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $head_rev" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo 'file + new (mode 644)' >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected
	(cd $testroot/wt && got diff new > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# diff with just one object ID argument results in
	# interpretation of argument as a path
	(cd $testroot/wt && got diff $head_rev 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "diff succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "got: $head_rev: No such file or directory" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# diff with more than two object arguments results in
	# interpretation of arguments as paths
	(cd $testroot/wt && got diff new $head_rev master \
		> $testroot/stout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "diff succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $head_rev" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo 'file + new (mode 644)' >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: $head_rev: No such file or directory" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		return 1
	fi

	# diff two blob ids
	(cd $testroot/wt && got commit -m 'edit' alpha >/dev/null)
	local alpha_new_blobid=`get_blob_id $testroot/repo "" alpha`
	(cd $testroot/wt && got diff $alpha_blobid $alpha_new_blobid) \
		> $testroot/diff
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<EOF >$testroot/diff.expected
blob - $alpha_blobid
blob + $alpha_new_blobid
--- $alpha_blobid
+++ $alpha_new_blobid
@@ -1 +1 @@
-alpha
+modified alpha
EOF

	cmp -s $testroot/diff.expected $testroot/diff
	ret=$?
	if [ $ret -ne 0 ]; then
		echo
		diff -u $testroot/diff.expected $testroot/diff
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_diff_shows_conflict() {
	local testroot=`test_init diff_shows_conflict 1`

	echo "1" > $testroot/repo/numbers
	echo "2" >> $testroot/repo/numbers
	echo "3" >> $testroot/repo/numbers
	echo "4" >> $testroot/repo/numbers
	echo "5" >> $testroot/repo/numbers
	echo "6" >> $testroot/repo/numbers
	echo "7" >> $testroot/repo/numbers
	echo "8" >> $testroot/repo/numbers
	git -C $testroot/repo add numbers
	git_commit $testroot/repo -m "added numbers file"
	local base_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	ed -s $testroot/repo/numbers <<-\EOF
	,s/2/22/
	,s/8/33/
	w
	EOF
	git_commit $testroot/repo -m "modified line 2"
	local head_rev=`git_show_head $testroot/repo`

	# modify lines 2 and 8 in conflicting ways
	ed -s $testroot/wt/numbers <<-\EOF
	,s/2/77/
	,s/8/88/
	w
	EOF

	echo "C  numbers" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: $head_rev" \
		>> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $head_rev" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'numbers$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + numbers' >> $testroot/stdout.expected
	echo '--- numbers' >> $testroot/stdout.expected
	echo '+++ numbers' >> $testroot/stdout.expected
	echo '@@ -1,8 +1,20 @@' >> $testroot/stdout.expected
	echo ' 1' >> $testroot/stdout.expected
	echo "+<<<<<<< merged change: commit $head_rev" \
		>> $testroot/stdout.expected
	echo ' 22' >> $testroot/stdout.expected
	echo "+||||||| 3-way merge base: commit $base_commit" \
		>> $testroot/stdout.expected
	echo '+2' >> $testroot/stdout.expected
	echo '+=======' >> $testroot/stdout.expected
	echo '+77' >> $testroot/stdout.expected
	echo '+>>>>>>>' >> $testroot/stdout.expected
	echo ' 3' >> $testroot/stdout.expected
	echo ' 4' >> $testroot/stdout.expected
	echo ' 5' >> $testroot/stdout.expected
	echo ' 6' >> $testroot/stdout.expected
	echo ' 7' >> $testroot/stdout.expected
	echo "+<<<<<<< merged change: commit $head_rev" \
		>> $testroot/stdout.expected
	echo ' 33' >> $testroot/stdout.expected
	echo "+||||||| 3-way merge base: commit $base_commit" \
		>> $testroot/stdout.expected
	echo '+8' >> $testroot/stdout.expected
	echo '+=======' >> $testroot/stdout.expected
	echo '+88' >> $testroot/stdout.expected
	echo '+>>>>>>>' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_diff_tag() {
	local testroot=`test_init diff_tag`
	local commit_id0=`git_show_head $testroot/repo`
	local tag1=1.0.0
	local tag2=2.0.0

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "changed alpha"
	local commit_id1=`git_show_head $testroot/repo`

	git -C $testroot/repo tag -m "test" $tag1

	echo "new file" > $testroot/repo/new
	git -C $testroot/repo add new
	git_commit $testroot/repo -m "new file"
	local commit_id2=`git_show_head $testroot/repo`

	git -C $testroot/repo tag -m "test" $tag2

	echo "diff $commit_id0 refs/tags/$tag1" > $testroot/stdout.expected
	echo "commit - $commit_id0" >> $testroot/stdout.expected
	echo "commit + $commit_id1" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id0 -i | grep 'alpha$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'alpha$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified alpha' >> $testroot/stdout.expected

	got diff -r $testroot/repo $commit_id0 $tag1 > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "diff refs/tags/$tag1 refs/tags/$tag2" > $testroot/stdout.expected
	echo "commit - $commit_id1" >> $testroot/stdout.expected
	echo "commit + $commit_id2" >> $testroot/stdout.expected
	echo "blob - /dev/null" >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i -c $commit_id2 | grep 'new$' | \
		cut -d' ' -f 1 | tr -d '\n' >> $testroot/stdout.expected
	echo " (mode 644)" >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected

	got diff -r $testroot/repo $tag1 $tag2 > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_diff_lightweight_tag() {
	local testroot=`test_init diff_tag`
	local commit_id0=`git_show_head $testroot/repo`
	local tag1=1.0.0
	local tag2=2.0.0

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "changed alpha"
	local commit_id1=`git_show_head $testroot/repo`

	git -C $testroot/repo tag $tag1

	echo "new file" > $testroot/repo/new
	git -C $testroot/repo add new
	git_commit $testroot/repo -m "new file"
	local commit_id2=`git_show_head $testroot/repo`

	git -C $testroot/repo tag $tag2

	echo "diff $commit_id0 refs/tags/$tag1" > $testroot/stdout.expected
	echo "commit - $commit_id0" >> $testroot/stdout.expected
	echo "commit + $commit_id1" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id0 -i | grep 'alpha$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'alpha$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified alpha' >> $testroot/stdout.expected

	got diff -r $testroot/repo $commit_id0 $tag1 > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "diff refs/tags/$tag1 refs/tags/$tag2" > $testroot/stdout.expected
	echo "commit - $commit_id1" >> $testroot/stdout.expected
	echo "commit + $commit_id2" >> $testroot/stdout.expected
	echo "blob - /dev/null" >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i -c $commit_id2 | grep 'new$' | \
		cut -d' ' -f 1 | tr -d '\n' >> $testroot/stdout.expected
	echo " (mode 644)" >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected

	got diff -r $testroot/repo $tag1 $tag2 > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_diff_ignore_whitespace() {
	local testroot=`test_init diff_ignore_whitespace`
	local commit_id0=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha   " > $testroot/wt/alpha

	(cd $testroot/wt && got diff -w > $testroot/stdout)

	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $commit_id0" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id0 -i | grep 'alpha$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo 'file + alpha' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_diff_submodule_of_same_repo() {
	local testroot=`test_init diff_submodule_of_same_repo`

	git -C $testroot clone -q repo repo2 >/dev/null
	git -C $testroot/repo -c protocol.file.allow=always \
		submodule -q add ../repo2
	git -C $testroot/repo commit -q -m 'adding submodule'

	epsilon_id=$(got tree -r $testroot/repo -i | grep 'epsilon/$' | \
		cut -d ' ' -f 1)
	submodule_id=$(got tree -r $testroot/repo -i | grep 'repo2\$$' | \
		cut -d ' ' -f 1)

	# Attempt a (nonsensical) diff between a tree object and a submodule.
	# Currently fails with "wrong type of object" error
	got diff -r $testroot/repo $epsilon_id $submodule_id \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "diff command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "got: wrong type of object" > $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_diff_symlinks_in_work_tree() {
	local testroot=`test_init diff_symlinks_in_work_tree`

	(cd $testroot/repo && ln -s alpha alpha.link)
	(cd $testroot/repo && ln -s epsilon epsilon.link)
	(cd $testroot/repo && ln -s /etc/passwd passwd.link)
	(cd $testroot/repo && ln -s ../beta epsilon/beta.link)
	(cd $testroot/repo && ln -s nonexistent nonexistent.link)
	(cd $testroot/repo && ln -s .got/foo dotgotfoo.link)
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "add symlinks"
	local commit_id1=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && ln -sf beta alpha.link)
	(cd $testroot/wt && rm epsilon.link && ln -s gamma epsilon.link)
	(cd $testroot/wt && ln -sf ../gamma/delta epsilon/beta.link)
	echo -n '.got/bar' > $testroot/wt/dotgotfoo.link
	(cd $testroot/wt && got rm nonexistent.link > /dev/null)
	(cd $testroot/wt && ln -sf epsilon/zeta zeta.link)
	(cd $testroot/wt && got add zeta.link > /dev/null)
	(cd $testroot/wt && got diff > $testroot/stdout)

	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $commit_id1" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id1 -i | \
		grep 'alpha.link@ -> alpha$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo 'file + alpha.link' >> $testroot/stdout.expected
	echo '--- alpha.link' >> $testroot/stdout.expected
	echo '+++ alpha.link' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo '+beta' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id1 -i | \
		grep 'dotgotfoo.link@ -> .got/foo$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo 'file + dotgotfoo.link' >> $testroot/stdout.expected
	echo '--- dotgotfoo.link' >> $testroot/stdout.expected
	echo '+++ dotgotfoo.link' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-.got/foo' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo '+.got/bar' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id1 -i epsilon | \
		grep 'beta.link@ -> ../beta$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo 'file + epsilon/beta.link' >> $testroot/stdout.expected
	echo '--- epsilon/beta.link' >> $testroot/stdout.expected
	echo '+++ epsilon/beta.link' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-../beta' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo '+../gamma/delta' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id1 -i | \
		grep 'epsilon.link@ -> epsilon$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo 'file + epsilon.link' >> $testroot/stdout.expected
	echo '--- epsilon.link' >> $testroot/stdout.expected
	echo '+++ epsilon.link' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-epsilon' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo '+gamma' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id1 -i | \
		grep 'nonexistent.link@ -> nonexistent$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo 'file + /dev/null' >> $testroot/stdout.expected
	echo '--- nonexistent.link' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-nonexistent' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo 'file + zeta.link (mode 120000)' >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ zeta.link' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+epsilon/zeta' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_diff_symlinks_in_repo() {
	local testroot=`test_init diff_symlinks_in_repo`

	(cd $testroot/repo && ln -s alpha alpha.link)
	(cd $testroot/repo && ln -s epsilon epsilon.link)
	(cd $testroot/repo && ln -s /etc/passwd passwd.link)
	(cd $testroot/repo && ln -s ../beta epsilon/beta.link)
	(cd $testroot/repo && ln -s nonexistent nonexistent.link)
	(cd $testroot/repo && ln -s .got/foo dotgotfoo.link)
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "add symlinks"
	local commit_id1=`git_show_head $testroot/repo`

	(cd $testroot/repo && ln -sf beta alpha.link)
	(cd $testroot/repo && rm epsilon.link && ln -s gamma epsilon.link)
	(cd $testroot/repo && ln -sf ../gamma/delta epsilon/beta.link)
	(cd $testroot/repo && ln -sf .got/bar $testroot/repo/dotgotfoo.link)
	git -C $testroot/repo rm -q nonexistent.link
	(cd $testroot/repo && ln -sf epsilon/zeta zeta.link)
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "change symlinks"
	local commit_id2=`git_show_head $testroot/repo`

	got diff -r $testroot/repo $commit_id1 $commit_id2 > $testroot/stdout

	echo "diff $commit_id1 $commit_id2" > $testroot/stdout.expected
	echo "commit - $commit_id1" >> $testroot/stdout.expected
	echo "commit + $commit_id2" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id1 -i | \
		grep 'alpha.link@ -> alpha$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id2 -i | \
		grep 'alpha.link@ -> beta$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo '--- alpha.link' >> $testroot/stdout.expected
	echo '+++ alpha.link' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo '+beta' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id1 -i | \
		grep 'dotgotfoo.link@ -> .got/foo$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id2 -i | \
		grep 'dotgotfoo.link@ -> .got/bar$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo '--- dotgotfoo.link' >> $testroot/stdout.expected
	echo '+++ dotgotfoo.link' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-.got/foo' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo '+.got/bar' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id1 -i epsilon | \
		grep 'beta.link@ -> ../beta$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id2 -i epsilon | \
		grep 'beta.link@ -> ../gamma/delta$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo '--- epsilon/beta.link' >> $testroot/stdout.expected
	echo '+++ epsilon/beta.link' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-../beta' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo '+../gamma/delta' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id1 -i | \
		grep 'epsilon.link@ -> epsilon$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id2 -i | \
		grep 'epsilon.link@ -> gamma$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo '--- epsilon.link' >> $testroot/stdout.expected
	echo '+++ epsilon.link' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-epsilon' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo '+gamma' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id1 -i | \
		grep 'nonexistent.link@ -> nonexistent$' | \
		cut -d' ' -f 1 | sed -e 's/$/ (mode 120000)/' \
		>> $testroot/stdout.expected
	echo 'blob + /dev/null' >> $testroot/stdout.expected
	echo '--- nonexistent.link' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-nonexistent' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -c $commit_id2 -i | \
		grep 'zeta.link@ -> epsilon/zeta$' | \
		cut -d' ' -f 1 | sed -e 's/$/ (mode 120000)/' \
		>> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ zeta.link' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+epsilon/zeta' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_diff_binary_files() {
	local testroot=`test_init diff_binary_files`
	local head_rev=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	printf '\377\377\0\0\377\377\0\0' > $testroot/wt/foo
	(cd $testroot/wt && got add foo >/dev/null)

	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $head_rev" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo 'file + foo (mode 644)' >> $testroot/stdout.expected
	echo "Binary files /dev/null and foo differ" \
		>> $testroot/stdout.expected

	(cd $testroot/wt && got diff > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -a -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $head_rev" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo 'file + foo (mode 644)' >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ foo' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	printf '+\377\377\0\0\377\377\0\0\n' >> $testroot/stdout.expected
	printf '\\ No newline at end of file\n' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff -a > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -a -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got commit -m 'add binary file' > /dev/null)
	local head_rev=`git_show_head $testroot/repo`

	printf '\377\200\0\0\377\200\0\0' > $testroot/wt/foo

	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $head_rev" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'foo$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + foo' >> $testroot/stdout.expected
	echo '--- foo' >> $testroot/stdout.expected
	echo '+++ foo' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	printf -- '-\377\377\0\0\377\377\0\0\n' >> $testroot/stdout.expected
	printf '\\ No newline at end of file\n' >> $testroot/stdout.expected
	printf '+\377\200\0\0\377\200\0\0\n' >> $testroot/stdout.expected
	printf '\\ No newline at end of file\n' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff -a > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -a -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_diff_commits() {
	local testroot=`test_init diff_commits`
	local commit_id0=`git_show_head $testroot/repo`
	local alpha_id0=`get_blob_id $testroot/repo "" alpha`
	local beta_id0=`get_blob_id $testroot/repo "" beta`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta >/dev/null)
	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)
	(cd $testroot/wt && got commit -m 'committing changes' >/dev/null)
	local commit_id1=`git_show_head $testroot/repo`

	alpha_id1=`get_blob_id $testroot/repo "" alpha`
	new_id1=`get_blob_id $testroot/repo "" new`

	echo "diff $commit_id0 refs/heads/master" > $testroot/stdout.expected
	echo "commit - $commit_id0" >> $testroot/stdout.expected
	echo "commit + $commit_id1" >> $testroot/stdout.expected
	echo "blob - $alpha_id0" >> $testroot/stdout.expected
	echo "blob + $alpha_id1" >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified alpha' >> $testroot/stdout.expected
	echo "blob - $beta_id0 (mode 644)" >> $testroot/stdout.expected
	echo 'blob + /dev/null' >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-beta' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo "blob + $new_id1 (mode 644)" >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff -c master > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# same diff with explicit parent commit ID
	(cd $testroot/wt && got diff -c $commit_id0 -c master \
		> $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# same diff with commit object IDs
	echo "diff $commit_id0 $commit_id1" > $testroot/stdout.expected
	echo "commit - $commit_id0" >> $testroot/stdout.expected
	echo "commit + $commit_id1" >> $testroot/stdout.expected
	echo "blob - $alpha_id0" >> $testroot/stdout.expected
	echo "blob + $alpha_id1" >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified alpha' >> $testroot/stdout.expected
	echo "blob - $beta_id0 (mode 644)" >> $testroot/stdout.expected
	echo 'blob + /dev/null' >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-beta' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo "blob + $new_id1 (mode 644)" >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected
	(cd $testroot/wt && got diff -c $commit_id0 -c $commit_id1 \
		> $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# same diff, filtered by paths
	echo "diff $commit_id0 $commit_id1" > $testroot/stdout.expected
	echo "commit - $commit_id0" >> $testroot/stdout.expected
	echo "commit + $commit_id1" >> $testroot/stdout.expected
	echo "blob - $alpha_id0" >> $testroot/stdout.expected
	echo "blob + $alpha_id1" >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified alpha' >> $testroot/stdout.expected
	(cd $testroot/repo && got diff -c $commit_id0 -c $commit_id1 alpha \
		> $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	# same in a work tree
	(cd $testroot/wt && got diff -c $commit_id0 -c $commit_id1 alpha \
		> $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "diff $commit_id0 $commit_id1" > $testroot/stdout.expected
	echo "commit - $commit_id0" >> $testroot/stdout.expected
	echo "commit + $commit_id1" >> $testroot/stdout.expected
	echo "blob - $beta_id0 (mode 644)" >> $testroot/stdout.expected
	echo 'blob + /dev/null' >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-beta' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo "blob + $new_id1 (mode 644)" >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected
	(cd $testroot/repo && got diff -c $commit_id0 -c $commit_id1 \
		beta new > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# more than two -c options are not allowed
	(cd $testroot/repo && got diff -c $commit_id0 -c $commit_id1 -c foo \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "diff succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "got: too many -c options used" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# use of -c options implies a repository diff; use with -P is an error
	(cd $testroot/wt && got diff -c $commit_id0 -c $commit_id1 -P foo \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "diff succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "got: -P option can only be used when diffing a work tree" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# use of -c options implies a repository diff; use with -s is an error
	(cd $testroot/wt && got diff -c $commit_id0 -c $commit_id1 -s foo \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "diff succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "got: -s option can only be used when diffing a work tree" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# three arguments imply use of path filtering (repository case)
	(cd $testroot/repo && got diff $commit_id0 $commit_id1 foo \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "diff succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "got: specified paths cannot be resolved: no work tree found" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# three arguments imply use of path filtering (work tree case)
	(cd $testroot/wt && got diff $commit_id0 master foo \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "diff succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "got: $commit_id0: No such file or directory" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_diff_ignored_file() {
	local testroot=`test_init diff_ignored_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 1 > $testroot/wt/number
	(cd $testroot/wt && got add number >/dev/null)
	(cd $testroot/wt && got commit -m 'add number' >/dev/null)

	echo "**/number" > $testroot/wt/.gitignore

	echo 2 > $testroot/wt/number
	(cd $testroot/wt && got diff number | sed '1,/^@@/d' > $testroot/stdout)

	echo "-1"  > $testroot/stdout.expected
	echo "+2" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_diff_crlf() {
	local testroot=`test_init diff_crlf`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" $ret
		return 1
	fi

	printf 'one\r\ntwo\r\nthree\r\n' > $testroot/wt/crlf
	(cd $testroot/wt && got add crlf && got commit -m +crlf) >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" $ret
		return 1
	fi

	printf 'one\r\ntwain\r\nthree\r\n' > $testroot/wt/crlf
	(cd $testroot/wt && got diff | sed -n '/^---/,$l' > $testroot/stdout)
	cat <<\EOF > $testroot/stdout.expected
--- crlf$
+++ crlf$
@@ -1,3 +1,3 @@$
 one\r$
-two\r$
+twain\r$
 three\r$
EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" $ret
}

test_diff_worktree_newfile_xbit() {
	local testroot=`test_init diff_worktree_newfile_xbit`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" $ret
		return 1
	fi

	echo xfile > $testroot/wt/xfile
	chmod +x $testroot/wt/xfile
	(cd $testroot/wt && got add xfile) > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" $ret
		return 1
	fi
	(cd $testroot/wt && got diff) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" $ret
		return 1
	fi

	local commit_id=`git_show_head $testroot/repo`
	cat <<EOF > $testroot/stdout.expected
diff $testroot/wt
commit - $commit_id
path + $testroot/wt
blob - /dev/null
file + xfile (mode 755)
--- /dev/null
+++ xfile
@@ -0,0 +1 @@
+xfile
EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "failed to record mode 755"
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" $ret
}

test_diff_commit_diffstat() {
	local testroot=`test_init diff_commit_diffstat`
	local commit_id0=`git_show_head $testroot/repo`
	local alpha_id0=`get_blob_id $testroot/repo "" alpha`
	local beta_id0=`get_blob_id $testroot/repo "" beta`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta >/dev/null)
	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)
	(cd $testroot/wt && got commit -m 'committing changes' >/dev/null)
	local commit_id1=`git_show_head $testroot/repo`

	local alpha_id1=`get_blob_id $testroot/repo "" alpha`
	local new_id1=`get_blob_id $testroot/repo "" new`

	cat <<EOF >$testroot/stdout.expected
diffstat $commit_id0 refs/heads/master
 M  alpha  |  1+  1-
 D  beta   |  0+  1-
 A  new    |  1+  0-

3 files changed, 2 insertions(+), 2 deletions(-)

EOF

	echo "diff $commit_id0 refs/heads/master" >> $testroot/stdout.expected
	echo "commit - $commit_id0" >> $testroot/stdout.expected
	echo "commit + $commit_id1" >> $testroot/stdout.expected
	echo "blob - $alpha_id0" >> $testroot/stdout.expected
	echo "blob + $alpha_id1" >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified alpha' >> $testroot/stdout.expected
	echo "blob - $beta_id0 (mode 644)" >> $testroot/stdout.expected
	echo 'blob + /dev/null' >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-beta' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo "blob + $new_id1 (mode 644)" >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff -d -c master > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# same diffstat with explicit parent commit ID
	(cd $testroot/wt && got diff -d -c $commit_id0 -c master \
		> $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<EOF >$testroot/stdout.expected
diffstat $commit_id0 $commit_id1
 M  alpha  |  1+  1-
 D  beta   |  0+  1-
 A  new    |  1+  0-

3 files changed, 2 insertions(+), 2 deletions(-)

EOF

	# same diffstat with commit object IDs
	echo "diff $commit_id0 $commit_id1" >> $testroot/stdout.expected
	echo "commit - $commit_id0" >> $testroot/stdout.expected
	echo "commit + $commit_id1" >> $testroot/stdout.expected
	echo "blob - $alpha_id0" >> $testroot/stdout.expected
	echo "blob + $alpha_id1" >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified alpha' >> $testroot/stdout.expected
	echo "blob - $beta_id0 (mode 644)" >> $testroot/stdout.expected
	echo 'blob + /dev/null' >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-beta' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo "blob + $new_id1 (mode 644)" >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected
	(cd $testroot/wt && got diff -d -c $commit_id0 -c $commit_id1 \
		> $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<EOF >$testroot/stdout.expected
diffstat $commit_id0 $commit_id1
 M  alpha  |  1+  1-

1 file changed, 1 insertion(+), 1 deletion(-)

EOF

	# same diffstat filtered by path "alpha"
	echo "diff $commit_id0 $commit_id1" >> $testroot/stdout.expected
	echo "commit - $commit_id0" >> $testroot/stdout.expected
	echo "commit + $commit_id1" >> $testroot/stdout.expected
	echo "blob - $alpha_id0" >> $testroot/stdout.expected
	echo "blob + $alpha_id1" >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified alpha' >> $testroot/stdout.expected
	(cd $testroot/repo && got diff -d -c $commit_id0 -c $commit_id1 alpha \
		> $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	# same diffstat in work tree
	(cd $testroot/wt && got diff -d -c $commit_id0 -c $commit_id1 alpha \
		> $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat <<EOF >$testroot/stdout.expected
diffstat $commit_id0 $commit_id1
 D  beta  |  0+  1-
 A  new   |  1+  0-

2 files changed, 1 insertion(+), 1 deletion(-)

EOF

	# same diffstat filtered by paths "beta" and "new"
	echo "diff $commit_id0 $commit_id1" >> $testroot/stdout.expected
	echo "commit - $commit_id0" >> $testroot/stdout.expected
	echo "commit + $commit_id1" >> $testroot/stdout.expected
	echo "blob - $beta_id0 (mode 644)" >> $testroot/stdout.expected
	echo 'blob + /dev/null' >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-beta' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo "blob + $new_id1 (mode 644)" >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected
	(cd $testroot/repo && got diff -d -c $commit_id0 -c $commit_id1 \
		beta new > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_diff_worktree_diffstat() {
	local testroot=`test_init diff_worktree_diffstat`
	local head_rev=`git_show_head $testroot/repo`
	local alpha_blobid=`get_blob_id $testroot/repo "" alpha`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta >/dev/null)
	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)

	cat <<EOF >$testroot/stdout.expected
diffstat $testroot/wt
 M  alpha  |  1+  1-
 D  beta   |  0+  1-
 A  new    |  1+  0-

3 files changed, 2 insertions(+), 2 deletions(-)

EOF

	echo "diff $testroot/wt" >> $testroot/stdout.expected
	echo "commit - $head_rev" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'alpha$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + alpha' >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified alpha' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'beta$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + /dev/null' >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-beta' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo 'file + new (mode 644)' >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff -d > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified zeta" > $testroot/wt/epsilon/zeta

	cat <<EOF >$testroot/stdout.expected
diffstat $testroot/wt
 M  alpha         |  1+  1-
 D  beta          |  0+  1-
 M  epsilon/zeta  |  1+  1-
 A  new           |  1+  0-

4 files changed, 3 insertions(+), 3 deletions(-)

EOF

	# specify paths to diffstat
	echo "diff $testroot/wt" >> $testroot/stdout.expected
	echo "commit - $head_rev" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'alpha$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + alpha' >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified alpha' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'beta$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + /dev/null' >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-beta' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i epsilon | grep 'zeta$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + epsilon/zeta' >> $testroot/stdout.expected
	echo '--- epsilon/zeta' >> $testroot/stdout.expected
	echo '+++ epsilon/zeta' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-zeta' >> $testroot/stdout.expected
	echo '+modified zeta' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo 'file + new (mode 644)' >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff -d new alpha epsilon beta > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# same diff irrespective of argument order
	(cd $testroot/wt && got diff -d alpha new epsilon beta \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# force paths with -P
	echo master > $testroot/wt/master
	(cd $testroot/wt && got add master > /dev/null)
	(cd $testroot/wt && got diff -d -P new master > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cat <<EOF >$testroot/stdout.expected
diffstat $testroot/wt
 A  master  |  1+  0-
 A  new     |  1+  0-

2 files changed, 2 insertions(+), 0 deletions(-)

EOF

	echo "diff $testroot/wt" >> $testroot/stdout.expected
	echo "commit - $head_rev" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo 'file + master (mode 644)' >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ master' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+master' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo 'file + new (mode 644)' >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ new' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# diff two blob ids
	(cd $testroot/wt && got commit -m 'edit' alpha >/dev/null)
	local alpha_new_blobid=`get_blob_id $testroot/repo "" alpha`
	(cd $testroot/wt && got diff -d $alpha_blobid $alpha_new_blobid) \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	short_alpha_id=$(printf '%.10s' $alpha_blobid)
	short_alpha_new_id=$(printf '%.10s' $alpha_new_blobid)
	cat <<EOF >$testroot/stdout.expected
diffstat $alpha_blobid $alpha_new_blobid
 M  $short_alpha_id -> $short_alpha_new_id  |  1+  1-

1 file changed, 1 insertion(+), 1 deletion(-)

blob - $alpha_blobid
blob + $alpha_new_blobid
--- $alpha_blobid
+++ $alpha_new_blobid
@@ -1 +1 @@
-alpha
+modified alpha
EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_diff_file_to_dir() {
	local testroot=`test_init diff_file_to_dir`
	local commit_id0=`git_show_head $testroot/repo`
	local alpha_blobid=`get_blob_id $testroot/repo "" alpha`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	git_rm $testroot/repo alpha
	mkdir $testroot/repo/alpha
	echo eta > $testroot/repo/alpha/eta
	git -C $testroot/repo add alpha/eta
	git_commit $testroot/repo -m "changed alpha into directory"
	local commit_id1=`git_show_head $testroot/repo`
	local alpha_eta_blobid=`get_blob_id $testroot/repo alpha eta`

	cat <<EOF >$testroot/stdout.expected
diff $commit_id0 $commit_id1
commit - $commit_id0
commit + $commit_id1
blob - $alpha_blobid (mode 644)
blob + /dev/null
--- alpha
+++ /dev/null
@@ -1 +0,0 @@
-alpha
blob - /dev/null
blob + $alpha_eta_blobid (mode 644)
--- /dev/null
+++ alpha/eta
@@ -0,0 +1 @@
+eta
EOF
	got diff -r $testroot/repo $commit_id0 $commit_id1 > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	local author_time=`git_show_author_time $testroot/repo`
	d=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	cat <<EOF >$testroot/stdout.expected
-----------------------------------------------
commit $commit_id1 (master)
from: $GOT_AUTHOR
date: $d
 
 changed alpha into directory
 
 D  alpha
 A  alpha/eta

EOF

	got log -P -r $testroot/repo -l1 -c $commit_id1 > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_diff_dir_to_file() {
	local testroot=`test_init diff_file_to_dir`
	local commit_id0=`git_show_head $testroot/repo`
	local epsilon_zeta_blobid=`get_blob_id $testroot/repo epsilon zeta`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	git_rmdir $testroot/repo epsilon
	echo epsilon > $testroot/repo/epsilon
	git -C $testroot/repo add epsilon
	git_commit $testroot/repo -m "changed epsilon into file"
	local commit_id1=`git_show_head $testroot/repo`
	local epsilon_blobid=`get_blob_id $testroot/repo "" epsilon`

	cat <<EOF >$testroot/stdout.expected
diff $commit_id0 $commit_id1
commit - $commit_id0
commit + $commit_id1
blob - $epsilon_zeta_blobid (mode 644)
blob + /dev/null
--- epsilon/zeta
+++ /dev/null
@@ -1 +0,0 @@
-zeta
blob - /dev/null
blob + $epsilon_blobid (mode 644)
--- /dev/null
+++ epsilon
@@ -0,0 +1 @@
+epsilon
EOF
	got diff -r $testroot/repo $commit_id0 $commit_id1 > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	local author_time=`git_show_author_time $testroot/repo`
	d=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	cat <<EOF >$testroot/stdout.expected
-----------------------------------------------
commit $commit_id1 (master)
from: $GOT_AUTHOR
date: $d
 
 changed epsilon into file
 
 D  epsilon/zeta
 A  epsilon

EOF

	got log -P -r $testroot/repo -l1 -c $commit_id1 > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_diff_path_in_root_commit() {
	local testroot=`test_init diff_path_in_root_commit`
	local commit_id=`git_show_head $testroot/repo`
	local alpha_blobid=`get_blob_id $testroot/repo "" alpha`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff -c $commit_id alpha > $testroot/stdout)

	cat <<EOF >$testroot/stdout.expected
diff /dev/null $commit_id
commit - /dev/null
commit + $commit_id
blob - /dev/null
blob + $alpha_blobid (mode 644)
--- /dev/null
+++ alpha
@@ -0,0 +1 @@
+alpha
EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# diff non-existent path
	(cd $testroot/wt && got diff -c $commit_id nonexistent \
		> $testroot/stdout 2> $testroot/stderr)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: nonexistent: no such entry found in tree" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_diff_commit_keywords() {
	local testroot=`test_init diff_commit_keywords`
	local repo="$testroot/repo"
	local wt="$testroot/wt"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	set -- "$(git_show_head $repo)"
	local alpha_ids="$(get_blob_id "$repo" "" alpha)"
	local beta_ids="$(get_blob_id "$repo" "" beta)"

	for i in `seq 8`; do
		if [ $(( i % 2 )) -eq 0 ]; then
			echo "alpha change $i" > "$testroot/wt/alpha"
		else
			echo "beta change $i" > "$testroot/wt/beta"
		fi

		(cd "$testroot/wt" && got ci -m "commit number $i" > /dev/null)
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "commit failed unexpectedly" >&2
			test_done "$testroot" "$ret"
			return 1
		fi

		if [ $(( i % 2 )) -eq 0 ]; then
			alpha_ids="$alpha_ids $(get_blob_id "$repo" "" alpha)"
		else
			beta_ids="$beta_ids $(get_blob_id "$repo" "" beta)"
		fi

		set -- "$@" "$(git_show_head $repo)"
	done

	echo "diff $(pop_idx 7 $@) $(pop_idx 8 $@)" > \
	    $testroot/stdout.expected
	echo "commit - $(pop_idx 7 $@)" >> $testroot/stdout.expected
	echo "commit + $(pop_idx 8 $@)" >> $testroot/stdout.expected
	echo "blob - $(pop_idx 4 $beta_ids)" >> $testroot/stdout.expected
	echo "blob + $(pop_idx 5 $beta_ids)" >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ beta' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-beta change 5' >> $testroot/stdout.expected
	echo '+beta change 7' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff -cmaster:- > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update -c:head:-6 > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "diff $(pop_idx 1 $@) $(pop_idx 2 $@)" > \
	    $testroot/stdout.expected
	echo "commit - $(pop_idx 1 $@)" >> $testroot/stdout.expected
	echo "commit + $(pop_idx 2 $@)" >> $testroot/stdout.expected
	echo "blob - $(pop_idx 1 $beta_ids)" >> $testroot/stdout.expected
	echo "blob + $(pop_idx 2 $beta_ids)" >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ beta' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-beta' >> $testroot/stdout.expected
	echo '+beta change 1' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff -c:base:- > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "diff $(pop_idx 3 $@) $(pop_idx 4 $@)" > \
	    $testroot/stdout.expected
	echo "commit - $(pop_idx 3 $@)" >> $testroot/stdout.expected
	echo "commit + $(pop_idx 4 $@)" >> $testroot/stdout.expected
	echo "blob - $(pop_idx 2 $beta_ids)" >> $testroot/stdout.expected
	echo "blob + $(pop_idx 3 $beta_ids)" >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ beta' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-beta change 1' >> $testroot/stdout.expected
	echo '+beta change 3' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff -c:base:+ > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# if modifier extends beyond HEAD, we should use HEAD ref
	echo "diff $(pop_idx 8 $@) $(pop_idx 9 $@)" > \
	    $testroot/stdout.expected
	echo "commit - $(pop_idx 8 $@)" >> $testroot/stdout.expected
	echo "commit + $(pop_idx 9 $@)" >> $testroot/stdout.expected
	echo "blob - $(pop_idx 4 $alpha_ids)" >> $testroot/stdout.expected
	echo "blob + $(pop_idx 5 $alpha_ids)" >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha change 6' >> $testroot/stdout.expected
	echo '+alpha change 8' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff -c:base:+20 > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "diff $(pop_idx 3 $@) $(pop_idx 9 $@)" > \
	    $testroot/stdout.expected
	echo "commit - $(pop_idx 3 $@)" >> $testroot/stdout.expected
	echo "commit + $(pop_idx 9 $@)" >> $testroot/stdout.expected
	echo "blob - $(pop_idx 2 $alpha_ids)" >> $testroot/stdout.expected
	echo "blob + $(pop_idx 5 $alpha_ids)" >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha change 2' >> $testroot/stdout.expected
	echo '+alpha change 8' >> $testroot/stdout.expected
	echo "blob - $(pop_idx 2 $beta_ids)" >> $testroot/stdout.expected
	echo "blob + $(pop_idx 5 $beta_ids)" >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ beta' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-beta change 1' >> $testroot/stdout.expected
	echo '+beta change 7' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff -c:base -c:head > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "diff $(pop_idx 6 $@) $(pop_idx 8 $@)" > \
	    $testroot/stdout.expected
	echo "commit - $(pop_idx 6 $@)" >> $testroot/stdout.expected
	echo "commit + $(pop_idx 8 $@)" >> $testroot/stdout.expected
	echo "blob - $(pop_idx 3 $alpha_ids)" >> $testroot/stdout.expected
	echo "blob + $(pop_idx 4 $alpha_ids)" >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha change 4' >> $testroot/stdout.expected
	echo '+alpha change 6' >> $testroot/stdout.expected
	echo "blob - $(pop_idx 4 $beta_ids)" >> $testroot/stdout.expected
	echo "blob + $(pop_idx 5 $beta_ids)" >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ beta' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-beta change 5' >> $testroot/stdout.expected
	echo '+beta change 7' >> $testroot/stdout.expected

	got diff -r "$testroot/repo" -cmaster:-3 -c:head:-1 > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "diff failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: '-c :base' requires work tree" > "$testroot/stderr.expected"

	got diff -r "$testroot/repo" -c:base -c:head 2> $testroot/stderr

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_diff_basic
run_test test_diff_shows_conflict
run_test test_diff_tag				sha256-ok
run_test test_diff_lightweight_tag		sha256-ok
run_test test_diff_ignore_whitespace
run_test test_diff_submodule_of_same_repo	sha256-ok
run_test test_diff_symlinks_in_work_tree
run_test test_diff_symlinks_in_repo		sha256-ok
run_test test_diff_binary_files
run_test test_diff_commits
run_test test_diff_ignored_file
run_test test_diff_crlf
run_test test_diff_worktree_newfile_xbit
run_test test_diff_commit_diffstat
run_test test_diff_worktree_diffstat
run_test test_diff_file_to_dir
run_test test_diff_dir_to_file
run_test test_diff_path_in_root_commit
run_test test_diff_commit_keywords
