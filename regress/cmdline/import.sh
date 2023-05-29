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

test_import_basic() {
	local testname=import_basic
	local testroot=`mktemp -d \
	    "$GOT_TEST_ROOT/got-test-$testname-XXXXXXXXXX"`

	gotadmin init $testroot/repo

	mkdir $testroot/tree
	make_test_tree $testroot/tree

	got import -m 'init' -r $testroot/repo $testroot/tree \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	local head_commit=`git_show_head $testroot/repo`
	echo "A  $testroot/tree/gamma/delta" > $testroot/stdout.expected
	echo "A  $testroot/tree/epsilon/zeta" >> $testroot/stdout.expected
	echo "A  $testroot/tree/alpha" >> $testroot/stdout.expected
	echo "A  $testroot/tree/beta" >> $testroot/stdout.expected
	echo "Created branch refs/heads/main with commit $head_commit" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && got log -p | grep -v ^date: > $testroot/stdout)

	id_alpha=`get_blob_id $testroot/repo "" alpha`
	id_beta=`get_blob_id $testroot/repo "" beta`
	id_zeta=`get_blob_id $testroot/repo epsilon zeta`
	id_delta=`get_blob_id $testroot/repo gamma delta`
	tree_id=`(cd $testroot/repo && got cat $head_commit | \
		grep ^tree | cut -d ' ' -f 2)`

	echo "-----------------------------------------------" \
		> $testroot/stdout.expected
	echo "commit $head_commit (main)" >> $testroot/stdout.expected
	echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo " init" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo "diff /dev/null $head_commit" >> $testroot/stdout.expected
	echo "commit - /dev/null" >> $testroot/stdout.expected
	echo "commit + $head_commit" >> $testroot/stdout.expected
	echo "blob - /dev/null" >> $testroot/stdout.expected
	echo "blob + $id_alpha (mode 644)" >> $testroot/stdout.expected
	echo "--- /dev/null" >> $testroot/stdout.expected
	echo "+++ alpha" >> $testroot/stdout.expected
	echo "@@ -0,0 +1 @@" >> $testroot/stdout.expected
	echo "+alpha" >> $testroot/stdout.expected
	echo "blob - /dev/null" >> $testroot/stdout.expected
	echo "blob + $id_beta (mode 644)" >> $testroot/stdout.expected
	echo "--- /dev/null" >> $testroot/stdout.expected
	echo "+++ beta" >> $testroot/stdout.expected
	echo "@@ -0,0 +1 @@" >> $testroot/stdout.expected
	echo "+beta" >> $testroot/stdout.expected
	echo "blob - /dev/null" >> $testroot/stdout.expected
	echo "blob + $id_zeta (mode 644)" >> $testroot/stdout.expected
	echo "--- /dev/null" >> $testroot/stdout.expected
	echo "+++ epsilon/zeta" >> $testroot/stdout.expected
	echo "@@ -0,0 +1 @@" >> $testroot/stdout.expected
	echo "+zeta" >> $testroot/stdout.expected
	echo "blob - /dev/null" >> $testroot/stdout.expected
	echo "blob + $id_delta (mode 644)" >> $testroot/stdout.expected
	echo "--- /dev/null" >> $testroot/stdout.expected
	echo "+++ gamma/delta" >> $testroot/stdout.expected
	echo "@@ -0,0 +1 @@" >> $testroot/stdout.expected
	echo "+delta" >> $testroot/stdout.expected
	echo "" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "A  $testroot/wt/alpha" > $testroot/stdout.expected
	echo "A  $testroot/wt/beta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/epsilon/zeta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/gamma/delta" >> $testroot/stdout.expected
	echo "Checked out refs/heads/main: $head_commit" \
		>> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected

	got checkout $testroot/repo $testroot/wt > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
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

	echo "alpha" > $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo "zeta" >> $testroot/content.expected
	echo "delta" >> $testroot/content.expected
	cat $testroot/wt/alpha $testroot/wt/beta $testroot/wt/epsilon/zeta \
	    $testroot/wt/gamma/delta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_import_specified_head() {
	local testname=import_specified_head
	local testroot=`mktemp -d \
	    "$GOT_TEST_ROOT/got-test-$testname-XXXXXXXXXX"`
	local headref=trunk

	gotadmin init -b $headref $testroot/repo

	mkdir $testroot/tree
	make_test_tree $testroot/tree

	got import -m init -r $testroot/repo $testroot/tree > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	local head_commit=`git_show_head $testroot/repo`
	echo "A  $testroot/tree/gamma/delta" > $testroot/stdout.expected
	echo "A  $testroot/tree/epsilon/zeta" >> $testroot/stdout.expected
	echo "A  $testroot/tree/alpha" >> $testroot/stdout.expected
	echo "A  $testroot/tree/beta" >> $testroot/stdout.expected
	echo "Created branch refs/heads/$headref with commit $head_commit" \
	    >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "fail"
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && got log -p | grep -v ^date: > $testroot/stdout)

	id_alpha=`get_blob_id $testroot/repo "" alpha`
	id_beta=`get_blob_id $testroot/repo "" beta`
	id_zeta=`get_blob_id $testroot/repo epsilon zeta`
	id_delta=`get_blob_id $testroot/repo gamma delta`
	tree_id=`(cd $testroot/repo && got cat $head_commit | \
	    grep ^tree | cut -d ' ' -f 2)`

	echo "-----------------------------------------------" \
	    > $testroot/stdout.expected
	echo "commit $head_commit ($headref)" >> $testroot/stdout.expected
	echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo " init" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo "diff /dev/null $head_commit" >> $testroot/stdout.expected
	echo "commit - /dev/null" >> $testroot/stdout.expected
	echo "commit + $head_commit" >> $testroot/stdout.expected
	echo "blob - /dev/null" >> $testroot/stdout.expected
	echo "blob + $id_alpha (mode 644)" >> $testroot/stdout.expected
	echo "--- /dev/null" >> $testroot/stdout.expected
	echo "+++ alpha" >> $testroot/stdout.expected
	echo "@@ -0,0 +1 @@" >> $testroot/stdout.expected
	echo "+alpha" >> $testroot/stdout.expected
	echo "blob - /dev/null" >> $testroot/stdout.expected
	echo "blob + $id_beta (mode 644)" >> $testroot/stdout.expected
	echo "--- /dev/null" >> $testroot/stdout.expected
	echo "+++ beta" >> $testroot/stdout.expected
	echo "@@ -0,0 +1 @@" >> $testroot/stdout.expected
	echo "+beta" >> $testroot/stdout.expected
	echo "blob - /dev/null" >> $testroot/stdout.expected
	echo "blob + $id_zeta (mode 644)" >> $testroot/stdout.expected
	echo "--- /dev/null" >> $testroot/stdout.expected
	echo "+++ epsilon/zeta" >> $testroot/stdout.expected
	echo "@@ -0,0 +1 @@" >> $testroot/stdout.expected
	echo "+zeta" >> $testroot/stdout.expected
	echo "blob - /dev/null" >> $testroot/stdout.expected
	echo "blob + $id_delta (mode 644)" >> $testroot/stdout.expected
	echo "--- /dev/null" >> $testroot/stdout.expected
	echo "+++ gamma/delta" >> $testroot/stdout.expected
	echo "@@ -0,0 +1 @@" >> $testroot/stdout.expected
	echo "+delta" >> $testroot/stdout.expected
	echo "" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "fail"
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "A  $testroot/wt/alpha" > $testroot/stdout.expected
	echo "A  $testroot/wt/beta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/epsilon/zeta" >> $testroot/stdout.expected
	echo "A  $testroot/wt/gamma/delta" >> $testroot/stdout.expected
	echo "Checked out refs/heads/$headref: $head_commit" \
	    >> $testroot/stdout.expected
	echo "Now shut up and hack" >> $testroot/stdout.expected

	got checkout $testroot/repo $testroot/wt > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "fail"
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "fail"
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha" > $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo "zeta" >> $testroot/content.expected
	echo "delta" >> $testroot/content.expected
	cat $testroot/wt/alpha $testroot/wt/beta $testroot/wt/epsilon/zeta \
	    $testroot/wt/gamma/delta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "fail"
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_import_detached_head() {
	local testroot=`test_init import_detached_head`

	# mute verbose 'detached HEAD' warning
	(cd $testroot/repo && git config --local advice.detachedHead false)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# enter detached HEAD state
	local head_commit=`git_show_head $testroot/repo | cut -c1-7`
	(cd $testroot/repo && \
	    git checkout $head_commit > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "HEAD is now at $head_commit adding the test tree" >> \
	    $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "fail"
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir $testroot/import
	make_test_tree $testroot/import

	# detached HEAD (i.e., not symbolic) so import should fallback to "main"
	got import -r $testroot/repo -m init $testroot/import > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	local main_commit=`(cd $testroot/repo && \
	    git show-ref main | cut -d ' ' -f 1)`
	echo "A  $testroot/import/gamma/delta" > $testroot/stdout.expected
	echo "A  $testroot/import/epsilon/zeta" >> $testroot/stdout.expected
	echo "A  $testroot/import/alpha" >> $testroot/stdout.expected
	echo "A  $testroot/import/beta" >> $testroot/stdout.expected
	echo "Created branch refs/heads/main with commit $main_commit" \
	    >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "fail"
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_import_requires_new_branch() {
	local testroot=`test_init import_requires_new_branch`

	mkdir $testroot/tree
	make_test_tree $testroot/tree

	got import -b master -m 'init' -r $testroot/repo $testroot/tree \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "import command should have failed but did not"
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: import target branch already exists" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got import -b newbranch -m 'init' -r $testroot/repo $testroot/tree  \
		> $testroot/stdout
	ret=$?
	test_done "$testroot" "$ret"

}

test_import_ignores() {
	local testname=import_ignores
	local testroot=`mktemp -d \
	    "$GOT_TEST_ROOT/got-test-$testname-XXXXXXXXXX"`

	gotadmin init $testroot/repo

	mkdir $testroot/tree
	make_test_tree $testroot/tree

	touch $testroot/tree/upsilon
	mkdir $testroot/tree/ysilon
	got import -I alpha -I 'beta/' -I '*lta*' -I '*silon/' \
		-m 'init' -r $testroot/repo $testroot/tree > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	local head_commit=`git_show_head $testroot/repo`
	echo "A  $testroot/tree/beta" >> $testroot/stdout.expected
	echo "A  $testroot/tree/upsilon" >> $testroot/stdout.expected
	echo "Created branch refs/heads/main with commit $head_commit" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_import_empty_dir() {
	local testname=import_empty_dir
	local testroot=`mktemp -d \
	    "$GOT_TEST_ROOT/got-test-$testname-XXXXXXXXXX"`

	gotadmin init $testroot/repo

	mkdir $testroot/tree
	mkdir -p $testroot/tree/empty $testroot/tree/notempty
	echo "alpha" > $testroot/tree/notempty/alpha

	got import -m 'init' -r $testroot/repo $testroot/tree > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	local head_commit=`git_show_head $testroot/repo`
	echo "A  $testroot/tree/notempty/alpha" >> $testroot/stdout.expected
	echo "Created branch refs/heads/main with commit $head_commit" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Verify that Got did not import the empty directory
	echo "notempty/" > $testroot/stdout.expected
	echo "notempty/alpha" >> $testroot/stdout.expected

	got tree -r $testroot/repo -R > $testroot/stdout
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_import_symlink() {
	local testname=import_symlink
	local testroot=`mktemp -d \
	    "$GOT_TEST_ROOT/got-test-$testname-XXXXXXXXXX"`

	gotadmin init $testroot/repo

	mkdir $testroot/tree
	echo 'this is file alpha' > $testroot/tree/alpha
	ln -s alpha $testroot/tree/alpha.link

	got import -m 'init' -r $testroot/repo $testroot/tree \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	local head_commit=`git_show_head $testroot/repo`
	echo "A  $testroot/tree/alpha" > $testroot/stdout.expected
	echo "A  $testroot/tree/alpha.link" >> $testroot/stdout.expected
	echo "Created branch refs/heads/main with commit $head_commit" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	id_alpha=`get_blob_id $testroot/repo "" alpha`
	id_alpha_link=$(got tree -r $testroot/repo -i | grep 'alpha.link@ -> alpha$' | cut -d' ' -f 1)
	tree_id=`(cd $testroot/repo && got cat $head_commit | \
		grep ^tree | cut -d ' ' -f 2)`

	got tree -i -r $testroot/repo -c $head_commit > $testroot/stdout

	echo "$id_alpha alpha" > $testroot/stdout.expected
	echo "$id_alpha_link alpha.link@ -> alpha" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_import_basic
run_test test_import_specified_head
run_test test_import_detached_head
run_test test_import_requires_new_branch
run_test test_import_ignores
run_test test_import_empty_dir
run_test test_import_symlink
