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

function test_update_basic {
	local testroot=`test_init update_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	if [ "$?" != "0" ]; then
		test_done "$testroot" "$?"
		return 1
	fi

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"

	echo "U  alpha" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp $testroot/stdout.expected $testroot/stdout
	if [ "$?" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$?"
		return 1
	fi

	echo "modified alpha" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content

	cmp $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

function test_update_adds_file {
	local testroot=`test_init update_adds_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	if [ "$?" != "0" ]; then
		test_done "$testroot" "$?"
		return 1
	fi

	echo "new" > $testroot/repo/gamma/new
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "adding a new file"

	echo "A  gamma/new" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp $testroot/stdout.expected $testroot/stdout
	if [ "$?" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$?"
		return 1
	fi

	echo "new" >> $testroot/content.expected
	cat $testroot/wt/gamma/new > $testroot/content

	cmp $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

function test_update_deletes_file {
	local testroot=`test_init update_deletes_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	if [ "$?" != "0" ]; then
		test_done "$testroot" "$?"
		return 1
	fi

	(cd $testroot/repo && git_rm $testroot/repo beta)
	git_commit $testroot/repo -m "deleting a file"

	echo "D  beta" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp $testroot/stdout.expected $testroot/stdout
	if [ "$?" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$?"
		return 1
	fi

	if [ -e $testroot/wt/beta ]; then
		echo "removed file beta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

function test_update_deletes_dir {
	local testroot=`test_init update_deletes_dir`

	got checkout $testroot/repo $testroot/wt > /dev/null
	if [ "$?" != "0" ]; then
		test_done "$testroot" "$?"
		return 1
	fi

	(cd $testroot/repo && git_rm $testroot/repo -r epsilon)
	git_commit $testroot/repo -m "deleting a directory"

	echo "D  epsilon/zeta" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp $testroot/stdout.expected $testroot/stdout
	if [ "$?" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$?"
		return 1
	fi

	if [ -e $testroot/wt/epsilon ]; then
		echo "removed dir epsilon still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

function test_update_deletes_dir_with_path_prefix {
	local testroot=`test_init update_deletes_dir_with_path_prefix`
	local first_rev=`git_show_head $testroot/repo`

	mkdir $testroot/repo/epsilon/psi
	echo mu > $testroot/repo/epsilon/psi/mu
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "adding a sub-directory beneath epsilon"

	# check out the epsilon/ sub-tree
	got checkout -p epsilon $testroot/repo $testroot/wt > /dev/null
	if [ "$?" != "0" ]; then
		test_done "$testroot" "$?"
		return 1
	fi

	# update back to first commit and expect psi/mu to be deleted
	echo "D  psi/mu" > $testroot/stdout.expected
	echo "Updated to commit $first_rev" >> $testroot/stdout.expected

	(cd $testroot/wt && got update -c $first_rev > $testroot/stdout)

	cmp $testroot/stdout.expected $testroot/stdout
	if [ "$?" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$?"
		return 1
	fi

	if [ -e $testroot/wt/psi ]; then
		echo "removed dir psi still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

function test_update_deletes_dir_recursively {
	local testroot=`test_init update_deletes_dir_recursively`
	local first_rev=`git_show_head $testroot/repo`

	mkdir $testroot/repo/epsilon/psi
	echo mu > $testroot/repo/epsilon/psi/mu
	mkdir $testroot/repo/epsilon/psi/chi
	echo tau > $testroot/repo/epsilon/psi/chi/tau
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "adding a sub-directory beneath epsilon"

	# check out the epsilon/ sub-tree
	got checkout -p epsilon $testroot/repo $testroot/wt > /dev/null
	if [ "$?" != "0" ]; then
		test_done "$testroot" "$?"
		return 1
	fi

	# update back to first commit and expect psi/mu to be deleted
	echo "D  psi/chi/tau" > $testroot/stdout.expected
	echo "D  psi/mu" >> $testroot/stdout.expected
	echo "Updated to commit $first_rev" >> $testroot/stdout.expected

	(cd $testroot/wt && got update -c $first_rev > $testroot/stdout)

	cmp $testroot/stdout.expected $testroot/stdout
	if [ "$?" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$?"
		return 1
	fi

	if [ -e $testroot/wt/psi ]; then
		echo "removed dir psi still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

function test_update_with_sibling_dirs_with_common_prefix {
	local testroot=`test_init update_with_sibling_dirs_with_common_prefix`

	got checkout $testroot/repo $testroot/wt > /dev/null
	if [ "$?" != "0" ]; then
		test_done "$testroot" "$?"
		return 1
	fi

	mkdir $testroot/repo/epsilon2
	echo mu > $testroot/repo/epsilon2/mu
	(cd $testroot/repo && git add epsilon2/mu)
	git_commit $testroot/repo -m "adding sibling of epsilon"
	echo change > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "changing epsilon/zeta"

	echo "U  epsilon/zeta" > $testroot/stdout.expected
	echo "A  epsilon2/mu" >> $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp $testroot/stdout.expected $testroot/stdout
	if [ "$?" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$?"
		return 1
	fi

	echo "another change" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "changing epsilon/zeta again"

	echo "U  epsilon/zeta" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	# Bug: This update used to do delete/add epsilon2/mu again:
	# U  epsilon/zeta
	# D  epsilon2/mu <--- not intended
	# A  epsilon2/mu <--- not intended
	(cd $testroot/wt && got update > $testroot/stdout)

	cmp $testroot/stdout.expected $testroot/stdout
	if [ "$?" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$?"
		return 1
	fi

	cmp $testroot/stdout.expected $testroot/stdout
	if [ "$?" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$?"
		return 1
	fi

	test_done "$testroot" "0"
}

run_test test_update_basic
run_test test_update_adds_file
run_test test_update_deletes_file
run_test test_update_deletes_dir
run_test test_update_deletes_dir_with_path_prefix
run_test test_update_deletes_dir_recursively
run_test test_update_with_sibling_dirs_with_common_prefix
