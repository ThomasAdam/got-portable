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

test_update_basic() {
	local testroot=`test_init update_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"

	echo "U  alpha" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_update_adds_file() {
	local testroot=`test_init update_adds_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new" > $testroot/repo/gamma/new
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding a new file"

	echo "A  gamma/new" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new" >> $testroot/content.expected
	cat $testroot/wt/gamma/new > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_update_deletes_file() {
	local testroot=`test_init update_deletes_file`

	mkdir $testroot/wtparent
	got checkout $testroot/repo $testroot/wtparent/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	git_rm $testroot/repo beta
	git_commit $testroot/repo -m "deleting a file"

	echo "D  beta" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	# verify that no error occurs if the work tree's parent
	# directory is not writable
	chmod u-w $testroot/wtparent
	(cd $testroot/wtparent/wt && got update > $testroot/stdout)
	chmod u+w $testroot/wtparent

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wtparent/wt/beta ]; then
		echo "removed file beta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

test_update_deletes_dir() {
	local testroot=`test_init update_deletes_dir`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	git_rm $testroot/repo -r epsilon
	git_commit $testroot/repo -m "deleting a directory"

	echo "D  epsilon/zeta" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/epsilon ]; then
		echo "removed dir epsilon still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

test_update_deletes_dir_with_path_prefix() {
	local testroot=`test_init update_deletes_dir_with_path_prefix`
	local first_rev=`git_show_head $testroot/repo`

	mkdir $testroot/repo/epsilon/psi
	echo mu > $testroot/repo/epsilon/psi/mu
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding a sub-directory beneath epsilon"

	# check out the epsilon/ sub-tree
	got checkout -p epsilon $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# update back to first commit and expect psi/mu to be deleted
	echo "D  psi/mu" > $testroot/stdout.expected
	echo "Updated to refs/heads/master: $first_rev" \
		>> $testroot/stdout.expected

	(cd $testroot/wt && got update -c $first_rev > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/psi ]; then
		echo "removed dir psi still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

test_update_deletes_dir_recursively() {
	local testroot=`test_init update_deletes_dir_recursively`
	local first_rev=`git_show_head $testroot/repo`

	mkdir $testroot/repo/epsilon/psi
	echo mu > $testroot/repo/epsilon/psi/mu
	mkdir $testroot/repo/epsilon/psi/chi
	echo tau > $testroot/repo/epsilon/psi/chi/tau
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding a sub-directory beneath epsilon"

	# check out the epsilon/ sub-tree
	got checkout -p epsilon $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# update back to first commit and expect psi/mu to be deleted
	echo "D  psi/chi/tau" > $testroot/stdout.expected
	echo "D  psi/mu" >> $testroot/stdout.expected
	echo "Updated to refs/heads/master: $first_rev" \
		>> $testroot/stdout.expected

	(cd $testroot/wt && got update -c $first_rev > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/psi ]; then
		echo "removed dir psi still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

test_update_sibling_dirs_with_common_prefix() {
	local testroot=`test_init update_sibling_dirs_with_common_prefix`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir $testroot/repo/epsilon2
	echo mu > $testroot/repo/epsilon2/mu
	git -C $testroot/repo add epsilon2/mu
	git_commit $testroot/repo -m "adding sibling of epsilon"
	echo change > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "changing epsilon/zeta"

	echo "U  epsilon/zeta" > $testroot/stdout.expected
	echo "A  epsilon2/mu" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "another change" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "changing epsilon/zeta again"

	echo "U  epsilon/zeta" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	# Bug: This update used to do delete/add epsilon2/mu again:
	# U  epsilon/zeta
	# D  epsilon2/mu <--- not intended
	# A  epsilon2/mu <--- not intended
	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_update_dir_with_dot_sibling() {
	local testroot=`test_init update_dir_with_dot_sibling`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo text > $testroot/repo/epsilon.txt
	git -C $testroot/repo add epsilon.txt
	git_commit $testroot/repo -m "adding sibling of epsilon"
	echo change > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "changing epsilon/zeta"

	echo "U  epsilon/zeta" > $testroot/stdout.expected
	echo "A  epsilon.txt" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "another change" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "changing epsilon/zeta again"

	echo "U  epsilon/zeta" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_update_moves_files_upwards() {
	local testroot=`test_init update_moves_files_upwards`

	mkdir $testroot/repo/epsilon/psi
	echo mu > $testroot/repo/epsilon/psi/mu
	mkdir $testroot/repo/epsilon/psi/chi
	echo tau > $testroot/repo/epsilon/psi/chi/tau
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding a sub-directory beneath epsilon"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo mv epsilon/psi/mu epsilon/mu
	git -C $testroot/repo mv epsilon/psi/chi/tau epsilon/psi/tau
	git_commit $testroot/repo -m "moving files upwards"

	echo "A  epsilon/mu" > $testroot/stdout.expected
	echo "D  epsilon/psi/chi/tau" >> $testroot/stdout.expected
	echo "D  epsilon/psi/mu" >> $testroot/stdout.expected
	echo "A  epsilon/psi/tau" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/epsilon/psi/chi ]; then
		echo "removed dir epsilon/psi/chi still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	if [ -e $testroot/wt/epsilon/psi/mu ]; then
		echo "removed file epsilon/psi/mu still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

test_update_moves_files_to_new_dir() {
	local testroot=`test_init update_moves_files_to_new_dir`

	mkdir $testroot/repo/epsilon/psi
	echo mu > $testroot/repo/epsilon/psi/mu
	mkdir $testroot/repo/epsilon/psi/chi
	echo tau > $testroot/repo/epsilon/psi/chi/tau
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding a sub-directory beneath epsilon"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/repo/epsilon-new/psi
	git -C $testroot/repo mv epsilon/psi/mu epsilon-new/mu
	git -C $testroot/repo mv epsilon/psi/chi/tau epsilon-new/psi/tau
	git_commit $testroot/repo -m "moving files upwards"

	echo "D  epsilon/psi/chi/tau" > $testroot/stdout.expected
	echo "D  epsilon/psi/mu" >> $testroot/stdout.expected
	echo "A  epsilon-new/mu" >> $testroot/stdout.expected
	echo "A  epsilon-new/psi/tau" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/epsilon/psi/chi ]; then
		echo "removed dir epsilon/psi/chi still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	if [ -e $testroot/wt/epsilon/psi/mu ]; then
		echo "removed file epsilon/psi/mu still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

test_update_creates_missing_parent() {
	local testroot=`test_init update_creates_missing_parent 1`

	touch $testroot/repo/Makefile
	touch $testroot/repo/snake.6
	touch $testroot/repo/snake.c
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding initial snake tree"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/repo/snake
	git -C $testroot/repo mv Makefile snake.6 snake.c snake
	touch $testroot/repo/snake/move.c
	touch $testroot/repo/snake/pathnames.h
	touch $testroot/repo/snake/snake.h
	mkdir -p $testroot/repo/snscore
	touch $testroot/repo/snscore/Makefile
	touch $testroot/repo/snscore/snscore.c
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "restructuring snake tree"

	echo "D  Makefile" > $testroot/stdout.expected
	echo "A  snake/Makefile" >> $testroot/stdout.expected
	echo "A  snake/move.c" >> $testroot/stdout.expected
	echo "A  snake/pathnames.h" >> $testroot/stdout.expected
	echo "A  snake/snake.6" >> $testroot/stdout.expected
	echo "A  snake/snake.c" >> $testroot/stdout.expected
	echo "A  snake/snake.h" >> $testroot/stdout.expected
	echo "D  snake.6" >> $testroot/stdout.expected
	echo "D  snake.c" >> $testroot/stdout.expected
	echo "A  snscore/Makefile" >> $testroot/stdout.expected
	echo "A  snscore/snscore.c" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_update_creates_missing_parent_with_subdir() {
	local testroot=`test_init update_creates_missing_parent_with_subdir 1`

	touch $testroot/repo/Makefile
	touch $testroot/repo/snake.6
	touch $testroot/repo/snake.c
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding initial snake tree"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/repo/sss/snake
	git -C $testroot/repo mv Makefile snake.6 snake.c sss/snake
	touch $testroot/repo/sss/snake/move.c
	touch $testroot/repo/sss/snake/pathnames.h
	touch $testroot/repo/sss/snake/snake.h
	mkdir -p $testroot/repo/snscore
	touch $testroot/repo/snscore/Makefile
	touch $testroot/repo/snscore/snscore.c
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "restructuring snake tree"

	echo "D  Makefile" > $testroot/stdout.expected
	echo "D  snake.6" >> $testroot/stdout.expected
	echo "D  snake.c" >> $testroot/stdout.expected
	echo "A  snscore/Makefile" >> $testroot/stdout.expected
	echo "A  snscore/snscore.c" >> $testroot/stdout.expected
	echo "A  sss/snake/Makefile" >> $testroot/stdout.expected
	echo "A  sss/snake/move.c" >> $testroot/stdout.expected
	echo "A  sss/snake/pathnames.h" >> $testroot/stdout.expected
	echo "A  sss/snake/snake.6" >> $testroot/stdout.expected
	echo "A  sss/snake/snake.c" >> $testroot/stdout.expected
	echo "A  sss/snake/snake.h" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "0"
}

test_update_file_in_subsubdir() {
	local testroot=`test_init update_fle_in_subsubdir 1`

	touch $testroot/repo/Makefile
	mkdir -p $testroot/repo/altq
	touch $testroot/repo/altq/if_altq.h
	mkdir -p $testroot/repo/arch/alpha
	touch $testroot/repo/arch/alpha/Makefile
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding initial tree"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo change > $testroot/repo/arch/alpha/Makefile
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "changed a file"

	echo "U  arch/alpha/Makefile" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "0"
}

test_update_changes_file_to_dir() {
	local testroot=`test_init update_changes_file_to_dir`

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

	(cd $testroot/wt && got update > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "D  alpha" > $testroot/stdout.expected
	echo "A  alpha/eta" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_update_changes_dir_to_file() {
	local testroot=`test_init update_changes_dir_to_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	git_rmdir $testroot/repo epsilon
	echo epsilon > $testroot/repo/epsilon
	cp $testroot/repo/epsilon $testroot/content.expected
	git -C $testroot/repo add epsilon
	git_commit $testroot/repo -m "changed epsilon into file"

	(cd $testroot/wt && got update > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# The current behaviour is not perfect, but we accept it for now.
	echo "~  epsilon" > $testroot/stdout.expected
	echo "D  epsilon/zeta" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	echo "File paths obstructed by a non-regular file: 1" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Updating again now restores the file which was obstructed by a
	# directory in the previous update operation. Ideally, a single
	# update operation would suffice.
	(cd $testroot/wt && got update > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "A  epsilon" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/content.expected $testroot/wt/epsilon
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/wt/epsilon
	fi
	test_done "$testroot" "$ret"
}

test_update_changes_modified_file_to_dir() {
	local testroot=`test_init update_changes_modified_file_to_dir`

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

	echo "modified alpha" >> $testroot/wt/alpha
	cp $testroot/wt/alpha $testroot/wt/content.expected
	(cd $testroot/wt && got update > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "update succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "d  alpha" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: alpha/eta: file is obstructed" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_update_merges_file_edits() {
	local testroot=`test_init update_merges_file_edits`

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

	echo "modified alpha" > $testroot/repo/alpha
	echo "modified beta" > $testroot/repo/beta
	ed -s $testroot/repo/numbers <<-\EOF
	,s/2/22/
	w
	EOF
	git_commit $testroot/repo -m "modified 3 files"

	echo "modified alpha, too" > $testroot/wt/alpha
	touch $testroot/wt/beta
	ed -s $testroot/wt/numbers <<-\EOF
	,s/7/77/
	w
	EOF

	echo "C  alpha" > $testroot/stdout.expected
	echo "U  beta" >> $testroot/stdout.expected
	echo "G  numbers" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
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

	echo -n "<<<<<<< merged change: commit " > $testroot/content.expected
	git_show_head $testroot/repo >> $testroot/content.expected
	echo >> $testroot/content.expected
	echo "modified alpha" >> $testroot/content.expected
	echo "||||||| 3-way merge base: commit $base_commit" \
		>> $testroot/content.expected
	echo "alpha" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "modified alpha, too" >> $testroot/content.expected
	echo '>>>>>>>' >> $testroot/content.expected
	echo "modified beta" >> $testroot/content.expected
	echo "1" >> $testroot/content.expected
	echo "22" >> $testroot/content.expected
	echo "3" >> $testroot/content.expected
	echo "4" >> $testroot/content.expected
	echo "5" >> $testroot/content.expected
	echo "6" >> $testroot/content.expected
	echo "77" >> $testroot/content.expected
	echo "8" >> $testroot/content.expected

	cat $testroot/wt/alpha > $testroot/content
	cat $testroot/wt/beta >> $testroot/content
	cat $testroot/wt/numbers >> $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_update_keeps_xbit() {
	local testroot=`test_init update_keeps_xbit 1`

	touch $testroot/repo/xfile
	chmod +x $testroot/repo/xfile
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding executable file"

	got checkout $testroot/repo $testroot/wt > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo foo > $testroot/repo/xfile
	git_commit $testroot/repo -m "changed executable file"

	echo "U  xfile" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)
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

	ls -l $testroot/wt/xfile | grep -q '^-rwx'
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "file is not executable" >&2
		ls -l $testroot/wt/xfile >&2
	fi
	test_done "$testroot" "$ret"
}

test_update_clears_xbit() {
	local testroot=`test_init update_clears_xbit 1`

	touch $testroot/repo/xfile
	chmod +x $testroot/repo/xfile
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding executable file"

	got checkout $testroot/repo $testroot/wt > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	ls -l $testroot/wt/xfile | grep -q '^-rwx'
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "file is not executable" >&2
		ls -l $testroot/wt/xfile >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	# XXX git seems to require a file edit when flipping the x bit?
	echo foo > $testroot/repo/xfile
	chmod -x $testroot/repo/xfile
	git_commit $testroot/repo -m "not an executable file anymore"

	echo "U  xfile" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)
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

	ls -l $testroot/wt/xfile | grep -q '^-rw-'
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "file is unexpectedly executable" >&2
		ls -l $testroot/wt/xfile >&2
	fi
	test_done "$testroot" "$ret"
}

test_update_restores_missing_file() {
	local testroot=`test_init update_restores_missing_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	rm $testroot/wt/alpha

	echo "!  alpha" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha" > $testroot/content.expected

	cat $testroot/wt/alpha > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_update_conflict_wt_add_vs_repo_add() {
	local testroot=`test_init update_conflict_wt_add_vs_repo_add`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new" > $testroot/repo/gamma/new
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding a new file"

	echo "also new" > $testroot/wt/gamma/new
	(cd $testroot/wt && got add gamma/new >/dev/null)

	(cd $testroot/wt && got update > $testroot/stdout)

	echo "C  gamma/new" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n "<<<<<<< merged change: commit " > $testroot/content.expected
	git_show_head $testroot/repo >> $testroot/content.expected
	echo >> $testroot/content.expected
	echo "new" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "also new" >> $testroot/content.expected
	echo '>>>>>>>' >> $testroot/content.expected

	cat $testroot/wt/gamma/new > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# resolve the conflict
	echo "new and also new" > $testroot/wt/gamma/new
	echo 'M  gamma/new' > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_update_conflict_wt_edit_vs_repo_rm() {
	local testroot=`test_init update_conflict_wt_edit_vs_repo_rm`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo rm -q beta
	git_commit $testroot/repo -m "removing a file"

	echo "modified beta" > $testroot/wt/beta

	(cd $testroot/wt && got update > $testroot/stdout)

	echo "G  beta" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified beta" > $testroot/content.expected

	cat $testroot/wt/beta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# beta is now an added file... we don't flag tree conflicts yet
	echo 'A  beta' > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_update_conflict_wt_rm_vs_repo_edit() {
	local testroot=`test_init update_conflict_wt_rm_vs_repo_edit`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified beta" > $testroot/repo/beta
	git_commit $testroot/repo -m "modified a file"

	(cd $testroot/wt && got rm beta > /dev/null)

	(cd $testroot/wt && got update > $testroot/stdout)

	echo "G  beta" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# beta remains a deleted file... we don't flag tree conflicts yet
	echo 'D  beta' > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# 'got diff' should show post-update contents of beta being deleted
	local head_rev=`git_show_head $testroot/repo`
	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $head_rev"  >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'beta$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + /dev/null' >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-modified beta' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_update_conflict_wt_rm_vs_repo_rm() {
	local testroot=`test_init update_conflict_wt_rm_vs_repo_rm`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo rm -q beta
	git_commit $testroot/repo -m "removing a file"

	(cd $testroot/wt && got rm beta > /dev/null)

	(cd $testroot/wt && got update > $testroot/stdout)

	echo "D  beta" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# beta is now gone... we don't flag tree conflicts yet
	echo "N  beta" > $testroot/stdout.expected
	echo -n > $testroot/stderr.expected
	(cd $testroot/wt && got status beta > $testroot/stdout \
		2> $testroot/stderr)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/beta ]; then
		echo "removed file beta still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

test_update_partial() {
	local testroot=`test_init update_partial`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/repo/alpha
	echo "modified beta" > $testroot/repo/beta
	echo "modified epsilon/zeta" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "modified two files"

	echo "U  alpha" > $testroot/stdout.expected
	echo "U  beta" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update alpha beta > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/content.expected
	echo "modified beta" >> $testroot/content.expected

	cat $testroot/wt/alpha $testroot/wt/beta > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "U  epsilon/zeta" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update epsilon > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified epsilon/zeta" > $testroot/content.expected
	cat $testroot/wt/epsilon/zeta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_update_partial_add() {
	local testroot=`test_init update_partial_add`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new" > $testroot/repo/new
	echo "epsilon/new2" > $testroot/repo/epsilon/new2
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "added two files"

	echo "A  epsilon/new2" > $testroot/stdout.expected
	echo "A  new" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update new epsilon/new2 > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new" > $testroot/content.expected
	echo "epsilon/new2" >> $testroot/content.expected

	cat $testroot/wt/new $testroot/wt/epsilon/new2 > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_update_partial_rm() {
	local testroot=`test_init update_partial_rm`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo rm -q alpha epsilon/zeta
	git_commit $testroot/repo -m "removed two files"

	echo "got: /alpha: no such entry found in tree" \
		> $testroot/stderr.expected

	(cd $testroot/wt && got update alpha epsilon/zeta 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "update succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_update_partial_dir() {
	local testroot=`test_init update_partial_dir`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/repo/alpha
	echo "modified beta" > $testroot/repo/beta
	echo "modified epsilon/zeta" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "modified two files"

	echo "U  epsilon/zeta" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update epsilon > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified epsilon/zeta" > $testroot/content.expected
	cat $testroot/wt/epsilon/zeta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi
	test_done "$testroot" "$ret"

}

test_update_moved_branch_ref() {
	local testroot=`test_init update_moved_branch_ref`

	git clone -q --mirror $testroot/repo $testroot/repo2

	echo "modified alpha with git" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha with git"

	got checkout $testroot/repo2 $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha with got" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "modified alpha with got" > /dev/null)

	# + xxxxxxx...yyyyyyy master     -> master  (forced update)
	git -C $testroot/repo2 fetch -q --all

	echo -n > $testroot/stdout.expected
	echo -n "got: work tree's head reference now points to a different " \
		> $testroot/stderr.expected
	echo "branch; new head reference and/or update -b required"  \
		>> $testroot/stderr.expected

	(cd $testroot/wt && got update > $testroot/stdout 2> $testroot/stderr)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_update_to_another_branch() {
	local testroot=`test_init update_to_another_branch`
	local base_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'refs/heads/master'> $testroot/head-ref.expected
	cmp -s $testroot/head-ref.expected $testroot/wt/.got/head-ref
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/head-ref.expected $testroot/wt/.got/head-ref
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified alpha on new branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha on new branch"

	echo "modified alpha in work tree" > $testroot/wt/alpha

	echo "Switching work tree from refs/heads/master to refs/heads/newbranch" > $testroot/stdout.expected
	echo "C  alpha" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/newbranch: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected

	(cd $testroot/wt && got update -b newbranch > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n "<<<<<<< merged change: commit " > $testroot/content.expected
	git_show_head $testroot/repo >> $testroot/content.expected
	echo >> $testroot/content.expected
	echo "modified alpha on new branch" >> $testroot/content.expected
	echo "||||||| 3-way merge base: commit $base_commit" \
		>> $testroot/content.expected
	echo "alpha" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "modified alpha in work tree" >> $testroot/content.expected
	echo '>>>>>>>' >> $testroot/content.expected

	cat $testroot/wt/alpha > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'refs/heads/newbranch'> $testroot/head-ref.expected
	cmp -s $testroot/head-ref.expected $testroot/wt/.got/head-ref
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/head-ref.expected $testroot/wt/.got/head-ref
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_update_to_commit_on_wrong_branch() {
	local testroot=`test_init update_to_commit_on_wrong_branch`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo checkout -q -b newbranch
	echo "modified alpha on new branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha on new branch"

	echo -n "" > $testroot/stdout.expected
	echo  "got: target commit is on a different branch" \
		> $testroot/stderr.expected

	local head_rev=`git_show_head $testroot/repo`
	(cd $testroot/wt && got update -c $head_rev > $testroot/stdout \
		2> $testroot/stderr)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_update_bumps_base_commit_id() {
	local testroot=`test_init update_bumps_base_commit_id`

	echo "psi" > $testroot/repo/epsilon/psi
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding another file"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified psi" > $testroot/wt/epsilon/psi
	(cd $testroot/wt && got commit -m "changed psi" > $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "M  epsilon/psi" > $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "changed zeta with git" > $testroot/repo/epsilon/zeta
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "changing zeta with git"

	echo "modified zeta" > $testroot/wt/epsilon/zeta
	(cd $testroot/wt && got commit -m "changed zeta" > $testroot/stdout \
		2> $testroot/stderr)

	echo -n "" > $testroot/stdout.expected
	echo "got: work tree must be updated before these changes can be committed"  > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update > $testroot/stdout)

	echo "U  epsilon/psi" > $testroot/stdout.expected
	echo "C  epsilon/zeta" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# resolve conflict
	echo "modified zeta with got and git" > $testroot/wt/epsilon/zeta

	(cd $testroot/wt && got commit -m "changed zeta" > $testroot/stdout)

	local head_rev=`git_show_head $testroot/repo`
	echo "M  epsilon/zeta" > $testroot/stdout.expected
	echo "Created commit $head_rev" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_update_tag() {
	local testroot=`test_init update_tag`
	local tag="1.0.0"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	git -C $testroot/repo tag -m "test" -a $tag

	echo "U  alpha" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update -c $tag > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_update_toggles_xbit() {
	local testroot=`test_init update_toggles_xbit 1`

	touch $testroot/repo/xfile
	chmod +x $testroot/repo/xfile
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding executable file"
	local commit_id1=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	ls -l $testroot/wt/xfile | grep -q '^-rwx'
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "file is not executable" >&2
		ls -l $testroot/wt/xfile >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	chmod -x $testroot/wt/xfile
	(cd $testroot/wt && got commit -m "clear x bit" >/dev/null)
	local commit_id2=`git_show_head $testroot/repo`

	echo "U  xfile" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update -c $commit_id1 > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "U  xfile" > $testroot/stdout.expected
	echo "Updated to refs/heads/master: $commit_id1" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi


	ls -l $testroot/wt/xfile | grep -q '^-rwx'
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "file is not executable" >&2
		ls -l $testroot/wt/xfile >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "U  xfile" > $testroot/stdout.expected
	echo "Updated to refs/heads/master: $commit_id2" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	ls -l $testroot/wt/xfile | grep -q '^-rw-'
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "file is unexpectedly executable" >&2
		ls -l $testroot/wt/xfile >&2
	fi
	test_done "$testroot" "$ret"
}

test_update_preserves_conflicted_file() {
	local testroot=`test_init update_preserves_conflicted_file`
	local commit_id0=`git_show_head $testroot/repo`

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"
	local commit_id1=`git_show_head $testroot/repo`

	got checkout -c $commit_id0 $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# fake a merge conflict
	echo '<<<<<<<' > $testroot/wt/alpha
	echo 'alpha' >> $testroot/wt/alpha
	echo '=======' >> $testroot/wt/alpha
	echo 'alpha, too' >> $testroot/wt/alpha
	echo '>>>>>>>' >> $testroot/wt/alpha
	cp $testroot/wt/alpha $testroot/content.expected

	echo "C  alpha" > $testroot/stdout.expected
	(cd $testroot/wt && got status  > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "#  alpha" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	echo "Files not updated because of existing merge conflicts: 1" \
		>> $testroot/stdout.expected
	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/content.expected $testroot/wt/alpha
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/wt/alpha
	fi
	test_done "$testroot" "$ret"
}

test_update_modified_submodules() {
	local testroot=`test_init update_modified_submodules`

	make_single_file_repo $testroot/repo2 foo

	git -C $testroot/repo -c protocol.file.allow=always \
		submodule -q add ../repo2
	git -C $testroot/repo commit -q -m 'adding submodule'

	got checkout $testroot/repo $testroot/wt > /dev/null

	echo "modified foo" > $testroot/repo2/foo
	git -C $testroot/repo2 commit -q -a -m 'modified a submodule'

	# Update the repo/repo2 submodule link
	git -C $testroot/repo/repo2 pull -q
	git -C $testroot/repo add repo2
	git_commit $testroot/repo -m "modified submodule link"

	echo "Already up-to-date" > $testroot/stdout.expected
	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_update_adds_submodule() {
	local testroot=`test_init update_adds_submodule`

	got checkout $testroot/repo $testroot/wt > /dev/null

	make_single_file_repo $testroot/repo2 foo

	echo "modified foo" > $testroot/repo2/foo
	git -C $testroot/repo2 commit -q -a -m 'modified a submodule'

	git -C $testroot/repo -c protocol.file.allow=always \
		submodule -q add ../repo2
	git -C $testroot/repo commit -q -m 'adding submodule'

	echo "A  .gitmodules" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_update_conflict_wt_file_vs_repo_submodule() {
	local testroot=`test_init update_conflict_wt_file_vs_repo_submodule`

	got checkout $testroot/repo $testroot/wt > /dev/null

	make_single_file_repo $testroot/repo2 foo

	# Add a file which will clash with the submodule
	echo "This is a file called repo2" > $testroot/wt/repo2
	(cd $testroot/wt && got add repo2 > /dev/null)
	(cd $testroot/wt && got commit -m 'add file repo2' > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "commit failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	git -C $testroot/repo -c protocol.file.allow=always \
		submodule -q add ../repo2
	git -C $testroot/repo commit -q -m 'adding submodule'

	# Modify the clashing file such that any modifications brought
	# in by 'got update' would require a merge.
	echo "This file was changed" > $testroot/wt/repo2

	# No conflict occurs because 'got update' ignores the submodule
	# and leaves the clashing file as it was.
	echo "A  .gitmodules" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo "M  repo2" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_update_adds_symlink() {
	local testroot=`test_init update_adds_symlink`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && ln -s alpha alpha.link)
	(cd $testroot/repo && ln -s epsilon epsilon.link)
	(cd $testroot/repo && ln -s /etc/passwd passwd.link)
	(cd $testroot/repo && ln -s ../beta epsilon/beta.link)
	(cd $testroot/repo && ln -s nonexistent nonexistent.link)
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "add symlinks"

	echo "A  alpha.link" > $testroot/stdout.expected
	echo "A  epsilon/beta.link" >> $testroot/stdout.expected
	echo "A  epsilon.link" >> $testroot/stdout.expected
	echo "A  nonexistent.link" >> $testroot/stdout.expected
	echo "A  passwd.link" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if ! [ -h $testroot/wt/alpha.link ]; then
		echo "alpha.link is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/alpha.link > $testroot/stdout
	echo "alpha" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if ! [ -h $testroot/wt/epsilon.link ]; then
		echo "epsilon.link is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/epsilon.link > $testroot/stdout
	echo "epsilon" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/passwd.link ]; then
		echo -n "passwd.link symlink points outside of work tree: " >&2
		readlink $testroot/wt/passwd.link >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n "/etc/passwd" > $testroot/content.expected
	cp $testroot/wt/passwd.link $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	readlink $testroot/wt/epsilon/beta.link > $testroot/stdout
	echo "../beta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	readlink $testroot/wt/nonexistent.link > $testroot/stdout
	echo "nonexistent" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Updating an up-to-date symlink should be a no-op.
	echo 'Already up-to-date' > $testroot/stdout.expected
	(cd $testroot/wt && got update > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_update_deletes_symlink() {
	local testroot=`test_init update_deletes_symlink`

	(cd $testroot/repo && ln -s alpha alpha.link)
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "add symlink"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	git -C $testroot/repo rm -q alpha.link
	git_commit $testroot/repo -m "delete symlink"

	echo "D  alpha.link" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/alpha.link ]; then
		echo "alpha.link still exists on disk"
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

test_update_symlink_conflicts() {
	local testroot=`test_init update_symlink_conflicts`

	(cd $testroot/repo && ln -s alpha alpha.link)
	(cd $testroot/repo && ln -s epsilon epsilon.link)
	(cd $testroot/repo && ln -s /etc/passwd passwd.link)
	(cd $testroot/repo && ln -s ../beta epsilon/beta.link)
	(cd $testroot/repo && ln -s nonexistent nonexistent.link)
	(cd $testroot/repo && ln -sf epsilon/zeta zeta.link)
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "add symlinks"
	local commit_id1=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && ln -sf beta alpha.link)
	(cd $testroot/repo && rm epsilon.link && ln -s gamma epsilon.link)
	(cd $testroot/repo && ln -sf ../gamma/delta epsilon/beta.link)
	echo 'this is regular file foo' > $testroot/repo/dotgotfoo.link
	(cd $testroot/repo && ln -sf .got/bar dotgotbar.link)
	git -C $testroot/repo rm -q nonexistent.link
	(cd $testroot/repo && ln -sf gamma/delta zeta.link)
	(cd $testroot/repo && ln -sf alpha new.link)
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "change symlinks"
	local commit_id2=`git_show_head $testroot/repo`

	# modified symlink to file A vs modified symlink to file B
	(cd $testroot/wt && ln -sf gamma/delta alpha.link)
	# modified symlink to dir A vs modified symlink to file B
	(cd $testroot/wt && rm epsilon.link && ln -s beta epsilon.link)
	# modeified symlink to file A vs modified symlink to dir B
	(cd $testroot/wt && rm epsilon/beta.link && ln -s ../gamma \
		epsilon/beta.link)
	# added regular file A vs added bad symlink to file A
	(cd $testroot/wt && ln -sf .got/bar dotgotfoo.link)
	(cd $testroot/wt && got add dotgotfoo.link > /dev/null)
	# added bad symlink to file A vs added regular file A
	echo 'this is regular file bar' > $testroot/wt/dotgotbar.link
	(cd $testroot/wt && got add dotgotbar.link > /dev/null)
	# removed symlink to non-existent file A vs modified symlink
	# to nonexistent file B
	(cd $testroot/wt && ln -sf nonexistent2 nonexistent.link)
	# modified symlink to file A vs removed symlink to file A
	(cd $testroot/wt && got rm zeta.link > /dev/null)
	# added symlink to file A vs added symlink to file B
	(cd $testroot/wt && ln -sf beta new.link)
	(cd $testroot/wt && got add new.link > /dev/null)

	(cd $testroot/wt && got update > $testroot/stdout)

	echo "C  alpha.link" >> $testroot/stdout.expected
	echo "C  dotgotbar.link" >> $testroot/stdout.expected
	echo "C  dotgotfoo.link" >> $testroot/stdout.expected
	echo "C  epsilon/beta.link" >> $testroot/stdout.expected
	echo "C  epsilon.link" >> $testroot/stdout.expected
	echo "C  new.link" >> $testroot/stdout.expected
	echo "C  nonexistent.link" >> $testroot/stdout.expected
	echo "G  zeta.link" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 7" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/alpha.link ]; then
		echo "alpha.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	echo "<<<<<<< merged change: commit $commit_id2" \
		> $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo "3-way merge base: commit $commit_id1" \
		>> $testroot/content.expected
	echo "alpha" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "gamma/delta" >> $testroot/content.expected
	echo '>>>>>>>' >> $testroot/content.expected
	echo -n "" >> $testroot/content.expected

	cp $testroot/wt/alpha.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/epsilon.link ]; then
		echo "epsilon.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	echo "<<<<<<< merged change: commit $commit_id2" \
		> $testroot/content.expected
	echo "gamma" >> $testroot/content.expected
	echo "3-way merge base: commit $commit_id1" \
		>> $testroot/content.expected
	echo "epsilon" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo '>>>>>>>' >> $testroot/content.expected
	echo -n "" >> $testroot/content.expected

	cp $testroot/wt/epsilon.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/passwd.link ]; then
		echo -n "passwd.link symlink points outside of work tree: " >&2
		readlink $testroot/wt/passwd.link >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n "/etc/passwd" > $testroot/content.expected
	cp $testroot/wt/passwd.link $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/epsilon/beta.link ]; then
		echo "epsilon/beta.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	echo "<<<<<<< merged change: commit $commit_id2" \
		> $testroot/content.expected
	echo "../gamma/delta" >> $testroot/content.expected
	echo "3-way merge base: commit $commit_id1" \
		>> $testroot/content.expected
	echo "../beta" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "../gamma" >> $testroot/content.expected
	echo '>>>>>>>' >> $testroot/content.expected
	echo -n "" >> $testroot/content.expected

	cp $testroot/wt/epsilon/beta.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/nonexistent.link ]; then
		echo -n "nonexistent.link still exists on disk: " >&2
		readlink $testroot/wt/nonexistent.link >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "<<<<<<< merged change: commit $commit_id2" \
		> $testroot/content.expected
	echo "(symlink was deleted)" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "nonexistent2" >> $testroot/content.expected
	echo '>>>>>>>' >> $testroot/content.expected
	echo -n "" >> $testroot/content.expected

	cp $testroot/wt/nonexistent.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/dotgotfoo.link ]; then
		echo "dotgotfoo.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	echo "<<<<<<< merged change: commit $commit_id2" \
		> $testroot/content.expected
	echo "this is regular file foo" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo -n ".got/bar" >> $testroot/content.expected
	echo '>>>>>>>' >> $testroot/content.expected
	echo -n "" >> $testroot/content.expected

	cp $testroot/wt/dotgotfoo.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/dotgotbar.link ]; then
		echo "dotgotbar.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi
	echo "<<<<<<< merged change: commit $commit_id2" \
		> $testroot/content.expected
	echo -n ".got/bar" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "this is regular file bar" >> $testroot/content.expected
	echo '>>>>>>>' >> $testroot/content.expected
	echo -n "" >> $testroot/content.expected

	cp $testroot/wt/dotgotbar.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/new.link ]; then
		echo "new.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	echo "<<<<<<< merged change: commit $commit_id2" \
		> $testroot/content.expected
	echo "alpha" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo '>>>>>>>' >> $testroot/content.expected
	echo -n "" >> $testroot/content.expected

	cp $testroot/wt/new.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "A  dotgotfoo.link" > $testroot/stdout.expected
	echo "M  new.link" >> $testroot/stdout.expected
	echo "D  nonexistent.link" >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "0"

}

test_update_single_file() {
	local testroot=`test_init update_single_file 1`

	echo c1 > $testroot/repo/c
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "adding file c"
	local commit_id1=`git_show_head $testroot/repo`

	echo a > $testroot/repo/a
	echo b > $testroot/repo/b
	echo c2 > $testroot/repo/c
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "add files a and b, change c"
	local commit_id2=`git_show_head $testroot/repo`

	git -C $testroot/repo rm -qf c
	git_commit $testroot/repo -m "remove file c"
	local commit_id3=`git_show_head $testroot/repo`

	got checkout -c $commit_id2 $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "U  c" > $testroot/stdout.expected
	echo "Updated to refs/heads/master: $commit_id1" \
		>> $testroot/stdout.expected

	(cd $testroot/wt && got update -c $commit_id1 c \
		> $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo c1 > $testroot/content.expected
	cat $testroot/wt/c > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "U  c" > $testroot/stdout.expected
	echo "Updated to refs/heads/master: $commit_id2" \
		>> $testroot/stdout.expected

	(cd $testroot/wt && got update -c $commit_id2 c > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo c2 > $testroot/content.expected
	cat $testroot/wt/c > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "D  c" > $testroot/stdout.expected
	echo "Updated to refs/heads/master: $commit_id3" \
		>> $testroot/stdout.expected

	(cd $testroot/wt && got update -c $commit_id3 c \
		> $testroot/stdout 2> $testroot/stderr)

	echo "got: /c: no such entry found in tree" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
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

	echo "D  c" > $testroot/stdout.expected
	echo "Updated to refs/heads/master: $commit_id3" \
		>> $testroot/stdout.expected

	(cd $testroot/wt && got update -c $commit_id3 > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/c ]; then
		echo "removed file c still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
	return 0
}

test_update_file_skipped_due_to_conflict() {
	local testroot=`test_init update_file_skipped_due_to_conflict`
	local commit_id0=`git_show_head $testroot/repo`
	blob_id0=`get_blob_id $testroot/repo "" beta`

	echo "changed beta" > $testroot/repo/beta
	git_commit $testroot/repo -m "changed beta"
	local commit_id1=`git_show_head $testroot/repo`
	blob_id1=`get_blob_id $testroot/repo "" beta`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	blob_id=`(cd $testroot/wt && got info beta | grep 'blob:' | \
		cut -d ':' -f 2 | tr -d ' ')`
	if [ "$blob_id" != "$blob_id1" ]; then
		echo "file beta has the wrong base blob ID" >&2
		test_done "$testroot" "1"
		return 1
	fi

	commit_id=`(cd $testroot/wt && got info beta | \
		grep 'based on commit:' | cut -d ':' -f 2 | tr -d ' ')`
	if [ "$commit_id" != "$commit_id1" ]; then
		echo "file beta has the wrong base commit ID" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "modified beta" > $testroot/wt/beta

	(cd $testroot/wt && got update -c $commit_id0 > $testroot/stdout)

	echo "C  beta" > $testroot/stdout.expected
	echo "Updated to refs/heads/master: $commit_id0" \
		>> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "<<<<<<< merged change: commit $commit_id0" \
		> $testroot/content.expected
	echo "beta" >> $testroot/content.expected
	echo "||||||| 3-way merge base: commit $commit_id1" \
		>> $testroot/content.expected
	echo "changed beta" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "modified beta" >> $testroot/content.expected
	echo ">>>>>>>" >> $testroot/content.expected

	cat $testroot/wt/beta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	blob_id=`(cd $testroot/wt && got info beta | grep 'blob:' | \
		cut -d ':' -f 2 | tr -d ' ')`
	if [ "$blob_id" != "$blob_id0" ]; then
		echo "file beta has the wrong base blob ID" >&2
		test_done "$testroot" "1"
		return 1
	fi

	commit_id=`(cd $testroot/wt && got info beta | \
		grep 'based on commit:' | cut -d ':' -f 2 | tr -d ' ')`
	if [ "$commit_id" != "$commit_id0" ]; then
		echo "file beta has the wrong base commit ID" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# update to the latest commit again; this skips beta
	(cd $testroot/wt && got update > $testroot/stdout)
	echo "#  beta" > $testroot/stdout.expected
	echo "Updated to refs/heads/master: $commit_id1" \
		>> $testroot/stdout.expected
	echo "Files not updated because of existing merge conflicts: 1" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# blob ID of beta should not have changed
	blob_id=`(cd $testroot/wt && got info beta | grep 'blob:' | \
		cut -d ':' -f 2 | tr -d ' ')`
	if [ "$blob_id" != "$blob_id0" ]; then
		echo "file beta has the wrong base blob ID" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# commit ID of beta should not have changed; There was a bug
	# here where the commit ID had been changed even though the
	# file was not updated.
	commit_id=`(cd $testroot/wt && got info beta | \
		grep 'based on commit:' | cut -d ':' -f 2 | tr -d ' ')`
	if [ "$commit_id" != "$commit_id0" ]; then
		echo "file beta has the wrong base commit ID: $commit_id" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# beta is still conflicted and based on commit 0
	echo 'C  beta' > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# resolve the conflict via revert
	(cd $testroot/wt && got revert beta >/dev/null)

	# beta now matches its base blob which is still from commit 0
	echo "beta" > $testroot/content.expected
	cat $testroot/wt/beta > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# updating to the latest commit should now update beta
	(cd $testroot/wt && got update > $testroot/stdout)
	echo "U  beta" > $testroot/stdout.expected
	echo "Updated to refs/heads/master: $commit_id1" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	blob_id=`(cd $testroot/wt && got info beta | grep 'blob:' | \
		cut -d ':' -f 2 | tr -d ' ')`
	if [ "$blob_id" != "$blob_id1" ]; then
		echo "file beta has the wrong base blob ID" >&2
		test_done "$testroot" "1"
		return 1
	fi

	commit_id=`(cd $testroot/wt && got info beta | \
		grep 'based on commit:' | cut -d ':' -f 2 | tr -d ' ')`
	if [ "$commit_id" != "$commit_id1" ]; then
		echo "file beta has the wrong base commit ID: $commit_id" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "changed beta" > $testroot/content.expected
	cat $testroot/wt/beta > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_update_file_skipped_due_to_obstruction() {
	local testroot=`test_init update_file_skipped_due_to_obstruction`
	local commit_id0=`git_show_head $testroot/repo`
	blob_id0=`get_blob_id $testroot/repo "" beta`

	echo "changed beta" > $testroot/repo/beta
	echo "new file" > $testroot/repo/new
	git -C $testroot/repo add new
	git_commit $testroot/repo -m "changed beta"
	local commit_id1=`git_show_head $testroot/repo`
	blob_id1=`get_blob_id $testroot/repo "" beta`

	got checkout -c $commit_id0 $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	blob_id=`(cd $testroot/wt && got info beta | grep 'blob:' | \
		cut -d ':' -f 2 | tr -d ' ')`
	if [ "$blob_id" != "$blob_id0" ]; then
		echo "file beta has the wrong base blob ID" >&2
		test_done "$testroot" "1"
		return 1
	fi

	commit_id=`(cd $testroot/wt && got info beta | \
		grep 'based on commit:' | cut -d ':' -f 2 | tr -d ' ')`
	if [ "$commit_id" != "$commit_id0" ]; then
		echo "file beta has the wrong base commit ID" >&2
		test_done "$testroot" "1"
		return 1
	fi

	rm $testroot/wt/beta
	mkdir -p $testroot/wt/beta/psi
	mkdir -p $testroot/wt/new

	# update to the latest commit; this skips beta and the new file
	(cd $testroot/wt && got update > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "~  beta" > $testroot/stdout.expected
	echo "~  new" >> $testroot/stdout.expected
	echo "Updated to refs/heads/master: $commit_id1" \
		>> $testroot/stdout.expected
	echo "File paths obstructed by a non-regular file: 2" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	blob_id=`(cd $testroot/wt && got info beta | grep 'blob:' | \
		cut -d ':' -f 2 | tr -d ' ')`
	if [ "$blob_id" != "$blob_id0" ]; then
		echo "file beta has the wrong base blob ID" >&2
		test_done "$testroot" "1"
		return 1
	fi

	commit_id=`(cd $testroot/wt && got info beta | \
		grep 'based on commit:' | cut -d ':' -f 2 | tr -d ' ')`
	if [ "$commit_id" != "$commit_id0" ]; then
		echo "file beta has the wrong base commit ID" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# remove the directory which obstructs file beta
	rm -r $testroot/wt/beta

	# updating to the latest commit should now update beta
	(cd $testroot/wt && got update > $testroot/stdout)
	echo "!  beta" > $testroot/stdout.expected
	echo "~  new" >> $testroot/stdout.expected
	echo "Updated to refs/heads/master: $commit_id1" \
		>> $testroot/stdout.expected
	echo "File paths obstructed by a non-regular file: 1" \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	blob_id=`(cd $testroot/wt && got info beta | grep 'blob:' | \
		cut -d ':' -f 2 | tr -d ' ')`
	if [ "$blob_id" != "$blob_id1" ]; then
		echo "file beta has the wrong base blob ID" >&2
		test_done "$testroot" "1"
		return 1
	fi

	commit_id=`(cd $testroot/wt && got info beta | \
		grep 'based on commit:' | cut -d ':' -f 2 | tr -d ' ')`
	if [ "$commit_id" != "$commit_id1" ]; then
		echo "file beta has the wrong base commit ID: $commit_id" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "changed beta" > $testroot/content.expected
	cat $testroot/wt/beta > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_update_quiet() {
	local testroot=`test_init update_quiet`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"

	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update -q > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_update_binary_file() {
	local testroot=`test_init update_binary_file`
	local commit_id0=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cp /bin/ls $testroot/wt/foo
	chmod 755 $testroot/wt/foo
	(cd $testroot/wt && got add foo >/dev/null)
	(cd $testroot/wt && got commit -m 'add binary file' > /dev/null)
	local commit_id1=`git_show_head $testroot/repo`

	cp /bin/cat $testroot/wt/foo
	chmod 755 $testroot/wt/foo
	(cd $testroot/wt && got commit -m 'change binary file' > /dev/null)
	local commit_id2=`git_show_head $testroot/repo`

	cp /bin/cp $testroot/wt/foo
	chmod 755 $testroot/wt/foo
	(cd $testroot/wt && got commit -m 'change binary file' > /dev/null)
	local commit_id3=`git_show_head $testroot/repo`

	(cd $testroot/wt && got rm foo >/dev/null)
	(cd $testroot/wt && got commit -m 'remove binary file' > /dev/null)
	local commit_id4=`git_show_head $testroot/repo`

	# backdate the work tree to make it usable for updating
	(cd $testroot/wt && got up -c $commit_id0 > /dev/null)

	# update which adds a binary file
	(cd $testroot/wt && got up -c $commit_id1 > $testroot/stdout)

	echo "A  foo" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: $commit_id1" \
		>> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cp /bin/ls $testroot/content.expected
	chmod 755 $testroot/content.expected
	cat $testroot/wt/foo > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# update which adds a conflicting binary file
	(cd $testroot/wt && got up -c $commit_id0 > /dev/null)
	cp /bin/cat $testroot/wt/foo
	chmod 755 $testroot/wt/foo
	(cd $testroot/wt && got add foo > /dev/null)
	(cd $testroot/wt && got up -c $commit_id1 > $testroot/stdout)

	echo "C  foo" > $testroot/stdout.expected
	echo "Updated to refs/heads/master: $commit_id1" \
		>> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "Binary files differ and cannot be merged automatically:" \
		> $testroot/content.expected
	echo "<<<<<<< merged change: commit $commit_id1" \
		>> $testroot/content.expected
	echo -n "file " >> $testroot/content.expected
	ls $testroot/wt/foo-1-* >> $testroot/content.expected
	echo '=======' >> $testroot/content.expected
	echo -n "file " >> $testroot/content.expected
	ls $testroot/wt/foo-2-* >> $testroot/content.expected
	echo ">>>>>>>" >> $testroot/content.expected
	cat $testroot/wt/foo > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	cp /bin/ls $testroot/content.expected
	chmod 755 $testroot/content.expected
	cat $testroot/wt/foo-1-* > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	cp /bin/cat $testroot/content.expected
	chmod 755 $testroot/content.expected
	cat $testroot/wt/foo-2-* > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# tidy up
	(cd $testroot/wt && got revert -R . >/dev/null)
	rm $testroot/wt/foo-1-* $testroot/wt/foo-2-*
	(cd $testroot/wt && got up -c $commit_id1 > /dev/null)

	# update which changes a binary file
	(cd $testroot/wt && got up -c $commit_id2 > $testroot/stdout)

	echo "U  foo" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: $commit_id2" \
		>> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cp /bin/cat $testroot/content.expected
	chmod 755 $testroot/content.expected
	cat $testroot/wt/foo > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# update which changes a locally modified binary file
	cp /bin/ls $testroot/wt/foo
	chmod 755 $testroot/wt/foo
	(cd $testroot/wt && got up -c $commit_id3 > $testroot/stdout)

	echo "C  foo" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: $commit_id3" \
		>> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "Binary files differ and cannot be merged automatically:" \
		> $testroot/content.expected
	echo "<<<<<<< merged change: commit $commit_id3" \
		>> $testroot/content.expected
	echo -n "file " >> $testroot/content.expected
	ls $testroot/wt/foo-1-* >> $testroot/content.expected
	echo "||||||| 3-way merge base: commit $commit_id2" \
		>> $testroot/content.expected
	echo -n "file " >> $testroot/content.expected
	ls $testroot/wt/foo-orig-* >> $testroot/content.expected
	echo '=======' >> $testroot/content.expected
	echo -n "file " >> $testroot/content.expected
	ls $testroot/wt/foo-2-* >> $testroot/content.expected
	echo ">>>>>>>" >> $testroot/content.expected
	cat $testroot/wt/foo > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	cp /bin/cp $testroot/content.expected
	chmod 755 $testroot/content.expected
	cp $testroot/wt/foo-1-* $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	cp /bin/ls $testroot/content.expected
	chmod 755 $testroot/content.expected
	cp $testroot/wt/foo-2-* $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo 'C  foo' > $testroot/stdout.expected
	echo -n '?  ' >> $testroot/stdout.expected
	(cd $testroot/wt && ls foo-1-* >> $testroot/stdout.expected)
	echo -n '?  ' >> $testroot/stdout.expected
	(cd $testroot/wt && ls foo-2-* >> $testroot/stdout.expected)
	echo -n '?  ' >> $testroot/stdout.expected
	(cd $testroot/wt && ls foo-orig-* >> $testroot/stdout.expected)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# tidy up
	(cd $testroot/wt && got revert -R . > /dev/null)
	rm $testroot/wt/foo-orig-* $testroot/wt/foo-1-* $testroot/wt/foo-2-*

	# update which deletes a binary file
	(cd $testroot/wt && got up -c $commit_id4 > $testroot/stdout)
	echo "D  foo" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: $commit_id4" \
		>> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
	fi

	if [ -e $testroot/wt/foo ]; then
		echo "removed file foo still exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi
	test_done "$testroot" "0"
}

test_update_umask() {
	local testroot=`test_init update_binary_file`

	got checkout "$testroot/repo" "$testroot/wt" >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	rm "$testroot/wt/alpha"

	# using a subshell to avoid clobbering global umask
	(umask 022 && cd "$testroot/wt" && got update alpha) \
		>/dev/null 2>/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" $ret
		return 1
	fi

	if ! ls -l "$testroot/wt/alpha" | grep -q ^-rw-r--r--; then
		echo "alpha is not 0644" >&2
		test_done "$testroot" 1
		return 1
	fi

	rm "$testroot/wt/alpha"

	# using a subshell to avoid clobbering global umask
	(umask 044 && cd "$testroot/wt" && got update alpha) \
		>/dev/null 2>/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" $ret
		return 1
	fi

	if ! ls -l "$testroot/wt/alpha" | grep -q ^-rw-------; then
		echo "alpha is not 0600" >&2
		test_done "$testroot" 1
		return 1
	fi

	rm "$testroot/wt/alpha"

	# using a subshell to avoid clobbering global umask
	(umask 222 && cd "$testroot/wt" && got update alpha) \
		>/dev/null 2>/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" $ret
		return 1
	fi

	if ! ls -l "$testroot/wt/alpha" | grep -q ^-r--r--r--; then
		echo "alpha is not 0444" >&2
		test_done "$testroot" 1
		return 1;
	fi

	test_done "$testroot" 0
}

test_update_commit_keywords() {
	local testroot=`test_init update_commit_keywords`

	set -- "$(git_show_head $testroot/repo)"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "checkout failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

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
		set -- "$@" "$(git_show_head $testroot/repo)"
	done

	echo "got: reference base not found" > $testroot/stderr.expected

	(cd $testroot/wt && got update -cbase:-2 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 1 ]; then
		echo "update succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: 'basefoo': invalid commit keyword" > \
	    $testroot/stderr.expected

	(cd $testroot/wt && got update -c:basefoo:-2 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 1 ]; then
		echo "update succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: ':base::': invalid commit keyword" > \
	    $testroot/stderr.expected

	(cd $testroot/wt && got update -c:base:: 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 1 ]; then
		echo "update succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: ':head:++': invalid commit keyword" > \
	    $testroot/stderr.expected

	(cd $testroot/wt && got update -c:head:++ 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 1 ]; then
		echo "update succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: ':head:+x': invalid commit keyword" > \
	    $testroot/stderr.expected

	(cd $testroot/wt && got update -c:head:+x 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 1 ]; then
		echo "update succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: 'master::': invalid commit keyword" > \
	    $testroot/stderr.expected

	(cd $testroot/wt && got update -cmaster:: 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 1 ]; then
		echo "update succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: 'master:++': invalid commit keyword" > \
	    $testroot/stderr.expected

	(cd $testroot/wt && got update -cmaster:++ 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 1 ]; then
		echo "update succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: 'master:+x': invalid commit keyword" > \
	    $testroot/stderr.expected

	(cd $testroot/wt && got update -cmaster:+x 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 1 ]; then
		echo "update succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "U  alpha" > $testroot/stdout.expected
	echo "U  beta" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	echo $(pop_idx 7 $@) >> "$testroot/stdout.expected"

	(cd $testroot/wt && got update -c:base:-2 > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update failed unexpectedly" >&2
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

	echo "U  beta" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	echo $(pop_idx 8 $@) >> "$testroot/stdout.expected"

	(cd $testroot/wt && got update -cmaster:- > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update failed unexpectedly" >&2
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

	echo "alpha change 6" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "U  alpha" > $testroot/stdout.expected
	echo "U  beta" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	echo $(pop_idx 2 $@) >> "$testroot/stdout.expected"

	(cd $testroot/wt && got update -c:base:-6 > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update failed unexpectedly" >&2
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

	echo "beta change 1" > $testroot/content.expected
	cat $testroot/wt/beta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "U  alpha" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	echo $(pop_idx 3 $@) >> "$testroot/stdout.expected"

	(cd $testroot/wt && got update -c:base:+ > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update failed unexpectedly" >&2
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

	echo "alpha change 2" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "U  alpha" > $testroot/stdout.expected
	echo "U  beta" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	echo $(pop_idx 7 $@) >> "$testroot/stdout.expected"

	(cd $testroot/wt && got update -c:head:-2 > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update failed unexpectedly" >&2
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

	echo "alpha change 6" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# if - modifier is too great, use root commit
	echo "U  alpha" > $testroot/stdout.expected
	echo "U  beta" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	echo $(pop_idx 1 $@) >> "$testroot/stdout.expected"

	(cd $testroot/wt && got update -c:base:-20 > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update failed unexpectedly" >&2
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

	echo "alpha" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# if + modifier is too great, use HEAD commit
	echo "U  alpha" > $testroot/stdout.expected
	echo "U  beta" >> $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	echo $(pop_idx 9 $@) >> "$testroot/stdout.expected"

	(cd $testroot/wt && got update -c:head:+10 > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "update failed unexpectedly" >&2
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

	echo "alpha change 8" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_update_basic
run_test test_update_adds_file
run_test test_update_deletes_file
run_test test_update_deletes_dir
run_test test_update_deletes_dir_with_path_prefix
run_test test_update_deletes_dir_recursively
run_test test_update_sibling_dirs_with_common_prefix
run_test test_update_dir_with_dot_sibling
run_test test_update_moves_files_upwards
run_test test_update_moves_files_to_new_dir
run_test test_update_creates_missing_parent
run_test test_update_creates_missing_parent_with_subdir
run_test test_update_file_in_subsubdir
run_test test_update_changes_file_to_dir
run_test test_update_changes_dir_to_file
run_test test_update_changes_modified_file_to_dir
run_test test_update_merges_file_edits
run_test test_update_keeps_xbit
run_test test_update_clears_xbit
run_test test_update_restores_missing_file
run_test test_update_conflict_wt_add_vs_repo_add
run_test test_update_conflict_wt_edit_vs_repo_rm
run_test test_update_conflict_wt_rm_vs_repo_edit
run_test test_update_conflict_wt_rm_vs_repo_rm
run_test test_update_partial
run_test test_update_partial_add
run_test test_update_partial_rm
run_test test_update_partial_dir
run_test test_update_moved_branch_ref
run_test test_update_to_another_branch
run_test test_update_to_commit_on_wrong_branch
run_test test_update_bumps_base_commit_id
run_test test_update_tag
run_test test_update_toggles_xbit
run_test test_update_preserves_conflicted_file
run_test test_update_modified_submodules
run_test test_update_adds_submodule
run_test test_update_conflict_wt_file_vs_repo_submodule
run_test test_update_adds_symlink
run_test test_update_deletes_symlink
run_test test_update_symlink_conflicts
run_test test_update_single_file
run_test test_update_file_skipped_due_to_conflict
run_test test_update_file_skipped_due_to_obstruction
run_test test_update_quiet
run_test test_update_binary_file
run_test test_update_umask
run_test test_update_commit_keywords
