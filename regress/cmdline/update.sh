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
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"

	echo "U  alpha" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

function test_update_adds_file {
	local testroot=`test_init update_adds_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
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

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new" >> $testroot/content.expected
	cat $testroot/wt/gamma/new > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

function test_update_deletes_file {
	local testroot=`test_init update_deletes_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git_rm $testroot/repo beta)
	git_commit $testroot/repo -m "deleting a file"

	echo "D  beta" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
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

function test_update_deletes_dir {
	local testroot=`test_init update_deletes_dir`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git_rm $testroot/repo -r epsilon)
	git_commit $testroot/repo -m "deleting a directory"

	echo "D  epsilon/zeta" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
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

function test_update_deletes_dir_with_path_prefix {
	local testroot=`test_init update_deletes_dir_with_path_prefix`
	local first_rev=`git_show_head $testroot/repo`

	mkdir $testroot/repo/epsilon/psi
	echo mu > $testroot/repo/epsilon/psi/mu
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "adding a sub-directory beneath epsilon"

	# check out the epsilon/ sub-tree
	got checkout -p epsilon $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# update back to first commit and expect psi/mu to be deleted
	echo "D  psi/mu" > $testroot/stdout.expected
	echo "Updated to commit $first_rev" >> $testroot/stdout.expected

	(cd $testroot/wt && got update -c $first_rev > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
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
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# update back to first commit and expect psi/mu to be deleted
	echo "D  psi/chi/tau" > $testroot/stdout.expected
	echo "D  psi/mu" >> $testroot/stdout.expected
	echo "Updated to commit $first_rev" >> $testroot/stdout.expected

	(cd $testroot/wt && got update -c $first_rev > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$?" != "0" ]; then
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

function test_update_sibling_dirs_with_common_prefix {
	local testroot=`test_init update_sibling_dirs_with_common_prefix`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
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

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
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

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_update_dir_with_dot_sibling {
	local testroot=`test_init update_dir_with_dot_sibling`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$ret"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo text > $testroot/repo/epsilon.txt
	(cd $testroot/repo && git add epsilon.txt)
	git_commit $testroot/repo -m "adding sibling of epsilon"
	echo change > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "changing epsilon/zeta"

	echo "U  epsilon/zeta" > $testroot/stdout.expected
	echo "A  epsilon.txt" >> $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "another change" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "changing epsilon/zeta again"

	echo "U  epsilon/zeta" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_update_moves_files_upwards {
	local testroot=`test_init update_moves_files_upwards`

	mkdir $testroot/repo/epsilon/psi
	echo mu > $testroot/repo/epsilon/psi/mu
	mkdir $testroot/repo/epsilon/psi/chi
	echo tau > $testroot/repo/epsilon/psi/chi/tau
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "adding a sub-directory beneath epsilon"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git mv epsilon/psi/mu epsilon/mu)
	(cd $testroot/repo && git mv epsilon/psi/chi/tau epsilon/psi/tau)
	git_commit $testroot/repo -m "moving files upwards"

	echo "A  epsilon/mu" > $testroot/stdout.expected
	echo "D  epsilon/psi/chi/tau" >> $testroot/stdout.expected
	echo "D  epsilon/psi/mu" >> $testroot/stdout.expected
	echo "A  epsilon/psi/tau" >> $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
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

function test_update_moves_files_to_new_dir {
	local testroot=`test_init update_moves_files_to_new_dir`

	mkdir $testroot/repo/epsilon/psi
	echo mu > $testroot/repo/epsilon/psi/mu
	mkdir $testroot/repo/epsilon/psi/chi
	echo tau > $testroot/repo/epsilon/psi/chi/tau
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "adding a sub-directory beneath epsilon"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/repo/epsilon-new/psi
	(cd $testroot/repo && git mv epsilon/psi/mu epsilon-new/mu)
	(cd $testroot/repo && git mv epsilon/psi/chi/tau epsilon-new/psi/tau)
	git_commit $testroot/repo -m "moving files upwards"

	echo "D  epsilon/psi/chi/tau" > $testroot/stdout.expected
	echo "D  epsilon/psi/mu" >> $testroot/stdout.expected
	echo "A  epsilon-new/mu" >> $testroot/stdout.expected
	echo "A  epsilon-new/psi/tau" >> $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
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

function test_update_creates_missing_parent {
	local testroot=`test_init update_creates_missing_parent 1`

	touch $testroot/repo/Makefile
	touch $testroot/repo/snake.6
	touch $testroot/repo/snake.c
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "adding initial snake tree"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/repo/snake
	(cd $testroot/repo && git mv Makefile snake.6 snake.c snake)
	touch $testroot/repo/snake/move.c
	touch $testroot/repo/snake/pathnames.h
	touch $testroot/repo/snake/snake.h
	mkdir -p $testroot/repo/snscore
	touch $testroot/repo/snscore/Makefile
	touch $testroot/repo/snscore/snscore.c
	(cd $testroot/repo && git add .)
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
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_update_creates_missing_parent_with_subdir {
	local testroot=`test_init update_creates_missing_parent_with_subdir 1`

	touch $testroot/repo/Makefile
	touch $testroot/repo/snake.6
	touch $testroot/repo/snake.c
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "adding initial snake tree"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	mkdir -p $testroot/repo/sss/snake
	(cd $testroot/repo && git mv Makefile snake.6 snake.c sss/snake)
	touch $testroot/repo/sss/snake/move.c
	touch $testroot/repo/sss/snake/pathnames.h
	touch $testroot/repo/sss/snake/snake.h
	mkdir -p $testroot/repo/snscore
	touch $testroot/repo/snscore/Makefile
	touch $testroot/repo/snscore/snscore.c
	(cd $testroot/repo && git add .)
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
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "0"
}

function test_update_file_in_subsubdir {
	local testroot=`test_init update_fle_in_subsubdir 1`

	touch $testroot/repo/Makefile
	mkdir -p $testroot/repo/altq
	touch $testroot/repo/altq/if_altq.h
	mkdir -p $testroot/repo/arch/alpha
	touch $testroot/repo/arch/alpha/Makefile
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "adding initial tree"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo change > $testroot/repo/arch/alpha/Makefile
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "changed a file"

	echo "U  arch/alpha/Makefile" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "0"
}

function test_update_merges_file_edits {
	local testroot=`test_init update_merges_file_edits`

	echo "1" > $testroot/repo/numbers
	echo "2" >> $testroot/repo/numbers
	echo "3" >> $testroot/repo/numbers
	echo "4" >> $testroot/repo/numbers
	echo "5" >> $testroot/repo/numbers
	echo "6" >> $testroot/repo/numbers
	echo "7" >> $testroot/repo/numbers
	echo "8" >> $testroot/repo/numbers
	(cd $testroot/repo && git add numbers)
	git_commit $testroot/repo -m "added numbers file"

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/repo/alpha
	echo "modified beta" > $testroot/repo/beta
	sed -i 's/2/22/' $testroot/repo/numbers
	git_commit $testroot/repo -m "modified 3 files"

	echo "modified alpha, too" > $testroot/wt/alpha
	touch $testroot/wt/beta
	sed -i 's/7/77/' $testroot/wt/numbers

	echo "C  alpha" > $testroot/stdout.expected
	echo "U  beta" >> $testroot/stdout.expected
	echo "G  numbers" >> $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n "<<<<<<< commit " > $testroot/content.expected
	git_show_head $testroot/repo >> $testroot/content.expected
	echo >> $testroot/content.expected
	echo "modified alpha" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "modified alpha, too" >> $testroot/content.expected
	echo '>>>>>>> alpha' >> $testroot/content.expected
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
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

function test_update_keeps_xbit {
	local testroot=`test_init update_keeps_xbit 1`

	touch $testroot/repo/xfile
	chmod +x $testroot/repo/xfile
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "adding executable file"

	got checkout $testroot/repo $testroot/wt > $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo foo > $testroot/repo/xfile
	git_commit $testroot/repo -m "changed executable file"

	echo "U  xfile" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	ls -l $testroot/wt/xfile | grep -q '^-rwx'
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "file is not executable" >&2
		ls -l $testroot/wt/xfile >&2
	fi
	test_done "$testroot" "$ret"
}

function test_update_clears_xbit {
	local testroot=`test_init update_clears_xbit 1`

	touch $testroot/repo/xfile
	chmod +x $testroot/repo/xfile
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "adding executable file"

	got checkout $testroot/repo $testroot/wt > $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	ls -l $testroot/wt/xfile | grep -q '^-rwx'
	ret="$?"
	if [ "$ret" != "0" ]; then
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
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	ls -l $testroot/wt/xfile | grep -q '^-rw-'
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "file is unexpectedly executable" >&2
		ls -l $testroot/wt/xfile >&2
	fi
	test_done "$testroot" "$ret"
}

function test_update_restores_missing_file {
	local testroot=`test_init update_restores_missing_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	rm $testroot/wt/alpha

	echo "!  alpha" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "alpha" > $testroot/content.expected

	cat $testroot/wt/alpha > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

function test_update_conflict_wt_add_vs_repo_add {
	local testroot=`test_init update_conflict_wt_add_vs_repo_add`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new" > $testroot/repo/gamma/new
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "adding a new file"

	echo "also new" > $testroot/wt/gamma/new
	(cd $testroot/wt && got add gamma/new >/dev/null)

	(cd $testroot/wt && got update > $testroot/stdout)

	echo "C  gamma/new" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n "<<<<<<< commit " > $testroot/content.expected
	git_show_head $testroot/repo >> $testroot/content.expected
	echo >> $testroot/content.expected
	echo "new" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "also new" >> $testroot/content.expected
	echo '>>>>>>> gamma/new' >> $testroot/content.expected

	cat $testroot/wt/gamma/new > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# resolve the conflict
	echo "new and also new" > $testroot/wt/gamma/new
	echo 'M  gamma/new' > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_update_conflict_wt_edit_vs_repo_rm {
	local testroot=`test_init update_conflict_wt_edit_vs_repo_rm`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git rm -q beta)
	git_commit $testroot/repo -m "removing a file"

	echo "modified beta" > $testroot/wt/beta

	(cd $testroot/wt && got update > $testroot/stdout)

	echo "G  beta" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified beta" > $testroot/content.expected

	cat $testroot/wt/beta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# beta is now an added file... we don't flag tree conflicts yet
	echo 'A  beta' > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_update_conflict_wt_rm_vs_repo_edit {
	local testroot=`test_init update_conflict_wt_rm_vs_repo_edit`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified beta" > $testroot/repo/beta
	git_commit $testroot/repo -m "modified a file"

	(cd $testroot/wt && got rm beta > /dev/null)

	(cd $testroot/wt && got update > $testroot/stdout)

	echo "G  beta" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# beta remains a deleted file... we don't flag tree conflicts yet
	echo 'D  beta' > $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# 'got diff' should show post-update contents of beta being deleted
	local head_rev=`git_show_head $testroot/repo`
	echo "diff $head_rev $testroot/wt" > $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'beta$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + /dev/null' >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ beta' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-modified beta' >> $testroot/stdout.expected

	(cd $testroot/wt && got diff > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_update_conflict_wt_rm_vs_repo_rm {
	local testroot=`test_init update_conflict_wt_rm_vs_repo_rm`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git rm -q beta)
	git_commit $testroot/repo -m "removing a file"

	(cd $testroot/wt && got rm beta > /dev/null)

	(cd $testroot/wt && got update > $testroot/stdout)

	echo "D  beta" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# beta is now gone... we don't flag tree conflicts yet
	echo 'got: bad path' > $testroot/stderr.expected
	(cd $testroot/wt && got status beta 2> $testroot/stderr)
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
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

function test_update_partial {
	local testroot=`test_init update_partial`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/repo/alpha
	echo "modified beta" > $testroot/repo/beta
	echo "modified epsilon/zeta" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "modified two files"

	for f in alpha beta epsilon/zeta; do
		echo "U  $f" > $testroot/stdout.expected
		echo -n "Updated to commit " >> $testroot/stdout.expected
		git_show_head $testroot/repo >> $testroot/stdout.expected
		echo >> $testroot/stdout.expected

		(cd $testroot/wt && got update $f > $testroot/stdout)

		cmp -s $testroot/stdout.expected $testroot/stdout
		ret="$?"
		if [ "$ret" != "0" ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi

		echo "modified $f" > $testroot/content.expected
		cat $testroot/wt/$f > $testroot/content

		cmp -s $testroot/content.expected $testroot/content
		ret="$?"
		if [ "$ret" != "0" ]; then
			diff -u $testroot/content.expected $testroot/content
			test_done "$testroot" "$ret"
			return 1
		fi
	done
	test_done "$testroot" "$ret"
}

function test_update_partial_add {
	local testroot=`test_init update_partial_add`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new" > $testroot/repo/new
	echo "epsilon/new2" > $testroot/repo/epsilon/new2
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "added two files"

	for f in new epsilon/new2; do
		echo "A  $f" > $testroot/stdout.expected
		echo -n "Updated to commit " >> $testroot/stdout.expected
		git_show_head $testroot/repo >> $testroot/stdout.expected
		echo >> $testroot/stdout.expected

		(cd $testroot/wt && got update $f > $testroot/stdout)

		cmp -s $testroot/stdout.expected $testroot/stdout
		ret="$?"
		if [ "$ret" != "0" ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi

		echo "$f" > $testroot/content.expected
		cat $testroot/wt/$f > $testroot/content

		cmp -s $testroot/content.expected $testroot/content
		ret="$?"
		if [ "$ret" != "0" ]; then
			diff -u $testroot/content.expected $testroot/content
			test_done "$testroot" "$ret"
			return 1
		fi
	done
	test_done "$testroot" "$ret"
}

function test_update_partial_rm {
	local testroot=`test_init update_partial_rm`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git rm -q alpha)
	(cd $testroot/repo && git rm -q epsilon/zeta)
	git_commit $testroot/repo -m "removed two files"

	for f in alpha epsilon/zeta; do
		echo "got: no such entry found in tree" \
			> $testroot/stderr.expected

		(cd $testroot/wt && got update $f 2> $testroot/stderr)
		ret="$?"
		if [ "$ret" == "0" ]; then
			echo "update succeeded unexpectedly" >&2
			test_done "$testroot" "1"
			return 1
		fi

		cmp -s $testroot/stderr.expected $testroot/stderr
		ret="$?"
		if [ "$ret" != "0" ]; then
			diff -u $testroot/stderr.expected $testroot/stderr
			test_done "$testroot" "$ret"
			return 1
		fi
	done
	test_done "$testroot" "$ret"
}

function test_update_partial_dir {
	local testroot=`test_init update_partial_dir`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/repo/alpha
	echo "modified beta" > $testroot/repo/beta
	echo "modified epsilon/zeta" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "modified two files"

	echo "U  epsilon/zeta" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update epsilon > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified epsilon/zeta" > $testroot/content.expected
	cat $testroot/wt/epsilon/zeta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi
	test_done "$testroot" "$ret"

}

function test_update_moved_branch_ref {
	local testroot=`test_init update_moved_branch_ref`

	git clone -q --mirror $testroot/repo $testroot/repo2

	echo "modified alpha with git" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha with git"

	got checkout $testroot/repo2 $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha with got" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "modified alpha with got" > /dev/null)

	# + xxxxxxx...yyyyyyy master     -> master  (forced update)
	(cd $testroot/repo2 && git fetch -q --all)

	echo -n > $testroot/stdout.expected
	echo "got: new branch or rebase required" >> $testroot/stderr.expected

	(cd $testroot/wt && got update > $testroot/stdout 2> $testroot/stderr)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

function test_update_to_another_branch {
	local testroot=`test_init update_to_another_branch`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'refs/heads/master'> $testroot/head-ref.expected
	cmp -s $testroot/head-ref.expected $testroot/wt/.got/head-ref
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/head-ref.expected $testroot/wt/.got/head-ref
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/repo && git checkout -q -b newbranch)
	echo "modified alpha on new branch" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha on new branch"

	echo "modified alpha in work tree" > $testroot/wt/alpha

	echo "C  alpha" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update -b newbranch > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n "<<<<<<< commit " > $testroot/content.expected
	git_show_head $testroot/repo >> $testroot/content.expected
	echo >> $testroot/content.expected
	echo "modified alpha on new branch" >> $testroot/content.expected
	echo "=======" >> $testroot/content.expected
	echo "modified alpha in work tree" >> $testroot/content.expected
	echo '>>>>>>> alpha' >> $testroot/content.expected

	cat $testroot/wt/alpha > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'refs/heads/newbranch'> $testroot/head-ref.expected
	cmp -s $testroot/head-ref.expected $testroot/wt/.got/head-ref
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/head-ref.expected $testroot/wt/.got/head-ref
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

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
