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

function test_status_basic {
	local testroot=`test_init status_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	if [ "$?" != "0" ]; then
		test_done "$testroot" "$?"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	echo "unversioned file" > $testroot/wt/foo
	rm $testroot/wt/epsilon/zeta
	touch $testroot/wt/beta

	echo 'M  alpha' > $testroot/stdout.expected
	echo '!  epsilon/zeta' >> $testroot/stdout.expected
	echo '?  foo' >> $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp $testroot/stdout.expected $testroot/stdout
	if [ "$?" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$?"
		return 1
	fi

	test_done "$testroot" "0"
}

function test_status_subdir_no_mods {
	local testroot=`test_init status_subdir_no_mods 1`

	mkdir $testroot/repo/Basic/
	mkdir $testroot/repo/Basic/Targets/
	touch $testroot/repo/Basic/Targets/AArch64.cpp
	touch $testroot/repo/Basic/Targets.cpp
	touch $testroot/repo/Basic/Targets.h
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "add subdir with files"

	got checkout $testroot/repo $testroot/wt > /dev/null
	if [ "$?" != "0" ]; then
		test_done "$testroot" "$?"
		return 1
	fi

	touch $testroot/stdout.expected

	# This used to erroneously print:
	#
	# !  Basic/Targets.cpp
	# ?  Basic/Targets.cpp
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp $testroot/stdout.expected $testroot/stdout
	if [ "$?" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$?"
		return 1
	fi

	test_done "$testroot" "0"
}

function test_status_subdir_no_mods2 {
	local testroot=`test_init status_subdir_no_mods2 1`

	mkdir $testroot/repo/AST
	touch $testroot/repo/AST/APValue.cpp
	mkdir $testroot/repo/ASTMatchers
	touch $testroot/repo/ASTMatchers/ASTMatchFinder.cpp
	mkdir $testroot/repo/Frontend
	touch $testroot/repo/Frontend/ASTConsumers.cpp
	mkdir $testroot/repo/Frontend/Rewrite
	touch $testroot/repo/Frontend/Rewrite/CMakeLists.txt
	mkdir $testroot/repo/FrontendTool
	touch $testroot/repo/FrontendTool/CMakeLists.txt
	touch $testroot/repo/FrontendTool/ExecuteCompilerInvocation.cpp
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "add subdir with files"

	got checkout $testroot/repo $testroot/wt > /dev/null
	if [ "$?" != "0" ]; then
		test_done "$testroot" "$?"
		return 1
	fi

	touch $testroot/stdout.expected

	# This used to erroneously print:
	#
	# !  AST/APValue.cpp
	# ?  AST/APValue.cpp
	# !  Frontend/ASTConsumers.cpp
	# !  Frontend/Rewrite/CMakeLists.txt
	# ?  Frontend/ASTConsumers.cpp
	# ?  Frontend/Rewrite/CMakeLists.txt
	(cd $testroot/wt && got status > $testroot/stdout)

	cmp $testroot/stdout.expected $testroot/stdout
	if [ "$?" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$?"
		return 1
	fi

	test_done "$testroot" "0"
}

function test_status_obstructed {
	local testroot=`test_init status_obstructed`

	got checkout $testroot/repo $testroot/wt > /dev/null
	if [ "$?" != "0" ]; then
		test_done "$testroot" "$?"
		return 1
	fi

	rm $testroot/wt/epsilon/zeta
	mkdir $testroot/wt/epsilon/zeta

	echo '~  epsilon/zeta' > $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp $testroot/stdout.expected $testroot/stdout
	if [ "$?" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$?"
		return 1
	fi

	test_done "$testroot" "0"
}

run_test test_status_basic
run_test test_status_subdir_no_mods
run_test test_status_subdir_no_mods2
run_test test_status_obstructed
