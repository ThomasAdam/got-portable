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

function test_revert_basic {
	local testroot=`test_init revert_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified epsilon/zeta" > $testroot/wt/epsilon/zeta

	echo 'R  epsilon/zeta' > $testroot/stdout.expected

	(cd $testroot/wt && got revert epsilon/zeta > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "zeta" > $testroot/content.expected
	cat $testroot/wt/epsilon/zeta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"

}

function test_revert_rm {
	local testroot=`test_init revert_rm`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rm beta >/dev/null)

	echo 'R  beta' > $testroot/stdout.expected

	(cd $testroot/wt && got revert beta > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "beta" > $testroot/content.expected
	cat $testroot/wt/beta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
		test_done "$testroot" "$ret"
}

function test_revert_add {
	local testroot=`test_init revert_add`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/wt/new
	(cd $testroot/wt && got add new >/dev/null)

	echo 'R  new' > $testroot/stdout.expected

	(cd $testroot/wt && got revert new > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/content.expected
	cat $testroot/wt/new > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo '?  new' > $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_revert_multiple {
	local testroot=`test_init revert_multiple`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	echo "modified epsilon/zeta" > $testroot/wt/epsilon/zeta

	echo 'R  alpha' > $testroot/stdout.expected
	echo 'R  epsilon/zeta' >> $testroot/stdout.expected

	(cd $testroot/wt && got revert alpha epsilon/zeta > $testroot/stdout)

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
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "zeta" > $testroot/content.expected
	cat $testroot/wt/epsilon/zeta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

function test_revert_file_in_new_subdir {
	local testroot=`test_init revert_file_in_new_subdir`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi


	mkdir -p $testroot/wt/newdir
	echo new > $testroot/wt/newdir/new
	(cd $testroot/wt && got add newdir/new > /dev/null)

	(cd $testroot/wt && got revert newdir/new > $testroot/stdout)

	echo "R  newdir/new" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)

	echo "?  newdir/new" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

function test_revert_no_arguments {
	local testroot=`test_init revert_no_arguments`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified epsilon/zeta" > $testroot/wt/epsilon/zeta

	(cd $testroot/wt && got revert > $testroot/stdout 2> $testroot/stderr)
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "revert command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "usage: got revert [-p] [-F response-script] [-R] path ..." \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

function test_revert_directory {
	local testroot=`test_init revert_directory`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified epsilon/zeta" > $testroot/wt/epsilon/zeta

	(cd $testroot/wt && got revert . > $testroot/stdout 2> $testroot/stderr)
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "got revert command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "got: reverting directories requires -R option" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got revert -R . > $testroot/stdout)

	echo 'R  epsilon/zeta' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "zeta" > $testroot/content.expected
	cat $testroot/wt/epsilon/zeta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
	fi
	test_done "$testroot" "$ret"
}

function test_revert_directory_unknown {
	local testroot=`test_init revert_directory_unknown`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	echo "new untracked file" > $testroot/wt/epsilon/new_file
	echo "modified epsilon/zeta" > $testroot/wt/epsilon/zeta

	(cd $testroot/wt && got revert -R . > $testroot/stdout)

	echo 'R  alpha' > $testroot/stdout.expected
	echo '?  epsilon/new_file' >> $testroot/stdout.expected
	echo 'R  epsilon/zeta' >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new untracked file" > $testroot/content.expected
	cat $testroot/wt/epsilon/new_file > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "zeta" > $testroot/content.expected
	cat $testroot/wt/epsilon/zeta > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
	fi

	test_done "$testroot" "$ret"
}

function test_revert_patch {
	local testroot=`test_init revert_patch`

	jot 16 > $testroot/repo/numbers
	(cd $testroot/repo && git add numbers)
	git_commit $testroot/repo -m "added numbers file"
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	sed -i -e 's/^2$/a/' $testroot/wt/numbers
	sed -i -e 's/^7$/b/' $testroot/wt/numbers
	sed -i -e 's/^16$/c/' $testroot/wt/numbers

	(cd $testroot/wt && got diff > $testroot/numbers.diff)

	# don't revert any hunks
	printf "n\nn\nn\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		numbers > $testroot/stdout)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got revert command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	cat > $testroot/stdout.expected <<EOF
-----------------------------------------------
@@ -1,5 +1,5 @@
 1
-2
+a
 3
 4
 5
-----------------------------------------------
M  numbers (change 1 of 3)
revert this change? [y/n/q] n
-----------------------------------------------
@@ -4,7 +4,7 @@
 4
 5
 6
-7
+b
 8
 9
 10
-----------------------------------------------
M  numbers (change 2 of 3)
revert this change? [y/n/q] n
-----------------------------------------------
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 3 of 3)
revert this change? [y/n/q] n
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "M  numbers" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff > $testroot/stdout)
	cmp -s $testroot/numbers.diff $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/numbers.diff $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# revert first hunk
	printf "y\nn\nn\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		numbers > $testroot/stdout)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got revert command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	cat > $testroot/stdout.expected <<EOF
-----------------------------------------------
@@ -1,5 +1,5 @@
 1
-2
+a
 3
 4
 5
-----------------------------------------------
M  numbers (change 1 of 3)
revert this change? [y/n/q] y
-----------------------------------------------
@@ -4,7 +4,7 @@
 4
 5
 6
-7
+b
 8
 9
 10
-----------------------------------------------
M  numbers (change 2 of 3)
revert this change? [y/n/q] n
-----------------------------------------------
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 3 of 3)
revert this change? [y/n/q] n
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "M  numbers" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "diff $commit_id $testroot/wt" > $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i -c $commit_id \
		| grep 'numbers$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + numbers' >> $testroot/stdout.expected
	cat >> $testroot/stdout.expected <<EOF
--- numbers
+++ numbers
@@ -4,7 +4,7 @@
 4
 5
 6
-7
+b
 8
 9
 10
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
EOF
	(cd $testroot/wt && got diff > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# put first hunk back
	sed -i -e 's/^2$/a/' $testroot/wt/numbers

	# revert middle hunk
	printf "n\ny\nn\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		numbers > $testroot/stdout)

	cat > $testroot/stdout.expected <<EOF
-----------------------------------------------
@@ -1,5 +1,5 @@
 1
-2
+a
 3
 4
 5
-----------------------------------------------
M  numbers (change 1 of 3)
revert this change? [y/n/q] n
-----------------------------------------------
@@ -4,7 +4,7 @@
 4
 5
 6
-7
+b
 8
 9
 10
-----------------------------------------------
M  numbers (change 2 of 3)
revert this change? [y/n/q] y
-----------------------------------------------
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 3 of 3)
revert this change? [y/n/q] n
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "M  numbers" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff > $testroot/stdout)

	echo "diff $commit_id $testroot/wt" > $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i -c $commit_id \
		| grep 'numbers$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + numbers' >> $testroot/stdout.expected
	cat >> $testroot/stdout.expected <<EOF
--- numbers
+++ numbers
@@ -1,5 +1,5 @@
 1
-2
+a
 3
 4
 5
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# revert last hunk
	printf "n\ny\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		numbers > $testroot/stdout)
	cat > $testroot/stdout.expected <<EOF
-----------------------------------------------
@@ -1,5 +1,5 @@
 1
-2
+a
 3
 4
 5
-----------------------------------------------
M  numbers (change 1 of 2)
revert this change? [y/n/q] n
-----------------------------------------------
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 2 of 2)
revert this change? [y/n/q] y
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff > $testroot/stdout)

	echo "diff $commit_id $testroot/wt" > $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i -c $commit_id \
		| grep 'numbers$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + numbers' >> $testroot/stdout.expected
	cat >> $testroot/stdout.expected <<EOF
--- numbers
+++ numbers
@@ -1,5 +1,5 @@
 1
-2
+a
 3
 4
 5
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_revert_patch_added {
	local testroot=`test_init revert_patch_added`
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new" > $testroot/wt/epsilon/new
	(cd $testroot/wt && got add epsilon/new > /dev/null)

	printf "n\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		epsilon/new > $testroot/stdout)

	echo "A  epsilon/new" > $testroot/stdout.expected
	echo "revert this addition? [y/n] n" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "A  epsilon/new" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	printf "y\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		epsilon/new > $testroot/stdout)

	echo "A  epsilon/new" > $testroot/stdout.expected
	echo "revert this addition? [y/n] y" >> $testroot/stdout.expected
	echo "R  epsilon/new" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "?  epsilon/new" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_revert_patch_removed {
	local testroot=`test_init revert_patch_removed`
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rm beta > /dev/null)

	printf "n\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		beta > $testroot/stdout)
	echo "D  beta" > $testroot/stdout.expected
	echo "revert this deletion? [y/n] n" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "D  beta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	printf "y\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		beta > $testroot/stdout)

	echo "D  beta" > $testroot/stdout.expected
	echo "revert this deletion? [y/n] y" >> $testroot/stdout.expected
	echo "R  beta" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_revert_patch_one_change {
	local testroot=`test_init revert_patch_one_change`

	jot 16 > $testroot/repo/numbers
	(cd $testroot/repo && git add numbers)
	git_commit $testroot/repo -m "added numbers file"
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure file size is changed. Avoids race condition causing test
	# failures where 'got revert' does not see changes to revert if
	# timestamps and size in stat info remain unchanged.
	sed -i -e 's/^2$/aa/' $testroot/wt/numbers

	# revert change with -p
	printf "y\n" > $testroot/patchscript
	(cd $testroot/wt && got revert -F $testroot/patchscript -p \
		numbers > $testroot/stdout)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got revert command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	cat > $testroot/stdout.expected <<EOF
-----------------------------------------------
@@ -1,5 +1,5 @@
 1
-2
+aa
 3
 4
 5
-----------------------------------------------
M  numbers (change 1 of 1)
revert this change? [y/n/q] y
EOF
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "got revert command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff > $testroot/stdout)
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

run_test test_revert_basic
run_test test_revert_rm
run_test test_revert_add
run_test test_revert_multiple
run_test test_revert_file_in_new_subdir
run_test test_revert_no_arguments
run_test test_revert_directory
run_test test_revert_directory_unknown
run_test test_revert_patch
run_test test_revert_patch_added
run_test test_revert_patch_removed
run_test test_revert_patch_one_change
