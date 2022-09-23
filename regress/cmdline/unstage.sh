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

test_unstage_basic() {
	local testroot=`test_init unstage_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified file" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta > /dev/null)
	echo "new file" > $testroot/wt/foo
	(cd $testroot/wt && got add foo > /dev/null)

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage alpha beta foo > /dev/null)

	(cd $testroot/wt && got unstage > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got unstage command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo 'G  alpha' > $testroot/stdout.expected
	echo 'D  beta' >> $testroot/stdout.expected
	echo 'G  foo' >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'M  alpha' > $testroot/stdout.expected
	echo 'D  beta' >> $testroot/stdout.expected
	echo 'A  foo' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_unstage_unversioned() {
	local testroot=`test_init unstage_unversioned`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified file" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta > /dev/null)
	echo "new file" > $testroot/wt/foo
	(cd $testroot/wt && got add foo > /dev/null)

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage > /dev/null)

	touch $testroot/wt/unversioned-file

	(cd $testroot/wt && got status > $testroot/stdout)
	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected
	echo "?  unversioned-file" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got unstage > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got unstage command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo 'G  alpha' > $testroot/stdout.expected
	echo 'D  beta' >> $testroot/stdout.expected
	echo 'G  foo' >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage > /dev/null)

	# unstaging an unversioned path is a no-op
	(cd $testroot/wt && got unstage unversioned > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got unstage command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected
	echo "?  unversioned-file" >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_unstage_nonexistent() {
	local testroot=`test_init unstage_nonexistent`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified file" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta > /dev/null)
	echo "new file" > $testroot/wt/foo
	(cd $testroot/wt && got add foo > /dev/null)

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage > /dev/null)

	# unstaging a non-existent file is a no-op
	(cd $testroot/wt && got unstage nonexistent-file > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got unstage command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_unstage_patch() {
	local testroot=`test_init unstage_patch`

	jot 16 > $testroot/repo/numbers
	(cd $testroot/repo && git add numbers)
	git_commit $testroot/repo -m "added numbers file"
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	sed -i -e 's/^2$/a/' $testroot/wt/numbers
	sed -i -e 's/^7$/b/' $testroot/wt/numbers
	sed -i -e 's/^16$/c/' $testroot/wt/numbers

	(cd $testroot/wt && got stage > /dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got stage command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# don't unstage any hunks
	printf "n\nn\nn\n" > $testroot/patchscript
	(cd $testroot/wt && got unstage -F $testroot/patchscript -p \
		numbers > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got unstage command failed unexpectedly" >&2
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
unstage this change? [y/n/q] n
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
unstage this change? [y/n/q] n
-----------------------------------------------
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 3 of 3)
unstage this change? [y/n/q] n
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo " M numbers" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# unstage middle hunk
	printf "n\ny\nn\n" > $testroot/patchscript
	(cd $testroot/wt && got unstage -F $testroot/patchscript -p \
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
unstage this change? [y/n/q] n
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
unstage this change? [y/n/q] y
-----------------------------------------------
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 3 of 3)
unstage this change? [y/n/q] n
G  numbers
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "MM numbers" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff -s > $testroot/stdout)

	echo "diff -s $testroot/wt" > $testroot/stdout.expected
	echo "commit - $commit_id" >> $testroot/stdout.expected
	echo "path + $testroot/wt (staged changes)" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i -c $commit_id \
		| grep 'numbers$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l numbers) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
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
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff > $testroot/stdout)
	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $commit_id" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l numbers) | cut -d' ' -f 1  | \
		tr -d '\n' >> $testroot/stdout.expected
	echo " (staged)" >> $testroot/stdout.expected
	echo "file + numbers" >> $testroot/stdout.expected
	cat >> $testroot/stdout.expected <<EOF
--- numbers
+++ numbers
@@ -4,7 +4,7 @@ a
 4
 5
 6
-7
+b
 8
 9
 10
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage >/dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got stage command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo " M numbers" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# unstage last hunk
	printf "n\nn\ny\n" > $testroot/patchscript
	(cd $testroot/wt && got unstage -F $testroot/patchscript -p \
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
unstage this change? [y/n/q] n
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
unstage this change? [y/n/q] n
-----------------------------------------------
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 3 of 3)
unstage this change? [y/n/q] y
G  numbers
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "MM numbers" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff -s > $testroot/stdout)

	echo "diff -s $testroot/wt" > $testroot/stdout.expected
	echo "commit - $commit_id" >> $testroot/stdout.expected
	echo "path + $testroot/wt (staged changes)" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i -c $commit_id \
		| grep 'numbers$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l numbers) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	cat >> $testroot/stdout.expected <<EOF
--- numbers
+++ numbers
@@ -1,10 +1,10 @@
 1
-2
+a
 3
 4
 5
 6
-7
+b
 8
 9
 10
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff > $testroot/stdout)
	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $commit_id" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l numbers) | cut -d' ' -f 1 | \
		tr -d '\n' >> $testroot/stdout.expected
	echo " (staged)" >> $testroot/stdout.expected
	echo "file + numbers" >> $testroot/stdout.expected
	cat >> $testroot/stdout.expected <<EOF
--- numbers
+++ numbers
@@ -13,4 +13,4 @@ b
 13
 14
 15
-16
+c
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage >/dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got stage command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo " M numbers" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# unstage all hunks
	printf "y\ny\ny\n" > $testroot/patchscript
	(cd $testroot/wt && got unstage -F $testroot/patchscript -p \
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
unstage this change? [y/n/q] y
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
unstage this change? [y/n/q] y
-----------------------------------------------
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 3 of 3)
unstage this change? [y/n/q] y
G  numbers
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "M  numbers" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff -s > $testroot/stdout)
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff > $testroot/stdout)

	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $commit_id" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i -c $commit_id \
		| grep 'numbers$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + numbers' >> $testroot/stdout.expected
	cat >> $testroot/stdout.expected <<EOF
--- numbers
+++ numbers
@@ -1,10 +1,10 @@
 1
-2
+a
 3
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
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

test_unstage_patch_added() {
	local testroot=`test_init unstage_patch_added`
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new" > $testroot/wt/epsilon/new
	(cd $testroot/wt && got add epsilon/new > /dev/null)

	(cd $testroot/wt && got stage > /dev/null)

	printf "y\n" > $testroot/patchscript
	(cd $testroot/wt && got unstage -F $testroot/patchscript -p \
		epsilon/new > $testroot/stdout)

	echo "A  epsilon/new" > $testroot/stdout.expected
	echo "unstage this addition? [y/n] y" >> $testroot/stdout.expected
	echo "G  epsilon/new" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "A  epsilon/new" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff -s > $testroot/stdout)
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff > $testroot/stdout)

	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $commit_id" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo 'file + epsilon/new (mode 644)' >> $testroot/stdout.expected
	echo "--- /dev/null" >> $testroot/stdout.expected
	echo "+++ epsilon/new" >> $testroot/stdout.expected
	echo "@@ -0,0 +1 @@" >> $testroot/stdout.expected
	echo "+new" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_unstage_patch_removed() {
	local testroot=`test_init unstage_patch_removed`
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rm beta > /dev/null)
	(cd $testroot/wt && got stage > /dev/null)

	printf "y\n" > $testroot/patchscript
	(cd $testroot/wt && got unstage -F $testroot/patchscript -p \
		beta > $testroot/stdout)

	echo "D  beta" > $testroot/stdout.expected
	echo "unstage this deletion? [y/n] y" >> $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "D  beta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff -s > $testroot/stdout)
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff > $testroot/stdout)

	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $commit_id" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'beta$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + /dev/null' >> $testroot/stdout.expected
	echo "--- beta" >> $testroot/stdout.expected
	echo "+++ /dev/null" >> $testroot/stdout.expected
	echo "@@ -1 +0,0 @@" >> $testroot/stdout.expected
	echo "-beta" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_unstage_patch_quit() {
	local testroot=`test_init unstage_patch_quit`

	jot 16 > $testroot/repo/numbers
	echo zzz > $testroot/repo/zzz
	(cd $testroot/repo && git add numbers zzz)
	git_commit $testroot/repo -m "added files"
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	sed -i -e 's/^2$/a/' $testroot/wt/numbers
	sed -i -e 's/^7$/b/' $testroot/wt/numbers
	sed -i -e 's/^16$/c/' $testroot/wt/numbers
	(cd $testroot/wt && got rm zzz > /dev/null)
	(cd $testroot/wt && got stage > /dev/null)

	# unstage first hunk and quit; and don't pass a path argument to
	# ensure that we don't skip asking about the 'zzz' file after 'quit'
	printf "y\nq\nn\n" > $testroot/patchscript
	(cd $testroot/wt && got unstage -F $testroot/patchscript -p \
		> $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got unstage command failed unexpectedly" >&2
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
unstage this change? [y/n/q] y
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
unstage this change? [y/n/q] q
G  numbers
D  zzz
unstage this deletion? [y/n] n
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "MM numbers" > $testroot/stdout.expected
	echo " D zzz" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff > $testroot/stdout)

	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $commit_id" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l numbers) | cut -d' ' -f 1 | \
		tr -d '\n' >> $testroot/stdout.expected
	echo " (staged)" >> $testroot/stdout.expected
	echo "file + numbers" >> $testroot/stdout.expected
	echo "--- numbers" >> $testroot/stdout.expected
	echo "+++ numbers" >> $testroot/stdout.expected
	echo "@@ -1,5 +1,5 @@" >> $testroot/stdout.expected
	echo " 1" >> $testroot/stdout.expected
	echo "-2" >> $testroot/stdout.expected
	echo "+a" >> $testroot/stdout.expected
	echo " 3" >> $testroot/stdout.expected
	echo " 4" >> $testroot/stdout.expected
	echo " 5" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff -s > $testroot/stdout)
	echo "diff -s $testroot/wt" > $testroot/stdout.expected
	echo "commit - $commit_id" >> $testroot/stdout.expected
	echo "path + $testroot/wt (staged changes)" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i -c $commit_id \
		| grep 'numbers$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l numbers) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
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
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'zzz$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'blob + /dev/null' >> $testroot/stdout.expected
	echo "--- zzz" >> $testroot/stdout.expected
	echo "+++ /dev/null" >> $testroot/stdout.expected
	echo "@@ -1 +0,0 @@" >> $testroot/stdout.expected
	echo "-zzz" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_unstage_symlink() {
	local testroot=`test_init unstage_symlink`

	(cd $testroot/repo && ln -s alpha alpha.link)
	(cd $testroot/repo && ln -s epsilon epsilon.link)
	(cd $testroot/repo && ln -s /etc/passwd passwd.link)
	(cd $testroot/repo && ln -s ../beta epsilon/beta.link)
	(cd $testroot/repo && ln -s nonexistent nonexistent.link)
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "add symlinks"
	local head_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && ln -sf beta alpha.link)
	(cd $testroot/wt && ln -sfh gamma epsilon.link)
	(cd $testroot/wt && ln -sf ../gamma/delta epsilon/beta.link)
	echo 'this is regular file foo' > $testroot/wt/dotgotfoo.link
	(cd $testroot/wt && got add dotgotfoo.link > /dev/null)
	(cd $testroot/wt && ln -sf .got/bar dotgotbar.link)
	(cd $testroot/wt && got add dotgotbar.link > /dev/null)
	(cd $testroot/wt && got rm nonexistent.link > /dev/null)
	(cd $testroot/wt && ln -sf gamma/delta zeta.link)
	(cd $testroot/wt && got add zeta.link > /dev/null)

	(cd $testroot/wt && got stage -S > /dev/null)

	(cd $testroot/wt && got status > $testroot/stdout)
	cat > $testroot/stdout.expected <<EOF
 M alpha.link
 A dotgotbar.link
 A dotgotfoo.link
 M epsilon/beta.link
 M epsilon.link
 D nonexistent.link
 A zeta.link
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got unstage > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got unstage command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
G  alpha.link
G  dotgotbar.link
G  dotgotfoo.link
G  epsilon/beta.link
G  epsilon.link
D  nonexistent.link
G  zeta.link
EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ ! -h $testroot/wt/alpha.link ]; then
		echo "alpha.link is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/alpha.link > $testroot/stdout
	echo "beta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ ! -h $testroot/wt/epsilon.link ]; then
		echo "epsilon.link is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/epsilon.link > $testroot/stdout
	echo "gamma" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ ! -h $testroot/wt/epsilon/beta.link ]; then
		echo "epsilon/beta.link is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/epsilon/beta.link > $testroot/stdout
	echo "../gamma/delta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ ! -f $testroot/wt/dotgotfoo.link ]; then
		echo "dotgotfoo.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	echo "this is regular file foo" > $testroot/content.expected
	cp $testroot/wt/dotgotfoo.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	# bad symlinks are allowed as-is for commit and stage/unstage
	if [ ! -h $testroot/wt/dotgotbar.link ]; then
		echo "dotgotbar.link is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/dotgotbar.link > $testroot/stdout
	echo ".got/bar" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -e $testroot/wt/nonexistent.link ]; then
		echo "nonexistent.link exists on disk"
		test_done "$testroot" "1"
		return 1
	fi

	if [ ! -h $testroot/wt/zeta.link ]; then
		echo "zeta.link is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/zeta.link > $testroot/stdout
	echo "gamma/delta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "0"
}

test_unstage_patch_symlink() {
	local testroot=`test_init unstage_patch_symlink`

	(cd $testroot/repo && ln -s alpha alpha.link)
	(cd $testroot/repo && ln -s epsilon epsilon.link)
	(cd $testroot/repo && ln -s /etc/passwd passwd.link)
	(cd $testroot/repo && ln -s ../beta epsilon/beta.link)
	(cd $testroot/repo && ln -s nonexistent nonexistent.link)
	(cd $testroot/repo && ln -sf epsilon/zeta zeta.link)
	(cd $testroot/repo && ln -sf epsilon/zeta zeta2.link)
	(cd $testroot/repo && git add .)
	git_commit $testroot/repo -m "add symlinks"
	local commit_id1=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	# symlink to file A now points to file B
	(cd $testroot/wt && ln -sf gamma/delta alpha.link)
	# symlink to a directory A now points to file B
	(cd $testroot/wt && ln -sfh beta epsilon.link)
	# "bad" symlink now contains a different target path
	echo "foo" > $testroot/wt/passwd.link
	# relative symlink to directory A now points to relative directory B
	(cd $testroot/wt && ln -sfh ../gamma epsilon/beta.link)
	# an unversioned symlink
	(cd $testroot/wt && ln -sf .got/foo dotgotfoo.link)
	# symlink to file A now points to non-existent file B
	(cd $testroot/wt && ln -sf nonexistent2 nonexistent.link)
	# removed symlink
	(cd $testroot/wt && got rm zeta.link > /dev/null)
	(cd $testroot/wt && got rm zeta2.link > /dev/null)
	# added symlink
	(cd $testroot/wt && ln -sf beta new.link)
	(cd $testroot/wt && got add new.link > /dev/null)
	(cd $testroot/wt && ln -sf beta zeta3.link)
	(cd $testroot/wt && got add zeta3.link > /dev/null)

	(cd $testroot/wt && got stage -S > /dev/null)

	(cd $testroot/wt && got status > $testroot/stdout)
	cat > $testroot/stdout.expected <<EOF
 M alpha.link
?  dotgotfoo.link
 M epsilon/beta.link
 M epsilon.link
 A new.link
 M nonexistent.link
 M passwd.link
 D zeta.link
 D zeta2.link
 A zeta3.link
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	printf "y\nn\ny\nn\ny\ny\nn\ny\ny\n" > $testroot/patchscript
	(cd $testroot/wt && got unstage -F $testroot/patchscript -p \
		> $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got unstage command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
-----------------------------------------------
@@ -1 +1 @@
-alpha
\ No newline at end of file
+gamma/delta
\ No newline at end of file
-----------------------------------------------
M  alpha.link (change 1 of 1)
unstage this change? [y/n/q] y
G  alpha.link
-----------------------------------------------
@@ -1 +1 @@
-../beta
\ No newline at end of file
+../gamma
\ No newline at end of file
-----------------------------------------------
M  epsilon/beta.link (change 1 of 1)
unstage this change? [y/n/q] n
-----------------------------------------------
@@ -1 +1 @@
-epsilon
\ No newline at end of file
+beta
\ No newline at end of file
-----------------------------------------------
M  epsilon.link (change 1 of 1)
unstage this change? [y/n/q] y
G  epsilon.link
A  new.link
unstage this addition? [y/n] n
-----------------------------------------------
@@ -1 +1 @@
-nonexistent
\ No newline at end of file
+nonexistent2
\ No newline at end of file
-----------------------------------------------
M  nonexistent.link (change 1 of 1)
unstage this change? [y/n/q] y
G  nonexistent.link
-----------------------------------------------
@@ -1 +1 @@
-/etc/passwd
\ No newline at end of file
+foo
-----------------------------------------------
M  passwd.link (change 1 of 1)
unstage this change? [y/n/q] y
G  passwd.link
D  zeta.link
unstage this deletion? [y/n] n
D  zeta2.link
unstage this deletion? [y/n] y
D  zeta2.link
A  zeta3.link
unstage this addition? [y/n] y
G  zeta3.link
EOF
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
	echo "gamma/delta" > $testroot/stdout.expected
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
	echo "beta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/passwd.link ]; then
		echo "passwd.link should not be a symlink" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "foo" > $testroot/content.expected
	cp $testroot/wt/passwd.link $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	readlink $testroot/wt/epsilon/beta.link > $testroot/stdout
	echo "../gamma" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	readlink $testroot/wt/nonexistent.link > $testroot/stdout
	echo "nonexistent2" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ ! -h $testroot/wt/dotgotfoo.link ]; then
		echo "dotgotfoo.link is not a symlink " >&2
		test_done "$testroot" "1"
		return 1
	fi
	readlink $testroot/wt/dotgotfoo.link > $testroot/stdout
	echo ".got/foo" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi


	if [ -e $testroot/wt/zeta.link ]; then
		echo -n "zeta.link should not exist on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	if [ -e $testroot/wt/zeta2.link ]; then
		echo -n "zeta2.link exists on disk" >&2
		test_done "$testroot" "1"
		return 1
	fi

	if [ ! -h $testroot/wt/zeta3.link ]; then
		echo -n "zeta3.link is not a symlink" >&2
		test_done "$testroot" "1"
		return 1
	fi

	readlink $testroot/wt/zeta3.link > $testroot/stdout
	echo "beta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ ! -h $testroot/wt/new.link ]; then
		echo -n "new.link is not a symlink" >&2
		test_done "$testroot" "1"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "M  alpha.link" > $testroot/stdout.expected
	echo "?  dotgotfoo.link" >> $testroot/stdout.expected
	echo " M epsilon/beta.link" >> $testroot/stdout.expected
	echo "M  epsilon.link" >> $testroot/stdout.expected
	echo " A new.link" >> $testroot/stdout.expected
	echo "M  nonexistent.link" >> $testroot/stdout.expected
	echo "M  passwd.link" >> $testroot/stdout.expected
	echo " D zeta.link" >> $testroot/stdout.expected
	echo "D  zeta2.link" >> $testroot/stdout.expected
	echo "A  zeta3.link" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_unstage_basic
run_test test_unstage_unversioned
run_test test_unstage_nonexistent
run_test test_unstage_patch
run_test test_unstage_patch_added
run_test test_unstage_patch_removed
run_test test_unstage_patch_quit
run_test test_unstage_symlink
run_test test_unstage_patch_symlink
