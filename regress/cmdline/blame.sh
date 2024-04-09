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

blame_cmp() {
	local testroot="$1"
	local file="$2"
	local xfail="$3"

	(cd $testroot/wt && got blame "$file" | cut -d ' ' -f 2 \
		> $testroot/${file}.blame.got)
	git -C $testroot/repo reset --hard master > /dev/null
	git -C $testroot/repo blame "$file" | cut -d ' ' -f 1 \
		> $testroot/${file}.blame.git

	cmp -s $testroot/${file}.blame.git $testroot/${file}.blame.got
	ret=$?
	if [ $ret -ne 0 -a "$xfail" = "" ]; then
		diff -u $testroot/${file}.blame.git $testroot/${file}.blame.got
		return 1
	fi
	return "$ret"
}

test_blame_basic() {
	local testroot=`test_init blame_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 1 > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 1" > /dev/null)
	local commit1=`git_show_head $testroot/repo`

	echo 2 >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 2" > /dev/null)
	local commit2=`git_show_head $testroot/repo`

	echo 3 >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 3" > /dev/null)
	local commit3=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`

	(cd $testroot/wt && got blame alpha > $testroot/stdout)

	local short_commit1=`trim_obj_id 32 $commit1`
	local short_commit2=`trim_obj_id 32 $commit2`
	local short_commit3=`trim_obj_id 32 $commit3`

	d=`date -u -r $author_time +"%G-%m-%d"`
	echo "1) $short_commit1 $d $GOT_AUTHOR_8 1" > $testroot/stdout.expected
	echo "2) $short_commit2 $d $GOT_AUTHOR_8 2" >> $testroot/stdout.expected
	echo "3) $short_commit3 $d $GOT_AUTHOR_8 3" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	blame_cmp "$testroot" "alpha"
	ret=$?
	test_done "$testroot" "$ret"
}

test_blame_tag() {
	local testroot=`test_init blame_tag`
	local tag=1.0.0

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi
	echo 1 > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 1" > /dev/null)
	local commit1=`git_show_head $testroot/repo`

	echo 2 >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 2" > /dev/null)
	local commit2=`git_show_head $testroot/repo`

	git -C $testroot/repo tag -a -m "test" $tag

	echo 3 >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 3" > /dev/null)
	local commit3=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`

	(cd $testroot/wt && got blame -c $tag alpha > $testroot/stdout)

	local short_commit1=`trim_obj_id 32 $commit1`
	local short_commit2=`trim_obj_id 32 $commit2`

	d=`date -u -r $author_time +"%G-%m-%d"`
	echo "1) $short_commit1 $d $GOT_AUTHOR_8 1" > $testroot/stdout.expected
	echo "2) $short_commit2 $d $GOT_AUTHOR_8 2" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	blame_cmp "$testroot" "alpha"
	ret=$?
	test_done "$testroot" "$ret"
}

test_blame_file_single_line() {
	local testroot=`test_init blame_file_single_line`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 1 > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 1" > /dev/null)
	local commit1=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`

	(cd $testroot/wt && got blame alpha > $testroot/stdout)

	local short_commit1=`trim_obj_id 32 $commit1`

	d=`date -u -r $author_time +"%G-%m-%d"`
	echo "1) $short_commit1 $d $GOT_AUTHOR_8 1" > $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	blame_cmp "$testroot" "alpha"
	ret=$?
	test_done "$testroot" "$ret"
}

test_blame_file_single_line_no_newline() {
	local testroot=`test_init blame_file_single_line_no_newline`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n 1 > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 1" > /dev/null)
	local commit1=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`

	(cd $testroot/wt && got blame alpha > $testroot/stdout)

	local short_commit1=`trim_obj_id 32 $commit1`

	d=`date -u -r $author_time +"%G-%m-%d"`
	echo "1) $short_commit1 $d $GOT_AUTHOR_8 1" > $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_blame_all_lines_replaced() {
	local testroot=`test_init blame_all_lines_replaced`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	seq 8 > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 1" > /dev/null)
	local commit1=`git_show_head $testroot/repo`
	local short_commit1=`trim_obj_id 32 $commit1`
	local author_time=`git_show_author_time $testroot/repo`

	(cd $testroot/wt && got blame alpha > $testroot/stdout)

	d=`date -u -r $author_time +"%G-%m-%d"`
	echo "1) $short_commit1 $d $GOT_AUTHOR_8 1" > $testroot/stdout.expected
	echo "2) $short_commit1 $d $GOT_AUTHOR_8 2" >> $testroot/stdout.expected
	echo "3) $short_commit1 $d $GOT_AUTHOR_8 3" >> $testroot/stdout.expected
	echo "4) $short_commit1 $d $GOT_AUTHOR_8 4" >> $testroot/stdout.expected
	echo "5) $short_commit1 $d $GOT_AUTHOR_8 5" >> $testroot/stdout.expected
	echo "6) $short_commit1 $d $GOT_AUTHOR_8 6" >> $testroot/stdout.expected
	echo "7) $short_commit1 $d $GOT_AUTHOR_8 7" >> $testroot/stdout.expected
	echo "8) $short_commit1 $d $GOT_AUTHOR_8 8" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

test_blame_lines_shifted_up() {
	local testroot=`test_init blame_lines_shifted_up`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	seq 8 > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 1" > /dev/null)
	local commit1=`git_show_head $testroot/repo`
	local short_commit1=`trim_obj_id 32 $commit1`
	local author_time=`git_show_author_time $testroot/repo`

	ed -s $testroot/wt/alpha <<-\EOF
	g/^[345]$/d
	w
	EOF
	(cd $testroot/wt && got commit -m "change 2" > /dev/null)
	local commit2=`git_show_head $testroot/repo`
	local short_commit2=`trim_obj_id 32 $commit2`

	seq 2 > $testroot/wt/alpha
	echo foo >> $testroot/wt/alpha
	echo bar >> $testroot/wt/alpha
	echo baz >> $testroot/wt/alpha
	seq 6 8 >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 3" > /dev/null)
	local commit3=`git_show_head $testroot/repo`
	local short_commit3=`trim_obj_id 32 $commit3`
	local author_time=`git_show_author_time $testroot/repo`

	(cd $testroot/wt && got blame alpha > $testroot/stdout)

	d=`date -u -r $author_time +"%G-%m-%d"`
	echo "1) $short_commit1 $d $GOT_AUTHOR_8 1" > $testroot/stdout.expected
	echo "2) $short_commit1 $d $GOT_AUTHOR_8 2" >> $testroot/stdout.expected
	echo "3) $short_commit3 $d $GOT_AUTHOR_8 foo" >> $testroot/stdout.expected
	echo "4) $short_commit3 $d $GOT_AUTHOR_8 bar" >> $testroot/stdout.expected
	echo "5) $short_commit3 $d $GOT_AUTHOR_8 baz" >> $testroot/stdout.expected
	echo "6) $short_commit1 $d $GOT_AUTHOR_8 6" >> $testroot/stdout.expected
	echo "7) $short_commit1 $d $GOT_AUTHOR_8 7" >> $testroot/stdout.expected
	echo "8) $short_commit1 $d $GOT_AUTHOR_8 8" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	blame_cmp "$testroot" "alpha"
	ret=$?
	test_done "$testroot" "$ret"
}

test_blame_lines_shifted_down() {
	local testroot=`test_init blame_lines_shifted_down`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	seq 8 > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 1" > /dev/null)
	local commit1=`git_show_head $testroot/repo`
	local short_commit1=`trim_obj_id 32 $commit1`
	local author_time=`git_show_author_time $testroot/repo`

	ed -s $testroot/wt/alpha <<-\EOF
	g/^8$/d
	w
	EOF
	(cd $testroot/wt && got commit -m "change 2" > /dev/null)
	local commit2=`git_show_head $testroot/repo`
	local short_commit2=`trim_obj_id 32 $commit2`

	seq 2 > $testroot/wt/alpha
	echo foo >> $testroot/wt/alpha
	echo bar >> $testroot/wt/alpha
	echo baz >> $testroot/wt/alpha
	seq 3 8 >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 3" > /dev/null)
	local commit3=`git_show_head $testroot/repo`
	local short_commit3=`trim_obj_id 32 $commit3`
	local author_time=`git_show_author_time $testroot/repo`

	(cd $testroot/wt && got blame alpha > $testroot/stdout)

	d=`date -u -r $author_time +"%G-%m-%d"`
	echo "01) $short_commit1 $d $GOT_AUTHOR_8 1" \
		> $testroot/stdout.expected
	echo "02) $short_commit1 $d $GOT_AUTHOR_8 2" \
		>> $testroot/stdout.expected
	echo "03) $short_commit3 $d $GOT_AUTHOR_8 foo" \
		>> $testroot/stdout.expected
	echo "04) $short_commit3 $d $GOT_AUTHOR_8 bar" \
		>> $testroot/stdout.expected
	echo "05) $short_commit3 $d $GOT_AUTHOR_8 baz" \
		>> $testroot/stdout.expected
	echo "06) $short_commit1 $d $GOT_AUTHOR_8 3" \
		>> $testroot/stdout.expected
	echo "07) $short_commit1 $d $GOT_AUTHOR_8 4" \
		>> $testroot/stdout.expected
	echo "08) $short_commit1 $d $GOT_AUTHOR_8 5" \
		>> $testroot/stdout.expected
	echo "09) $short_commit1 $d $GOT_AUTHOR_8 6" \
		>> $testroot/stdout.expected
	echo "10) $short_commit1 $d $GOT_AUTHOR_8 7" \
		>> $testroot/stdout.expected
	echo "11) $short_commit3 $d $GOT_AUTHOR_8 8" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	blame_cmp "$testroot" "alpha"
	ret=$?
	test_done "$testroot" "$ret"
}

test_blame_commit_subsumed() {
	local testroot=`test_init blame_commit_subsumed`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/wt/alpha <<EOF
SUBDIRS = ext modules codedocs docs

if WITH_PDNS_SERVER
  SUBDIRS += pdns
endif

EXTRA_DIST =
	INSTALL
	NOTICE
	README
	.version
	build-aux/gen-version
	codedocs/doxygen.conf
	contrib/powerdns.solaris.init.d
	pdns/named.conf.parsertest
	regression-tests/zones/unit.test

ACLOCAL_AMFLAGS = -I m4

dvi: # do nothing to build dvi
EOF
	(cd $testroot/wt && got commit -m "change 1" > /dev/null)
	local commit1=`git_show_head $testroot/repo`
	local short_commit1=`trim_obj_id 32 $commit1`
	local author_time1=`git_show_author_time $testroot/repo`
	local d1=`date -u -r $author_time1 +"%G-%m-%d"`

	cat > $testroot/wt/alpha <<EOF
SUBDIRS = ext modules codedocs docs

SUBDIRS += pdns

EXTRA_DIST =
	INSTALL
	NOTICE
	README
	.version
	build-aux/gen-version
	codedocs/doxygen.conf
	contrib/powerdns.solaris.init.d
	pdns/named.conf.parsertest
	regression-tests/zones/unit.test

ACLOCAL_AMFLAGS = -I m4

dvi: # do nothing to build dvi
EOF
	# all changes in this commit will be subsumed by later commits
	(cd $testroot/wt && got commit -m "change 2" > /dev/null)
	local commit2=`git_show_head $testroot/repo`
	local short_commit2=`trim_obj_id 32 $commit2`
	local author_time2=`git_show_author_time $testroot/repo`
	local d2=`date -u -r $author_time2 +"%G-%m-%d"`

	cat > $testroot/wt/alpha <<EOF
SUBDIRS = ext modules pdns codedocs docs

EXTRA_DIST =
	INSTALL
	NOTICE
	README
	.version
	build-aux/gen-version
	codedocs/doxygen.conf
	contrib/powerdns.solaris.init.d
	pdns/named.conf.parsertest
	regression-tests/zones/unit.test

ACLOCAL_AMFLAGS = -I m4

dvi: # do nothing to build dvi
EOF
	(cd $testroot/wt && got commit -m "change 3" > /dev/null)
	local commit3=`git_show_head $testroot/repo`
	local short_commit3=`trim_obj_id 32 $commit3`
	local author_time3=`git_show_author_time $testroot/repo`
	local d3=`date -u -r $author_time3 +"%G-%m-%d"`

	cat > $testroot/wt/alpha <<EOF
SUBDIRS = ext modules pdns codedocs docs

EXTRA_DIST =
	INSTALL
	NOTICE
	README
	COPYING
	codedocs/doxygen.conf
	contrib/powerdns.solaris.init.d
	pdns/named.conf.parsertest
	regression-tests/zones/unit.test
	builder-support/gen-version

ACLOCAL_AMFLAGS = -I m4

dvi: # do nothing to build dvi
EOF
	(cd $testroot/wt && got commit -m "change 4" > /dev/null)
	local commit4=`git_show_head $testroot/repo`
	local short_commit4=`trim_obj_id 32 $commit4`
	local author_time4=`git_show_author_time $testroot/repo`
	local d4=`date -u -r $author_time4 +"%G-%m-%d"`

	(cd $testroot/wt && got blame alpha > $testroot/stdout)

	echo -n "01) $short_commit3 $d3 $GOT_AUTHOR_8 " \
		> $testroot/stdout.expected
	echo "SUBDIRS = ext modules pdns codedocs docs" \
		>> $testroot/stdout.expected
	echo "02) $short_commit1 $d1 $GOT_AUTHOR_8 " \
		>> $testroot/stdout.expected
	echo -n "03) $short_commit1 $d1 $GOT_AUTHOR_8 " \
		>> $testroot/stdout.expected
	echo 'EXTRA_DIST =' >> $testroot/stdout.expected
	echo -n "04) $short_commit1 $d1 $GOT_AUTHOR_8 " \
		>> $testroot/stdout.expected
	printf "\tINSTALL\n" >> $testroot/stdout.expected
	echo -n "05) $short_commit1 $d1 $GOT_AUTHOR_8 " \
		>> $testroot/stdout.expected
	printf "\tNOTICE\n" >> $testroot/stdout.expected
	echo -n "06) $short_commit1 $d1 $GOT_AUTHOR_8 " \
		>> $testroot/stdout.expected
	printf "\tREADME\n"  >> $testroot/stdout.expected
	echo -n "07) $short_commit4 $d4 $GOT_AUTHOR_8 " \
		>> $testroot/stdout.expected
	printf "\tCOPYING\n" >> $testroot/stdout.expected
	echo -n "08) $short_commit1 $d1 $GOT_AUTHOR_8 " \
		>> $testroot/stdout.expected
	printf "\tcodedocs/doxygen.conf\n" >> $testroot/stdout.expected
	echo -n "09) $short_commit1 $d1 $GOT_AUTHOR_8 " \
		>> $testroot/stdout.expected
	printf "\tcontrib/powerdns.solaris.init.d\n" \
		>> $testroot/stdout.expected
	echo -n "10) $short_commit1 $d1 $GOT_AUTHOR_8 " \
		>> $testroot/stdout.expected
	printf "\tpdns/named.conf.parsertest\n" >> $testroot/stdout.expected
	echo -n "11) $short_commit1 $d1 $GOT_AUTHOR_8 " \
		>> $testroot/stdout.expected
	printf "\tregression-tests/zones/unit.test\n" \
		>> $testroot/stdout.expected
	echo -n "12) $short_commit4 $d4 $GOT_AUTHOR_8 " \
		>> $testroot/stdout.expected
	printf "\tbuilder-support/gen-version\n" >> $testroot/stdout.expected
	echo "13) $short_commit1 $d1 $GOT_AUTHOR_8 " \
		>> $testroot/stdout.expected
	echo -n "14) $short_commit1 $d1 $GOT_AUTHOR_8 " \
		>> $testroot/stdout.expected
	echo "ACLOCAL_AMFLAGS = -I m4" \
		>> $testroot/stdout.expected
	echo "15) $short_commit1 $d1 $GOT_AUTHOR_8 " \
		>> $testroot/stdout.expected
	echo -n "16) $short_commit1 $d1 $GOT_AUTHOR_8 " \
		>> $testroot/stdout.expected
	echo "dvi: # do nothing to build dvi" \
		>> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	blame_cmp "$testroot" "alpha"
	ret=$?
	test_done "$testroot" "$ret"
}

test_blame_blame_h() {
	local testroot=`test_init blame_blame_h`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/wt/got_blame.h <<EOF
/*
 * Copyright (c) 2018 Stefan Sperling <stsp@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

const struct got_error *got_blame(const char *, struct got_object_id *,
    struct got_repository *, FILE *);
EOF
	(cd $testroot/wt && got add got_blame.h > /dev/null)
	(cd $testroot/wt && got commit -m "change 1" > /dev/null)

	cat > $testroot/wt/blame-2.patch <<EOF
diff 63581804340e880bf611c6a4a59eda26c503799f 84451b3ef755f3226d0d79af367632e5f3a830e7
blob - b53ca469a18871cc2f6af334dab25028599c6488
blob + c787aadf05e2afab61bd34976f7349912252e6da
--- got_blame.h
+++ got_blame.h
@@ -14,5 +14,22 @@
  * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
  */

+/*
+ * Write an annotated version of a file at a given in-repository path,
+ * as found in the commit specified by ID, to the specified output file.
+ */
 const struct got_error *got_blame(const char *, struct got_object_id *,
     struct got_repository *, FILE *);
+
+/*
+ * Like got_blame() but instead of generating an output file invoke
+ * a callback whenever an annotation has been computed for a line.
+ *
+ * The callback receives the provided void * argument, the total number
+ * of lines of the annotated file, a line number, and the ID of the commit
+ * which last changed this line.
+ */
+const struct got_error *got_blame_incremental(const char *,
+    struct got_object_id *, struct got_repository *,
+    const struct got_error *(*cb)(void *, int, int, struct got_object_id *),
+    void *);
EOF
	(cd $testroot/wt && patch < blame-2.patch > /dev/null)
	(cd $testroot/wt && got commit -m "change 2" > /dev/null)

	cat > $testroot/wt/blame-3.patch <<EOF
diff 75b7a700d9d14ef8eb902961255212acbedef164 d68a0a7de13af722c55099582019c03240e13320
blob - c787aadf05e2afab61bd34976f7349912252e6da
blob + 5255d076c915accf159940978b821d06803ff2f8
--- got_blame.h
+++ got_blame.h
@@ -28,6 +28,15 @@ const struct got_error *got_blame(const char *, struct
  * The callback receives the provided void * argument, the total number
  * of lines of the annotated file, a line number, and the ID of the commit
  * which last changed this line.
+ *
+ * The callback is invoked for each commit as history is traversed.
+ * If no changes to the file were made in a commit, line number -1 and
+ * commit ID NULL will be reported.
+ *
+ * If the callback returns GOT_ERR_ITER_COMPLETED, the blame operation
+ * will be aborted and this function returns NULL.
+ * If the callback returns any other error, the blame operation will be
+ * aborted and the callback's error is returned from this function.
  */
 const struct got_error *got_blame_incremental(const char *,
     struct got_object_id *, struct got_repository *,
EOF
	(cd $testroot/wt && patch < blame-3.patch > /dev/null)
	(cd $testroot/wt && got commit -m "change 3" > /dev/null)

	cat > $testroot/wt/blame-4.patch <<EOF
diff 3f60a8ef49086101685260fcb829f578cdf6d320 3bf198ba335fa30c8d16efb5c8e496200ac99c05
blob - 5255d076c915accf159940978b821d06803ff2f8
blob + 39623c468e733ee08abb50eafe29202b2b0a04ef
--- got_blame.h
+++ got_blame.h
@@ -30,8 +30,8 @@ const struct got_error *got_blame(const char *, struct
  * which last changed this line.
  *
  * The callback is invoked for each commit as history is traversed.
- * If no changes to the file were made in a commit, line number -1 and
- * commit ID NULL will be reported.
+ * If no changes to the file were made in a commit, line number -1 will
+ * be reported.
  *
  * If the callback returns GOT_ERR_ITER_COMPLETED, the blame operation
  * will be aborted and this function returns NULL.
EOF
	(cd $testroot/wt && patch < blame-4.patch > /dev/null)
	(cd $testroot/wt && got commit -m "change 4" > /dev/null)

	cat > $testroot/wt/blame-5.patch <<EOF
diff 28315671b93d195163b0468fcb3879e29b25759c e27a7222faaa171dcb086ea0b566dc7bebb74a0b
blob - 39623c468e733ee08abb50eafe29202b2b0a04ef
blob + 6075cadbd177e1802679c7353515bf4ceebb51d0
--- got_blame.h
+++ got_blame.h
@@ -15,14 +15,7 @@
  */

 /*
- * Write an annotated version of a file at a given in-repository path,
- * as found in the commit specified by ID, to the specified output file.
- */
-const struct got_error *got_blame(const char *, struct got_object_id *,
-    struct got_repository *, FILE *);
-
-/*
- * Like got_blame() but instead of generating an output file invoke
+ * Blame the blob at the specified path in the specified commit and invoke
  * a callback whenever an annotation has been computed for a line.
  *
  * The callback receives the provided void * argument, the total number
EOF
	(cd $testroot/wt && patch < blame-5.patch > /dev/null)
	(cd $testroot/wt && got commit -m "change 5" > /dev/null)

	blame_cmp "$testroot" "got_blame.h"
	ret=$?
	test_done "$testroot" "$ret"
}

test_blame_added_on_branch() {
	local testroot=`test_init blame_added_on_branch`

	got branch -r $testroot/repo -c master newbranch
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	got checkout -b newbranch $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 1 > $testroot/wt/new
	(cd $testroot/wt && got add new > /dev/null)
	(cd $testroot/wt && got commit -m "change 1" > /dev/null)
	local commit1=`git_show_branch_head $testroot/repo newbranch`

	echo 2 >> $testroot/wt/new
	(cd $testroot/wt && got commit -m "change 2" > /dev/null)
	local commit2=`git_show_branch_head $testroot/repo newbranch`

	echo 3 >> $testroot/wt/new
	(cd $testroot/wt && got commit -m "change 3" > /dev/null)
	local commit3=`git_show_branch_head $testroot/repo newbranch`
	local author_time=`git_show_author_time $testroot/repo`

	(cd $testroot/wt && got blame new > $testroot/stdout)

	local short_commit1=`trim_obj_id 32 $commit1`
	local short_commit2=`trim_obj_id 32 $commit2`
	local short_commit3=`trim_obj_id 32 $commit3`

	d=`date -u -r $author_time +"%G-%m-%d"`
	echo "1) $short_commit1 $d $GOT_AUTHOR_8 1" > $testroot/stdout.expected
	echo "2) $short_commit2 $d $GOT_AUTHOR_8 2" >> $testroot/stdout.expected
	echo "3) $short_commit3 $d $GOT_AUTHOR_8 3" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_blame_submodule() {
	local testroot=`test_init blame_submodule`
	local commit_id0=`git_show_head $testroot/repo`
	local author_time=`git_show_author_time $testroot/repo`

	make_single_file_repo $testroot/repo2 foo

	git -C $testroot/repo -c protocol.file.allow=always \
		submodule -q add ../repo2
	git -C $testroot/repo commit -q -m 'adding submodule'

	# Attempt a (nonsensical) blame of a submodule.
	got blame -r $testroot/repo repo2 \
		> $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "blame command succeeded unexpectedly" >&2
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

test_blame_symlink() {
	local testroot=`test_init blame_symlink`
	local commit_id0=`git_show_head $testroot/repo`
	local short_commit0=`trim_obj_id 32 $commit_id0`

	(cd $testroot/repo && ln -s alpha alpha.link)
	(cd $testroot/repo && ln -s epsilon epsilon.link)
	(cd $testroot/repo && ln -s /etc/passwd passwd.link)
	(cd $testroot/repo && ln -s ../beta epsilon/beta.link)
	(cd $testroot/repo && ln -s nonexistent nonexistent.link)
	git -C $testroot/repo add .
	git_commit $testroot/repo -m "add symlinks"

	local commit_id1=`git_show_head $testroot/repo`
	local short_commit1=`trim_obj_id 32 $commit_id1`
	local author_time=`git_show_author_time $testroot/repo`

	# got blame dereferences symlink to a regular file
	got blame -r $testroot/repo alpha.link > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "blame command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	d=`date -u -r $author_time +"%G-%m-%d"`
	echo "1) $short_commit0 $d $GOT_AUTHOR_8 alpha" \
		> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 -a "$xfail" = "" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "1"
		return 1
	fi

	# got blame dereferences symlink with relative path
	got blame -r $testroot/repo epsilon/beta.link > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "blame command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	d=`date -u -r $author_time +"%G-%m-%d"`
	echo "1) $short_commit0 $d $GOT_AUTHOR_8 beta" \
		> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 -a "$xfail" = "" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "1"
		return 1
	fi

	got blame -r $testroot/repo epsilon.link > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "blame command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	# blame dereferences symlink to a directory
	echo "got: /epsilon: wrong type of object" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "1"
		return 1
	fi

	# got blame fails if symlink target does not exist in repo
	got blame -r $testroot/repo passwd.link > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "blame command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: /etc/passwd: no such entry found in tree" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "1"
		return 1
	fi

	got blame -r $testroot/repo nonexistent.link > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "blame command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: /nonexistent: no such entry found in tree" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_blame_lines_shifted_skip() {
	local testroot=`test_init blame_lines_shifted_skip`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/wt/alpha <<EOF
A
B
C
D
EOF
	(cd $testroot/wt && got commit -m "change 1" > /dev/null)
	local commit1=`git_show_head $testroot/repo`
	local short_commit1=`trim_obj_id 32 $commit1`
	local author_time1=`git_show_author_time $testroot/repo`

	cat > $testroot/wt/alpha <<EOF
A
B
Y
C
P
Q
EOF
	(cd $testroot/wt && got commit -m "change 2" > /dev/null)
	local commit2=`git_show_head $testroot/repo`
	local short_commit2=`trim_obj_id 32 $commit2`
	local author_time2=`git_show_author_time $testroot/repo`

	cat > $testroot/wt/alpha <<EOF
A
B
Y
C
D
P
Q
EOF
	(cd $testroot/wt && got commit -m "change 3" > /dev/null)
	local commit3=`git_show_head $testroot/repo`
	local short_commit3=`trim_obj_id 32 $commit3`
	local author_time3=`git_show_author_time $testroot/repo`

	cat > $testroot/wt/alpha <<EOF
A
B
C
P
Y
Q
EOF
	(cd $testroot/wt && got commit -m "change 4" > /dev/null)
	local commit4=`git_show_head $testroot/repo`
	local short_commit4=`trim_obj_id 32 $commit4`
	local author_time4=`git_show_author_time $testroot/repo`

	cat > $testroot/wt/alpha <<EOF
X
A
B
C
P
Y
Q
EOF
	(cd $testroot/wt && got commit -m "change 5" > /dev/null)
	local commit5=`git_show_head $testroot/repo`
	local short_commit5=`trim_obj_id 32 $commit5`
	local author_time5=`git_show_author_time $testroot/repo`

	(cd $testroot/wt && got blame alpha > $testroot/stdout)

	d1=`date -u -r $author_time1 +"%G-%m-%d"`
	d2=`date -u -r $author_time2 +"%G-%m-%d"`
	d4=`date -u -r $author_time4 +"%G-%m-%d"`
	d5=`date -u -r $author_time5 +"%G-%m-%d"`
	echo "1) $short_commit5 $d5 $GOT_AUTHOR_8 X" > $testroot/stdout.expected
	echo "2) $short_commit1 $d1 $GOT_AUTHOR_8 A" >> $testroot/stdout.expected
	echo "3) $short_commit1 $d1 $GOT_AUTHOR_8 B" >> $testroot/stdout.expected
	echo "4) $short_commit1 $d1 $GOT_AUTHOR_8 C" >> $testroot/stdout.expected
	echo "5) $short_commit2 $d2 $GOT_AUTHOR_8 P" >> $testroot/stdout.expected
	echo "6) $short_commit4 $d4 $GOT_AUTHOR_8 Y" >> $testroot/stdout.expected
	echo "7) $short_commit2 $d5 $GOT_AUTHOR_8 Q" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	blame_cmp "$testroot" "alpha"
	ret=$?
	test_done "$testroot" "$ret"
}

test_blame_commit_keywords() {
	local testroot=$(test_init blame_commit_keywords)
	local repo="$testroot/repo"
	local wt="$testroot/wt"
	local id=$(git_show_head "$repo")

	set -- "$(trim_obj_id 32 $id)"

	# :base requires work tree
	echo "got: '-c :base' requires work tree" > "$testroot/stderr.expected"
	got blame -r "$repo" -c:base alpha 2> "$testroot/stderr"
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "blame command succeeded unexpectedly" >&2
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

	echo -n > "$wt/alpha"

	for i in $(seq 8); do
		echo "change $i" >> "$wt/alpha"

		(cd "$wt" && got ci -m "commit $i" > /dev/null)
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "commit failed unexpectedly" >&2
			test_done "$testroot" "$ret"
			return 1
		fi

		id=$(git_show_head "$repo")
		set -- "$@" "$(trim_obj_id 32 $id)"
	done

	local author_time=$(git_show_author_time "$repo")
	local d=$(date -u -r $author_time +"%G-%m-%d")

	got blame -r "$repo" -c:head:-8 alpha > "$testroot/stdout"
	echo "1) $(pop_idx 1 $@) $d $GOT_AUTHOR_8 alpha" > \
	    "$testroot/stdout.expected"

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/stdout.expected" "$testroot/stdout"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd "$wt" && got blame -cmaster:-5 alpha > "$testroot/stdout")

	echo "1) $(pop_idx 2 $@) $d $GOT_AUTHOR_8 change 1" > \
	    "$testroot/stdout.expected"
	echo "2) $(pop_idx 3 $@) $d $GOT_AUTHOR_8 change 2" >> \
	    "$testroot/stdout.expected"
	echo "3) $(pop_idx 4 $@) $d $GOT_AUTHOR_8 change 3" >> \
	    "$testroot/stdout.expected"

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/stdout.expected" "$testroot/stdout"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd "$wt" && got blame -c:head:-4 alpha > "$testroot/stdout")

	echo "1) $(pop_idx 2 $@) $d $GOT_AUTHOR_8 change 1" > \
	    "$testroot/stdout.expected"
	echo "2) $(pop_idx 3 $@) $d $GOT_AUTHOR_8 change 2" >> \
	    "$testroot/stdout.expected"
	echo "3) $(pop_idx 4 $@) $d $GOT_AUTHOR_8 change 3" >> \
	    "$testroot/stdout.expected"
	echo "4) $(pop_idx 5 $@) $d $GOT_AUTHOR_8 change 4" >> \
	    "$testroot/stdout.expected"

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/stdout.expected" "$testroot/stdout"
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd "$wt" && got up -c:head:-8 > /dev/null)
	(cd "$wt" && got blame -c:base:+5 alpha > "$testroot/stdout")

	echo "1) $(pop_idx 2 $@) $d $GOT_AUTHOR_8 change 1" > \
	    "$testroot/stdout.expected"
	echo "2) $(pop_idx 3 $@) $d $GOT_AUTHOR_8 change 2" >> \
	    "$testroot/stdout.expected"
	echo "3) $(pop_idx 4 $@) $d $GOT_AUTHOR_8 change 3" >> \
	    "$testroot/stdout.expected"
	echo "4) $(pop_idx 5 $@) $d $GOT_AUTHOR_8 change 4" >> \
	    "$testroot/stdout.expected"
	echo "5) $(pop_idx 6 $@) $d $GOT_AUTHOR_8 change 5" >> \
	    "$testroot/stdout.expected"

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/stdout.expected" "$testroot/stdout"
		test_done "$testroot" "$ret"
		return 1
	fi

	blame_cmp "$testroot" "alpha"
	ret=$?
	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_blame_basic
run_test test_blame_tag
run_test test_blame_file_single_line
run_test test_blame_file_single_line_no_newline
run_test test_blame_all_lines_replaced
run_test test_blame_lines_shifted_up
run_test test_blame_lines_shifted_down
run_test test_blame_commit_subsumed
run_test test_blame_blame_h
run_test test_blame_added_on_branch
run_test test_blame_submodule
run_test test_blame_symlink
run_test test_blame_lines_shifted_skip
run_test test_blame_commit_keywords
