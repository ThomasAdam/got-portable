#!/bin/sh
#
# Copyright (c) 2024 Stefan Sperling <stsp@openbsd.org>
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

. ../cmdline/common.sh
. ./common.sh

test_file_changed() {
	local testroot=`test_init file_changed 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "change alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'make changes' > /dev/null)
	local commit_id=`git_show_head $testroot/repo-clone`
	local author_time=`git_show_author_time $testroot/repo-clone`

	(printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l "$GOTD_TEST_SMTP_PORT" > $testroot/stdout) &

	got send -b main -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for nc -l

	HOSTNAME=`hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" >> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} changed refs/heads/main\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf "commit $commit_id\n" >> $testroot/stdout.expected
	printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
	d=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	printf "date: $d\n" >> $testroot/stdout.expected
	printf "messagelen: 14\n" >> $testroot/stdout.expected
	printf " \n" >> $testroot/stdout.expected
	printf " make changes\n \n" >> $testroot/stdout.expected
	printf " M  alpha  |  1+  1-\n\n"  >> $testroot/stdout.expected
	printf "1 file changed, 1 insertion(+), 1 deletion(-)\n\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_many_commits_not_summarized() {
	local testroot=`test_init many_commits_not_summarized 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	for i in `seq 1 24`; do
		echo "alpha $i" > $testroot/wt/alpha
		(cd $testroot/wt && got commit -m 'make changes' > /dev/null)
		local commit_id=`git_show_head $testroot/repo-clone`
		local author_time=`git_show_author_time $testroot/repo-clone`
		d=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
		set -- "$@" "$commit_id $d"
	done

	(printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l "$GOTD_TEST_SMTP_PORT" > $testroot/stdout) &

	got send -b main -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for nc -l

	HOSTNAME=`hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" \
		>> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} changed refs/heads/main\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	for i in `seq 1 24`; do
		s=`pop_idx $i "$@"`
		commit_id=$(echo $s | cut -d' ' -f1)
		commit_time=$(echo $s | sed -e "s/^$commit_id //g")
		printf "commit $commit_id\n" >> $testroot/stdout.expected
		printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
		printf "date: $commit_time\n" >> $testroot/stdout.expected
		printf "messagelen: 14\n" >> $testroot/stdout.expected
		printf " \n" >> $testroot/stdout.expected
		printf " make changes\n \n" >> $testroot/stdout.expected
		printf " M  alpha  |  1+  1-\n\n"  \
			>> $testroot/stdout.expected
		printf "1 file changed, 1 insertion(+), 1 deletion(-)\n\n" \
			>> $testroot/stdout.expected
	done
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_many_commits_summarized() {
	local testroot=`test_init many_commits_summarized 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	for i in `seq 1 51`; do
		echo "alpha $i" > $testroot/wt/alpha
		(cd $testroot/wt && got commit -m 'make changes' > /dev/null)
		local commit_id=`git_show_head $testroot/repo-clone`
		local short_commit_id=`trim_obj_id 33 $commit_id`
		local author_time=`git_show_author_time $testroot/repo-clone`
		d=`date -u -r $author_time +"%G-%m-%d"`
		set -- "$@" "$short_commit_id $d"
	done

	(printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l "$GOTD_TEST_SMTP_PORT" > $testroot/stdout) &

	got send -b main -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for nc -l

	HOSTNAME=`hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" \
		>> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} changed refs/heads/main\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	for i in `seq 1 51`; do
		s=`pop_idx $i "$@"`
		commit_id=$(echo $s | cut -d' ' -f1)
		commit_time=$(echo $s | sed -e "s/^$commit_id //g")
		printf "$commit_time $commit_id $GOT_AUTHOR_8 make changes\n" \
			>> $testroot/stdout.expected
	done
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_branch_created() {
	local testroot=`test_init branch_created 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	(cd $testroot/wt && got branch newbranch > /dev/null)

	echo "change alpha on branch" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'newbranch' > /dev/null)
	local commit_id=`git_show_branch_head $testroot/repo-clone newbranch`
	local author_time=`git_show_author_time $testroot/repo-clone $commit_id`

	(printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l "$GOTD_TEST_SMTP_PORT" > $testroot/stdout) &

	got send -b newbranch -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for nc -l

	HOSTNAME=`hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" >> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} created refs/heads/newbranch\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf "commit $commit_id\n" >> $testroot/stdout.expected
	printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
	d=`date -u -r $author_time +"%a %b %e %X %Y UTC"`
	printf "date: $d\n" >> $testroot/stdout.expected
	printf "messagelen: 11\n" >> $testroot/stdout.expected
	printf " \n" >> $testroot/stdout.expected
	printf " newbranch\n \n" >> $testroot/stdout.expected
	printf " M  alpha  |  1+  1-\n\n"  >> $testroot/stdout.expected
	printf "1 file changed, 1 insertion(+), 1 deletion(-)\n\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_branch_removed() {
	local testroot=`test_init branch_removed 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	(printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l "$GOTD_TEST_SMTP_PORT" > $testroot/stdout) &

	local commit_id=`git_show_branch_head $testroot/repo-clone newbranch`

	got send -d newbranch -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for nc -l

	HOSTNAME=`hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" >> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} removed refs/heads/newbranch\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf "Removed refs/heads/newbranch: $commit_id\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_tag_created() {
	local testroot=`test_init tag_created 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got tag -r $testroot/repo-clone -m "new tag" 1.0 > /dev/null
	local commit_id=`git_show_head $testroot/repo-clone`
	local tagger_time=`git_show_tagger_time $testroot/repo-clone 1.0`

	(printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l "$GOTD_TEST_SMTP_PORT" > $testroot/stdout) &

	got send -t 1.0 -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for nc -l

	HOSTNAME=`hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" >> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} created refs/tags/1.0\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf "tag refs/tags/1.0\n" >> $testroot/stdout.expected
	printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
	d=`date -u -r $tagger_time +"%a %b %e %X %Y UTC"`
	printf "date: $d\n" >> $testroot/stdout.expected
	printf "object: commit $commit_id\n" >> $testroot/stdout.expected
	printf "messagelen: 9\n" >> $testroot/stdout.expected
	printf " \n" >> $testroot/stdout.expected
	printf " new tag\n \n" >> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_tag_changed() {
	local testroot=`test_init tag_changed 1`

	got clone -a -q ${GOTD_TEST_REPO_URL} $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got clone failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	got checkout -q $testroot/repo-clone $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "change alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'make changes' > /dev/null)
	local commit_id=`git_show_head $testroot/repo-clone`

	got ref -r $testroot/repo-clone -d refs/tags/1.0 >/dev/null
	got tag -r $testroot/repo-clone -m "new tag" 1.0 > /dev/null
	local tagger_time=`git_show_tagger_time $testroot/repo-clone 1.0`

	(printf "220\r\n250\r\n250\r\n250\r\n354\r\n250\r\n221\r\n" \
		| timeout 5 nc -l "$GOTD_TEST_SMTP_PORT" > $testroot/stdout) &

	got send -f -t 1.0 -q -r $testroot/repo-clone
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	wait %1 # wait for nc -l

	HOSTNAME=`hostname`
	printf "HELO localhost\r\n" > $testroot/stdout.expected
	printf "MAIL FROM:<${GOTD_USER}@${HOSTNAME}>\r\n" \
		>> $testroot/stdout.expected
	printf "RCPT TO:<${GOTD_DEVUSER}>\r\n" >> $testroot/stdout.expected
	printf "DATA\r\n" >> $testroot/stdout.expected
	printf "From: ${GOTD_USER}@${HOSTNAME}\r\n" >> $testroot/stdout.expected
	printf "To: ${GOTD_DEVUSER}\r\n" >> $testroot/stdout.expected
	printf "Subject: $GOTD_TEST_REPO_NAME: " >> $testroot/stdout.expected
	printf "${GOTD_DEVUSER} changed refs/tags/1.0\r\n" \
		>> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf "tag refs/tags/1.0\n" >> $testroot/stdout.expected
	printf "from: $GOT_AUTHOR\n" >> $testroot/stdout.expected
	d=`date -u -r $tagger_time +"%a %b %e %X %Y UTC"`
	printf "date: $d\n" >> $testroot/stdout.expected
	printf "messagelen: 8\n" >> $testroot/stdout.expected
	printf "object: commit $commit_id\n" >> $testroot/stdout.expected
	printf " \n" >> $testroot/stdout.expected
	printf " new tag\n \n" >> $testroot/stdout.expected
	printf "\r\n" >> $testroot/stdout.expected
	printf ".\r\n" >> $testroot/stdout.expected
	printf "QUIT\r\n" >> $testroot/stdout.expected

	grep -v ^Date $testroot/stdout > $testroot/stdout.filtered
	cmp -s $testroot/stdout.expected $testroot/stdout.filtered
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout.filtered
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_file_changed
run_test test_many_commits_not_summarized
run_test test_many_commits_summarized
run_test test_branch_created
run_test test_branch_removed
run_test test_tag_created
run_test test_tag_changed
