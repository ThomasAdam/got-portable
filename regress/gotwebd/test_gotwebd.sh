#!/bin/sh
#
# Copyright (c) 2024 Mark Jamsek <mark@jamsek.dev>
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

. ${GOTWEBD_TEST_DATA_DIR}/common.sh

test_gotwebd_action_summary()
{
	local testroot=$(test_init gotwebd_action_summary 1)
	local repo="${GOTWEBD_TEST_CHROOT}/got/public/repo.git"
	local author_time=$(git_show_author_time $repo)
	local id=$(git_show_head $repo)

	COMMIT_ID=$id \
	COMMIT_ID10=$(printf '%.10s' $id) \
	COMMIT_YMDHMS=$(date -u -r $author_time +"%FT%TZ") \
	interpolate ${GOTWEBD_TEST_DATA_DIR}/action_summary.html \
		> $testroot/content.expected

	$GOTWEBD_TEST_FCGI > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "" "$ret"
		return 1
	fi

	test_done "$testroot" "" "$ret"
}

test_gotwebd_action_diff()
{
	local testroot=$(test_init gotwebd_action_diff 1)
	local repo="${GOTWEBD_TEST_CHROOT}/got/public/repo.git"
	local id=$(git_show_head $repo)
	local author_time=$(git_show_author_time $repo)
	local qs="action=diff&commit=${id}&headref=HEAD&path=repo.git"

	COMMIT_ID=$id \
	BLOB_ALPHA=$(get_blob_id $repo "" alpha) \
	BLOB_BETA=$(get_blob_id $repo "" beta) \
	BLOB_ZETA=$(get_blob_id $repo epsilon zeta) \
	BLOB_DELTA=$(get_blob_id $repo gamma delta) \
	COMMITTER="Flan Hacker" \
	COMMITTER_EMAIL="flan_hacker@openbsd.org" \
	COMMIT_YMDHMS=$(date -u -r $author_time +"%FT%TZ") \
	COMMIT_DATE=$(date -u -r $author_time +"%a %b %e %X %Y") \
	interpolate ${GOTWEBD_TEST_DATA_DIR}/action_diff.html \
		> $testroot/content.expected

	$GOTWEBD_TEST_FCGI -q "$qs" > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$repo" "$ret"
		return 1
	fi

	test_done "$testroot" "$repo" "$ret"
}

test_gotwebd_action_blame()
{
	local testroot=$(test_init gotwebd_action_blame 1)
	local repo="${GOTWEBD_TEST_CHROOT}/got/public/repo.git"
	local id=$(git_show_head $repo)
	local author_time=$(git_show_author_time $repo)
	local qs="action=blame&commit=${id}&file=alpha&folder=&path=repo.git"

	COMMIT_ID=$id \
	COMMITTER="flan_hack" \
	COMMIT_ID8=$(printf '%.8s' $id) \
	COMMIT_YMD=$(date -u -r $author_time +"%F") \
	COMMIT_YMDHMS=$(date -u -r $author_time +"%FT%TZ") \
	COMMIT_DATE=$(date -u -r $author_time +"%a %b %e %X %Y") \
	interpolate ${GOTWEBD_TEST_DATA_DIR}/action_blame.html \
		> $testroot/content.expected

	$GOTWEBD_TEST_FCGI -q "$qs" > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$repo" "$ret"
		return 1
	fi

	test_done "$testroot" "$repo" "$ret"
}

test_gotwebd_action_tree()
{
	local testroot=$(test_init gotwebd_action_tree 1)
	local repo="${GOTWEBD_TEST_CHROOT}/got/public/repo.git"
	local author_time=$(git_show_author_time $repo)
	local qs="action=tree&path=repo.git"

	COMMIT_ID=$(git_show_head $repo) \
	COMMIT_YMDHMS=$(date -u -r $author_time +"%FT%TZ") \
	COMMIT_DATE=$(date -u -r $author_time +"%a %b %e %X %Y") \
	TREE_ID=$(got cat -r $repo main | head -1 | cut -d ' ' -f2) \
	interpolate ${GOTWEBD_TEST_DATA_DIR}/action_tree.html \
		> $testroot/content.expected

	$GOTWEBD_TEST_FCGI -q "$qs" > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$repo" "$ret"
		return 1
	fi

	test_done "$testroot" "$repo" "$ret"
}

test_gotwebd_action_patch()
{
	local testroot=$(test_init gotwebd_action_patch 1)
	local repo="${GOTWEBD_TEST_CHROOT}/got/public/repo.git"
	local id=$(git_show_head $repo)
	local author_time=$(git_show_author_time $repo)
	local qs="action=patch&commit=${id}&headref=HEAD&path=repo.git"

	COMMIT_ID=$id \
	BLOB_ALPHA=$(get_blob_id $repo "" alpha) \
	BLOB_BETA=$(get_blob_id $repo "" beta) \
	BLOB_ZETA=$(get_blob_id $repo epsilon zeta) \
	BLOB_DELTA=$(get_blob_id $repo gamma delta) \
	COMMITTER="Flan Hacker" \
	COMMITTER_EMAIL="flan_hacker@openbsd.org" \
	COMMIT_DATE=$(date -u -r $author_time +"%a %b %e %X %Y") \
	interpolate ${GOTWEBD_TEST_DATA_DIR}/action_patch.html \
		> $testroot/content.expected

	$GOTWEBD_TEST_FCGI -q "$qs" > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$repo" "$ret"
		return 1
	fi

	test_done "$testroot" "$repo" "$ret"
}

test_gotwebd_action_commits()
{
	local testroot=$(test_init gotwebd_action_commits 1)
	local repo="${GOTWEBD_TEST_CHROOT}/got/public/repo.git"
	local author_time_root=$(git_show_author_time $repo)
	local id_root=$(git_show_head $repo)
	local qs="action=commits&headref=HEAD&path=repo.git"

	got checkout $repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "'alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "edit alpha" >/dev/null)

	local author_time_head=$(git_show_author_time $repo)

	COMMITTER="Flan Hacker" \
	COMMIT_ID_ROOT=$id_root \
	COMMIT_ID_HEAD=$(git_show_head $repo) \
	COMMITTER_EMAIL="flan_hacker@openbsd.org" \
	COMMIT_YMDHMS_ROOT=$(date -u -r $author_time_root +"%FT%TZ") \
	COMMIT_YMDHMS_HEAD=$(date -u -r $author_time_head +"%FT%TZ") \
	COMMIT_DATE_ROOT=$(date -u -r $author_time_root +"%a %b %e %X %Y") \
	COMMIT_DATE_HEAD=$(date -u -r $author_time_head +"%a %b %e %X %Y") \
	interpolate ${GOTWEBD_TEST_DATA_DIR}/action_commits.html \
		> $testroot/content.expected

	$GOTWEBD_TEST_FCGI -q "$qs" > $testroot/content

	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$repo" "$ret"
		return 1
	fi

	test_done "$testroot" "$repo" "$ret"
}

test_parseargs "$@"
run_test test_gotwebd_action_summary
run_test test_gotwebd_action_diff
run_test test_gotwebd_action_blame
run_test test_gotwebd_action_tree
run_test test_gotwebd_action_patch
run_test test_gotwebd_action_commits
