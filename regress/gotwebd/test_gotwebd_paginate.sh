#!/bin/sh
#
# Copyright (c) 2025 Mark Jamsek <mark@jamsek.dev>
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

test_gotwebd_paginate_commits()
{
	local testroot=$(test_init gotwebd_paginate_commits 1)
	local wt="$testroot/wt"
	local repo="${GOTWEBD_TEST_CHROOT}/got/public/repo.git"
	local ids="$(git_show_head $repo)"
	local dates="$(git_show_author_time $repo)"

	got checkout "$repo" "$wt" > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly"
		test_done "$testroot" "$repo" "$ret"
		return 1
	fi

	cd "$wt"

	for i in $(seq 2 $GOTWEBD_TEST_PAGINATE_NITEMS); do
		echo "alpha $i" > alpha

		got commit -m "commit $i" > /dev/null
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "got commit failed unexpectedly" >&2
			test_done "$testroot" "$repo" "$ret"
			return 1
		fi

		ids="$ids $(git_show_head "$repo")"
		dates="$dates $(git_show_author_time "$repo")"
	done

	for i in $(seq $GOTWEBD_TEST_PAGINATE_NITEMS -3 1); do
		local id_more=$i
		local id=$(pop_idx $i $ids)
		local d1=$(pop_idx $i $dates)
		local d2=$(pop_idx $((i - 1)) $dates)
		local d3=$(pop_idx $((i - 2)) $dates)
		local logmsg3="commit $((i - 2))"
		local page="${GOTWEBD_TEST_DATA_DIR}/commits_page.html"
		local qs="action=commits&commit=${id}&path=repo.git"

		if [ $i -gt 3 ]; then
			id_more=$((i - 3))
		else
			# remove "nav_more" div from the final page footer
			perl -pe 'substr($_, 275, 150, q{}) if eof' "$page" \
			    > "$testroot/commits_page_end.html"
			page="$testroot/commits_page_end.html"
			logmsg3="import the test tree"
		fi

		LOGMSG1="commit $i" \
		LOGMSG2="commit $((i - 1))" \
		LOGMSG3="$logmsg3" \
		COMMITTER="Flan Hacker" \
		COMMIT_ID1="$id" \
		COMMIT_ID2=$(pop_idx $((i - 1)) $ids) \
		COMMIT_ID3=$(pop_idx $((i - 2)) $ids) \
		COMMIT_ID_MORE=$(pop_idx $id_more $ids) \
		COMMITTER_EMAIL="flan_hacker@openbsd.org" \
		COMMIT_YMDHMS1=$(date -u -r $d1 +"%FT%TZ") \
		COMMIT_YMDHMS2=$(date -u -r $d2 +"%FT%TZ") \
		COMMIT_YMDHMS3=$(date -u -r $d3 +"%FT%TZ") \
		COMMIT_DATE1=$(date -u -r $d1 +"%a %b %e %X %Y") \
		COMMIT_DATE2=$(date -u -r $d2 +"%a %b %e %X %Y") \
		COMMIT_DATE3=$(date -u -r $d3 +"%a %b %e %X %Y") \
		interpolate "$page" > "$testroot/content.expected"

		$GOTWEBD_TEST_FCGI -q "$qs" > "$testroot/content"

		cmp -s $testroot/content.expected $testroot/content
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/content.expected $testroot/content
			test_done "$testroot" "$repo" "$ret"
			return 1
		fi
	done

	test_done "$testroot" "$repo" 0
}

test_parseargs "$@"
run_test test_gotwebd_paginate_commits
