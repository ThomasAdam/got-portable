#!/bin/sh
#
# Copyright (c) 2023 Omar Polo <op@openbsd.org>
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

format_arg=
if [ "${GOT_TEST_ALGO}" = sha256 ]; then
	format_arg="-A sha256"
fi

test_load_bundle() {
	local testroot=`test_init test_load_bundle`

	# generate a bundle with all the history of the repository
	git -C "$testroot/repo" bundle create -q "$testroot/bundle" master

	# then load it in an empty repository
	(cd "$testroot/" && gotadmin init $format_arg -b master repo2) >/dev/null
	(cd "$testroot/repo2" && gotadmin load < "$testroot/bundle") \
		>/dev/null
	if [ $? -ne 0 ]; then
		echo "failed to load the bundle" >&2
		test_done "$testroot" 1
		return 1
	fi

	(cd "$testroot/repo"  && got log -p >$testroot/repo.log)
	(cd "$testroot/repo2" && got log -p >$testroot/repo2.log)
	if ! cmp -s $testroot/repo.log $testroot/repo2.log; then
		diff -u $testroot/repo.log $testroot/repo2.log
		test_done "$testroot" 1
		return 1
	fi

	base=$(git_show_head "$testroot/repo")

	echo "modified alpha in master" >$testroot/repo/alpha
	git_commit "$testroot/repo" -m "edit alpha in master"

	# XXX git outputs a "thin pack" when making bundles using an
	# exclude base and doesn't provide a way to generate "thick"
	# packs; use gotadmin since we don't support them.
	#git -C "$testroot/repo" bundle create -q \
	#	"$testroot/bundle" "$base..master"
	gotadmin dump -q -r "$testroot/repo" -x "$base" master \
		> "$testroot/bundle"

	(cd "$testroot/repo2" && gotadmin load < "$testroot/bundle") >/dev/null
	if [ $? -ne 0 ]; then
		echo "failed to load incremental bundle" >&2
		test_done "$testroot" 1
		return 1
	fi

	(cd "$testroot/repo"  && got log -p >$testroot/repo.log)
	(cd "$testroot/repo2" && got log -p >$testroot/repo2.log)
	if ! cmp -s $testroot/repo.log $testroot/repo2.log; then
		diff -u $testroot/repo.log $testroot/repo2.log
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" 0
}

test_load_branch_from_bundle() {
	local testroot=`test_init test_load_branch_from_bundle`

	echo "modified alpha in master" >$testroot/repo/alpha
	git_commit "$testroot/repo" -m "edit alpha in master"

	master_commit="$(git_show_head "$testroot/repo")"

	git -C "$testroot/repo" checkout -q -b newbranch

	for i in `seq 1`; do
		echo "alpha edit #$i" > $testroot/repo/alpha
		git_commit "$testroot/repo" -m "edit alpha"
	done

	newbranch_commit="$(git_show_head "$testroot/repo")"

	(cd "$testroot/repo" && gotadmin dump -q >$testroot/bundle)

	(cd "$testroot/" && gotadmin init $format_arg -b newbranch repo2) >/dev/null

	# check that the reference in the bundle are what we expect
	(cd "$testroot/repo2" && gotadmin load -l "$testroot/bundle") \
		>$testroot/stdout

	cat <<EOF >$testroot/stdout.expected
HEAD: $newbranch_commit
refs/heads/master: $master_commit
refs/heads/newbranch: $newbranch_commit
EOF
	if ! cmp -s "$testroot/stdout" "$testroot/stdout.expected"; then
		diff -u "$testroot/stdout" "$testroot/stdout.expected"
		test_done "$testroot" 1
		return 1
	fi

	(cd "$testroot/repo2" && gotadmin load -q refs/heads/newbranch \
		<$testroot/bundle)
	if [ $? -ne 0 ]; then
		echo "gotadmin load failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# now that the bundle is loaded, delete the branch master on
	# the repo to have the same got log output.
	(cd "$testroot/repo" && got branch -d master) >/dev/null

	(cd "$testroot/repo"  && got log -p >$testroot/repo.log)
	(cd "$testroot/repo2" && got log -p >$testroot/repo2.log)
	if ! cmp -s $testroot/repo.log $testroot/repo2.log; then
		diff -u $testroot/repo.log $testroot/repo2.log
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" 0
}

test_parseargs "$@"
run_test test_load_bundle
run_test test_load_branch_from_bundle
