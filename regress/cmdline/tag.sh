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

test_tag_create() {
	local testroot=`test_init tag_create`
	local commit_id=`git_show_head $testroot/repo`
	local tag=1.0.0
	local tag2=2.0.0

	# Create a tag based on repository's HEAD reference
	got tag -m 'test' -r $testroot/repo -c HEAD $tag > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`
	echo "Created tag $tag_id" > $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure that Git recognizes the tag Got has created
	git -C $testroot/repo checkout -q $tag
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure Got recognizes the new tag
	got checkout -c $tag $testroot/repo $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Create a tag based on implied worktree HEAD ref
	(cd $testroot/wt && got branch foo > /dev/null)
	echo 'foo' >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m foo > /dev/null)
	local commit_id2=`git_show_branch_head $testroot/repo foo`
	(cd $testroot/wt && got tag -m 'test' $tag2 > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	tag_id2=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag2" | tr -d ' ' | cut -d: -f2`
	echo "Created tag $tag_id2" > $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	tagged_commit=`got cat -r $testroot/repo $tag2 | grep ^object \
		| cut -d' ' -f2`
	if [ "$tagged_commit" != "$commit_id2" ]; then
		echo "wrong commit was tagged" >&2
		test_done "$testroot" "1"
		return 1
	fi

	git -C $testroot/repo checkout -q $tag2
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Attempt to create a tag pointing at a non-commit
	local tree_id=`git_show_tree $testroot/repo`
	(cd $testroot/wt && got tag -m 'test' -c $tree_id foobar \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got tag command succeeded unexpectedly"
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: commit $tree_id: object not found" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got ref -r $testroot/repo -l > $testroot/stdout
	echo "HEAD: $commit_id2" > $testroot/stdout.expected
	echo -n "refs/got/worktree/base-" >> $testroot/stdout.expected
	cat $testroot/wt/.got/uuid | tr -d '\n' >> $testroot/stdout.expected
	echo ": $commit_id2" >> $testroot/stdout.expected
	echo "refs/heads/foo: $commit_id2" >> $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	echo "refs/tags/$tag: $tag_id" >> $testroot/stdout.expected
	echo "refs/tags/$tag2: $tag_id2" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_tag_list() {
	local testroot=`test_init tag_list`
	local commit_id=`git_show_head $testroot/repo`
	local tag=1.0.0
	local tag2=2.0.0

	# create tag with Git
	git -C $testroot/repo tag -a -m 'test' $tag
	# create tag with Got
	(cd $testroot/repo && got tag -m 'test' $tag2 > /dev/null)

	tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`
	local tagger_time=`git_show_tagger_time $testroot/repo $tag`
	d1=`date -u -r $tagger_time +"%a %b %e %X %Y UTC"`
	tag_id2=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag2" | tr -d ' ' | cut -d: -f2`
	local tagger_time2=`git_show_tagger_time $testroot/repo $tag2`
	d2=`date -u -r $tagger_time2 +"%a %b %e %X %Y UTC"`

	got tag -r $testroot/repo -l > $testroot/stdout

	echo "-----------------------------------------------" \
		> $testroot/stdout.expected
	echo "tag $tag2 $tag_id2" >> $testroot/stdout.expected
	echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo "date: $d2" >> $testroot/stdout.expected
	echo "object: commit $commit_id" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo " test" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo "-----------------------------------------------" \
		>> $testroot/stdout.expected
	echo "tag $tag $tag_id" >> $testroot/stdout.expected
	echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo "date: $d1" >> $testroot/stdout.expected
	echo "object: commit $commit_id" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo " test" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got tag -r $testroot/repo -l $tag > $testroot/stdout

	echo "-----------------------------------------------" \
		> $testroot/stdout.expected
	echo "tag $tag $tag_id" >> $testroot/stdout.expected
	echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo "date: $d1" >> $testroot/stdout.expected
	echo "object: commit $commit_id" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo " test" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got tag -r $testroot/repo -l $tag2 > $testroot/stdout

	echo "-----------------------------------------------" \
		> $testroot/stdout.expected
	echo "tag $tag2 $tag_id2" >> $testroot/stdout.expected
	echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo "date: $d2" >> $testroot/stdout.expected
	echo "object: commit $commit_id" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo " test" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_tag_list_oneline() {
	local testroot=`test_init tag_list`
	local commit_id=`git_show_head $testroot/repo`
	local tag=1.0.0
	local tag2=2.0.0

	local head_ref=`got ref -r $testroot/repo -l | sed -n 's/^HEAD: //p'`
	local tag_commit_id=`got ref -r $testroot/repo -l "$head_ref" |
	    sed -n "s:^$head_ref\: ::p"`

	# create tag with Git
	git -C $testroot/repo tag -a -m 'test' $tag
	# create tag with Got
	(cd $testroot/repo && got tag -m 'test' $tag2 > /dev/null)

	local tagger_time=`git_show_tagger_time $testroot/repo $tag`
	d1=`date -u -r $tagger_time +"%F"`
	local tagger_time2=`git_show_tagger_time $testroot/repo $tag2`
	d2=`date -u -r $tagger_time2 +"%F"`

	got tag -r $testroot/repo -ls > $testroot/stdout

	echo "$d2 commit:$(trim_obj_id 10 "$tag_commit_id") $tag2: test" \
	    > $testroot/stdout.expected
	echo "$d1 commit:$(trim_obj_id 10 "$tag_commit_id") $tag: test" \
	    >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got tag -r $testroot/repo -ls $tag > $testroot/stdout

	echo "$d1 commit:$(trim_obj_id 10 "$tag_commit_id") $tag: test" \
	    > $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got tag -r $testroot/repo -ls $tag2 > $testroot/stdout

	echo "$d2 commit:$(trim_obj_id 10 "$tag_commit_id") $tag2: test" \
	    > $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_tag_list_lightweight() {
	local testroot=`test_init tag_list_lightweight`
	local commit_id=`git_show_head $testroot/repo`
	local tag=1.0.0
	local tag2=2.0.0

	# create "lightweight" tag with Git
	git -C $testroot/repo tag $tag
	git -C $testroot/repo tag $tag2

	tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`
	local tagger_time=`git_show_author_time $testroot/repo $tag`
	d1=`date -u -r $tagger_time +"%a %b %e %X %Y UTC"`
	tag_id2=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag2" | tr -d ' ' | cut -d: -f2`
	local tagger_time2=`git_show_author_time $testroot/repo $tag2`
	d2=`date -u -r $tagger_time2 +"%a %b %e %X %Y UTC"`

	got tag -r $testroot/repo -l > $testroot/stdout

	# test signature validation ignoring lightweight tags
	got tag -r $testroot/repo -V > $testroot/stdout

	echo "-----------------------------------------------" \
		> $testroot/stdout.expected
	echo "tag $tag2 $tag_id2" >> $testroot/stdout.expected
	echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo "date: $d2" >> $testroot/stdout.expected
	echo "object: commit $commit_id" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo " adding the test tree" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo "-----------------------------------------------" \
		>> $testroot/stdout.expected
	echo "tag $tag $tag_id" >> $testroot/stdout.expected
	echo "from: $GOT_AUTHOR" >> $testroot/stdout.expected
	echo "date: $d1" >> $testroot/stdout.expected
	echo "object: commit $commit_id" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	echo " adding the test tree" >> $testroot/stdout.expected
	echo " " >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_tag_create_ssh_signed() {
	local testroot=`test_init tag_create`
	local commit_id=`git_show_head $testroot/repo`
	local tag=1.0.0
	local tag2=2.0.0
	local tag3=3.0.0

	ssh-keygen -q -N '' -t ed25519 -f $testroot/id_ed25519
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "ssh-keygen failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi
	touch $testroot/allowed_signers
	touch $testroot/revoked_signers
	echo "allowed_signers \"$testroot/allowed_signers\"" >> \
		$testroot/repo/.git/got.conf
	echo "revoked_signers \"$testroot/revoked_signers\"" >> \
		$testroot/repo/.git/got.conf

	# Create a signed tag based on repository's HEAD reference
	got tag -S $testroot/id_ed25519 -m 'test' -r $testroot/repo -c HEAD \
		$tag > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got tag command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	tag_id=`got ref -r $testroot/repo -l \
		| grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2`
	echo "Created tag $tag_id" > $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure validation fails when the key is not allowed
	echo "signature: Could not verify signature." > \
		$testroot/stdout.expected
	VERIFY_STDOUT=$(got tag -r $testroot/repo -V $tag 2> $testroot/stderr)
	ret=$?
	echo "$VERIFY_STDOUT" | grep '^signature: ' > $testroot/stdout
	if [ $ret -eq 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "1"
		return 1
	fi

	GOOD_SIG='Good "git" signature for flan_hacker@openbsd.org with ED25519 key '

	# Validate the signature with the key allowed
	echo -n 'flan_hacker@openbsd.org ' > $testroot/allowed_signers
	cat $testroot/id_ed25519.pub >> $testroot/allowed_signers
	GOT_STDOUT=$(got tag -r $testroot/repo -V $tag 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got tag command failed unexpectedly"
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	if ! echo "$GOT_STDOUT" | grep -q "^signature: $GOOD_SIG"; then
		echo "got tag command failed to validate signature"
		test_done "$testroot" "1"
		return 1
	fi

	# Ensure validation fails after revoking the key
	ssh-keygen -y -f $testroot/id_ed25519 >> $testroot/revoked_signers
	echo "signature: Could not verify signature." > \
		$testroot/stdout.expected
	VERIFY_STDOUT=$(got tag -r $testroot/repo -V $tag 2> $testroot/stderr)
	ret=$?
	echo "$VERIFY_STDOUT" | grep '^signature: ' > $testroot/stdout
	if [ $ret -eq 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "1"
		return 1
	fi

	# Later tests expect validation to work
	echo -n > $testroot/revoked_signers

	# Ensure that Git recognizes and verifies the tag Got has created
	git -C $testroot/repo checkout -q $tag
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "git checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi
	git -C $testroot/repo config --local gpg.ssh.allowedSignersFile \
		$testroot/allowed_signers
	GIT_STDERR=$(git -C $testroot/repo tag -v $tag 2>&1 1>/dev/null)
	if ! echo "$GIT_STDERR" | grep -q "^$GOOD_SIG"; then
		echo "git tag command failed to validate signature"
		test_done "$testroot" "1"
		return 1
	fi

	# Ensure Got recognizes the new tag
	got checkout -c $tag $testroot/repo $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# Create another signed tag with a SHA1 commit ID
	got tag -S $testroot/id_ed25519 -m 'test' -r $testroot/repo \
		-c $commit_id $tag2 > $testroot/stdout

	# Create another signed tag with key defined in got.conf(5)
	echo "signer_id \"$testroot/id_ed25519\"" >> \
		$testroot/repo/.git/got.conf
	got tag -m 'test' -r $testroot/repo -c HEAD $tag3 > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got tag command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# got tag -V behaves like got tag -l, but with verification enabled.
	got tag -l -r $testroot/repo > $testroot/stdout.list
	got tag -V -r $testroot/repo > $testroot/stdout.verify
	diff -U0 $testroot/stdout.list $testroot/stdout.verify |
	    sed -e '/^--- /d' -e '/^+++ /d' > $testroot/stdout
	echo "@@ -5,0 +6 @@" > $testroot/stdout.expected
	echo -n "+signature: $GOOD_SIG" >> $testroot/stdout.expected
	ssh-keygen -l -f $testroot/id_ed25519.pub | cut -d' ' -f 2 \
		>> $testroot/stdout.expected
	echo "@@ -19,0 +21 @@" >> $testroot/stdout.expected
	echo -n "+signature: $GOOD_SIG" >> $testroot/stdout.expected
	ssh-keygen -l -f $testroot/id_ed25519.pub | cut -d' ' -f 2 \
		>> $testroot/stdout.expected
	echo "@@ -33,0 +36 @@" >> $testroot/stdout.expected
	echo -n "+signature: $GOOD_SIG" >> $testroot/stdout.expected
	ssh-keygen -l -f $testroot/id_ed25519.pub | cut -d' ' -f 2 \
		>> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_tag_create_ssh_signed_missing_key() {
	local testroot=`test_init tag_create`
	local commit_id=`git_show_head $testroot/repo`
	local tag=1.0.0

	# Fail to create a signed tag due to a missing SSH key
	got tag -S $testroot/bogus -m 'test' -r $testroot/repo \
		-c HEAD	$tag > $testroot/stdout 2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got tag command succeeded unexpectedly"
		test_done "$testroot" 1
		return 1
	fi

	got ref -r $testroot/repo -l > $testroot/stdout
	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo "refs/heads/master: $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	printf "Couldn't load public key $testroot/bogus: " \
		>> $testroot/stderr.expected
	printf "No such file or directory\r\n" >> $testroot/stderr.expected
	echo "got: unable to sign tag" >> $testroot/stderr.expected
	cmp -s $testroot/stderr $testroot/stderr.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_tag_commit_keywords() {
	local testroot=$(test_init tag_commit_keywords)
	local repo="$testroot/repo"
	local wt="$testroot/wt"
	local commit_id=$(git_show_head "$repo")
	local tag=1.0.0
	local tag2=2.0.0

	echo "alphas" > "$repo/alpha"
	git_commit "$repo" -m "alphas"

	# create tag based on first gen ancestor of the repository's HEAD
	got tag -m 'v1.0.0' -r "$repo" -c:head:- "$tag" > "$testroot/stdout"
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got ref command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	tag_id=$(got ref -r "$repo" -l \
	    | grep "^refs/tags/$tag" | tr -d ' ' | cut -d: -f2)
	echo "Created tag $tag_id" > "$testroot/stdout.expected"
	cmp -s "$testroot/stdout" "$testroot/stdout.expected"
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u "$testroot/stdout.expected" "$testroot/stdout"
		test_done "$testroot" "$ret"
		return 1
	fi

	tag_commit=$(got cat -r "$repo" "$tag" | grep ^object | cut -d' ' -f2)
	if [ "$tag_commit" != "$commit_id" ]; then
		echo "wrong commit was tagged" >&2
		test_done "$testroot" "1"
		return 1
	fi

	got checkout -c "$tag" "$repo" "$wt" >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout command failed unexpectedly"
		test_done "$testroot" "$ret"
		return 1
	fi

	# create new tag based on the base commit's 2nd gen descendant
	(cd "$wt" && got up > /dev/null)
	echo 'foo' > "$wt/alpha"
	echo 'boo' > "$wt/beta"
	echo 'hoo' > "$wt/gamma/delta"
	(cd "$wt" && got commit -m foo alpha > /dev/null)
	(cd "$wt" && got commit -m boo beta > /dev/null)
	(cd "$wt" && got commit -m hoo gamma/delta > /dev/null)
	local head_id=$(git_show_branch_head "$repo")
	(cd "$wt" && got up -c:base:-2 > /dev/null)
	local base_id=$(cd "$wt" && got info | grep base | cut -d' ' -f5)

	(cd "$wt" && got tag -m 'v2.0.0' -c:base:+2 $tag2 > "$testroot/stdout")
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	tag_id2=$(got ref -r "$repo" -l \
	    | grep "^refs/tags/$tag2" | tr -d ' ' | cut -d: -f2)
	echo "Created tag $tag_id2" > $testroot/stdout.expected

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	tag2_commit=$(got cat -r "$repo" "$tag2" | grep ^object | cut -d' ' -f2)
	if [ "$tag2_commit" != "$head_id" ]; then
		echo "wrong commit was tagged" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "HEAD: refs/heads/master" > $testroot/stdout.expected
	echo -n "refs/got/worktree/base-" >> $testroot/stdout.expected
	cat "$wt/.got/uuid" | tr -d '\n' >> $testroot/stdout.expected
	echo ": $base_id" >> $testroot/stdout.expected
	echo "refs/heads/master: $head_id" >> $testroot/stdout.expected
	echo "refs/tags/$tag: $tag_id" >> $testroot/stdout.expected
	echo "refs/tags/$tag2: $tag_id2" >> $testroot/stdout.expected

	got ref -r "$repo" -l > $testroot/stdout

	cmp -s $testroot/stdout $testroot/stdout.expected
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_tag_create
run_test test_tag_list
run_test test_tag_list_lightweight
run_test test_tag_list_oneline
run_test test_tag_create_ssh_signed
run_test test_tag_create_ssh_signed_missing_key
run_test test_tag_commit_keywords
