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

test_stage_basic() {
	local testroot=`test_init stage_basic`

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
	(cd $testroot/wt && got stage > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_stage_no_changes() {
	local testroot=`test_init stage_no_changes`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage alpha beta > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got stage command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: no changes to stage" > $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
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

test_stage_unversioned() {
	local testroot=`test_init stage_unversioned`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified file" > $testroot/wt/alpha
	touch $testroot/wt/unversioned-file

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "M  alpha" > $testroot/stdout.expected
	echo "?  unversioned-file" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got stage command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo " M alpha" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified file again" > $testroot/wt/alpha

	(cd $testroot/wt && got stage unversioned-file > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got stage command succeed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: no changes to stage" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"

}

test_stage_nonexistent() {
	local testroot=`test_init stage_nonexistent`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage nonexistent-file \
		> $testroot/stdout 2> $testroot/stderr)
	echo "got: nonexistent-file: No such file or directory" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_stage_list() {
	local testroot=`test_init stage_list`

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

	(cd $testroot/wt && got stage -l > $testroot/stdout)
	(cd $testroot/wt && got diff -s alpha | grep '^blob +' | \
		cut -d' ' -f3 | tr -d '\n' > $testroot/stdout.expected)
	echo " M alpha" >> $testroot/stdout.expected
	(cd $testroot/wt && got diff -s beta | grep '^blob -' | \
		cut -d' ' -f3 | tr -d '\n' >> $testroot/stdout.expected)
	echo " D beta" >> $testroot/stdout.expected
	(cd $testroot/wt && got diff -s foo | grep '^blob +' | \
		cut -d' ' -f3 | tr -d '\n' >> $testroot/stdout.expected)
	echo " A foo" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage -l epsilon nonexistent \
		> $testroot/stdout)

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage -l alpha > $testroot/stdout)

	(cd $testroot/wt && got diff -s alpha | grep '^blob +' | \
		cut -d' ' -f3 | tr -d '\n' > $testroot/stdout.expected)
	echo " M alpha" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

test_stage_conflict() {
	local testroot=`test_init stage_conflict`
	local initial_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "modified alpha" >/dev/null)

	(cd $testroot/wt && got update -c $initial_commit > /dev/null)

	echo "modified alpha, too" > $testroot/wt/alpha

	echo "C  alpha" > $testroot/stdout.expected
	echo -n "Updated to refs/heads/master: " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected
	echo "Files with new merge conflicts: 1" >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage alpha > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got stage command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	echo "got: alpha: cannot stage file in conflicted status" \
		> $testroot/stderr.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

test_stage_out_of_date() {
	local testroot=`test_init stage_out_of_date`
	local initial_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "modified alpha" >/dev/null)

	(cd $testroot/wt && got update -c $initial_commit > /dev/null)

	echo "modified alpha again" > $testroot/wt/alpha
	(cd $testroot/wt && got stage alpha > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got stage command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	echo "got: work tree must be updated before changes can be staged" \
		> $testroot/stderr.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}


test_double_stage() {
	local testroot=`test_init double_stage`

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
	(cd $testroot/wt && got stage alpha beta foo > /dev/null)

	echo "got: no changes to stage" > $testroot/stderr.expected
	(cd $testroot/wt && got stage alpha 2> $testroot/stderr)
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage beta \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got stage command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: no changes to stage" > $testroot/stderr.expected
	(cd $testroot/wt && got stage foo 2> $testroot/stderr)
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	printf "q\n" > $testroot/patchscript
	(cd $testroot/wt && got stage -F $testroot/patchscript -p \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got stage command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: no changes to stage" > $testroot/stderr.expected
	(cd $testroot/wt && got stage foo 2> $testroot/stderr)
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified file again" > $testroot/wt/alpha
	echo "modified new file" > $testroot/wt/foo

	echo ' M alpha' > $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage alpha beta foo > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_stage_status() {
	local testroot=`test_init stage_status`

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
	echo "new file" > $testroot/wt/epsilon/new
	(cd $testroot/wt && got add epsilon/new > /dev/null)
	echo "modified file" > $testroot/wt/epsilon/zeta
	(cd $testroot/wt && got rm gamma/delta > /dev/null)

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo 'A  epsilon/new' >> $testroot/stdout.expected
	echo 'M  epsilon/zeta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected
	echo 'D  gamma/delta' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage alpha beta foo > /dev/null)

	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified file again" >> $testroot/wt/alpha
	echo "modified added file again" >> $testroot/wt/foo

	echo 'MM alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo 'A  epsilon/new' >> $testroot/stdout.expected
	echo 'M  epsilon/zeta' >> $testroot/stdout.expected
	echo 'MA foo' >> $testroot/stdout.expected
	echo 'D  gamma/delta' >> $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# test no-op change of added file with new stat(2) timestamp
	echo "new file" > $testroot/wt/foo
	echo ' A foo' > $testroot/stdout.expected
	(cd $testroot/wt && got status foo > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# test staged deleted file which is restored on disk
	echo "new file" > $testroot/wt/beta
	echo ' D beta' > $testroot/stdout.expected
	(cd $testroot/wt && got status beta > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

test_stage_add_already_staged_file() {
	local testroot=`test_init stage_add_already_staged_file`

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

	(cd $testroot/wt && got stage alpha beta foo > $testroot/stdout)

	echo -n > $testroot/stdout.expected
	for f in alpha beta foo; do
		(cd $testroot/wt && got add $f \
			> $testroot/stdout 2> $testroot/stderr)
		echo "got: $f: file has unexpected status" \
			> $testroot/stderr.expected
		cmp -s $testroot/stderr.expected $testroot/stderr
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stderr.expected $testroot/stderr
			test_done "$testroot" "$ret"
			return 1
		fi
		cmp -s $testroot/stdout.expected $testroot/stdout
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stdout.expected $testroot/stdout
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_stage_rm_already_staged_file() {
	local testroot=`test_init stage_rm_already_staged_file`

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

	(cd $testroot/wt && got stage alpha beta foo > $testroot/stdout)

	(cd $testroot/wt && got rm beta \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got rm command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	echo -n > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	for f in alpha foo; do
		echo "got: $f: file is staged" > $testroot/stderr.expected
		(cd $testroot/wt && got rm $f \
			> $testroot/stdout 2> $testroot/stderr)
		ret=$?
		if [ $ret -eq 0 ]; then
			echo "got rm command succeeded unexpectedly" >&2
			test_done "$testroot" "1"
			return 1
		fi
		cmp -s $testroot/stderr.expected $testroot/stderr
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/stderr.expected $testroot/stderr
			test_done "$testroot" "$ret"
			return 1
		fi
	done

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_stage_revert() {
	local testroot=`test_init stage_revert`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta > /dev/null)
	echo "new file" > $testroot/wt/foo
	(cd $testroot/wt && got add foo > /dev/null)
	(cd $testroot/wt && got stage alpha beta foo > /dev/null)

	echo "modified file again" >> $testroot/wt/alpha
	echo "modified added file again" >> $testroot/wt/foo

	(cd $testroot/wt && got revert alpha > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "revert command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "R  alpha" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo 'MA foo' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got revert alpha > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "revert command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got revert beta > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "revert command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got revert foo > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "revert command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "R  foo" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/content.expected
	cat $testroot/wt/foo > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got revert foo > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "revert command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/content.expected
	cat $testroot/wt/foo > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified file again" >> $testroot/wt/alpha
	echo "modified added file again" >> $testroot/wt/foo

	(cd $testroot/wt && got revert -R . > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "revert command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "R  alpha" > $testroot/stdout.expected
	echo "R  foo" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_stage_diff() {
	local testroot=`test_init stage_diff`
	local head_commit=`git_show_head $testroot/repo`

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

	(cd $testroot/wt && got diff -s > $testroot/stdout)
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage alpha beta foo > /dev/null)

	(cd $testroot/wt && got diff > $testroot/stdout)
	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified file again" > $testroot/wt/alpha
	echo "new file changed" > $testroot/wt/foo

	(cd $testroot/wt && got diff > $testroot/stdout)

	echo "diff $testroot/wt" > $testroot/stdout.expected
	echo "commit - $head_commit" >> $testroot/stdout.expected
	echo "path + $testroot/wt" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l alpha) | cut -d' ' -f 1 | tr -d '\n' \
		>> $testroot/stdout.expected
	echo ' (staged)' >> $testroot/stdout.expected
	echo 'file + alpha' >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-modified file' >> $testroot/stdout.expected
	echo '+modified file again' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l foo) | cut -d' ' -f 1 | tr -d '\n' \
		>> $testroot/stdout.expected
	echo " (staged)" >> $testroot/stdout.expected
	echo 'file + foo' >> $testroot/stdout.expected
	echo '--- foo' >> $testroot/stdout.expected
	echo '+++ foo' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-new file' >> $testroot/stdout.expected
	echo '+new file changed' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff -s > $testroot/stdout)

	echo "diff -s $testroot/wt" > $testroot/stdout.expected
	echo "commit - $head_commit" >> $testroot/stdout.expected
	echo "path + $testroot/wt (staged changes)" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'alpha$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l alpha) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified file' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'beta$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'blob + /dev/null' >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-beta' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l foo) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ foo' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

test_stage_histedit() {
	local testroot=`test_init stage_histedit`
	local orig_commit=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified file" > $testroot/wt/alpha
	(cd $testroot/wt && got stage alpha > /dev/null)

	echo "modified alpha on master" > $testroot/repo/alpha
	(cd $testroot/repo && git rm -q beta)
	echo "new file on master" > $testroot/repo/epsilon/new
	(cd $testroot/repo && git add epsilon/new)
	git_commit $testroot/repo -m "committing changes"
	local old_commit1=`git_show_head $testroot/repo`

	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local old_commit2=`git_show_head $testroot/repo`

	echo "pick $old_commit1" > $testroot/histedit-script
	echo "pick $old_commit2" >> $testroot/histedit-script

	(cd $testroot/wt && got histedit -F $testroot/histedit-script \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got histedit command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	echo "got: alpha: file is staged" > $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

test_stage_rebase() {
	local testroot=`test_init stage_rebase`

	(cd $testroot/repo && git checkout -q -b newbranch)
	echo "modified delta on branch" > $testroot/repo/gamma/delta
	git_commit $testroot/repo -m "committing to delta on newbranch"

	echo "modified alpha on branch" > $testroot/repo/alpha
	(cd $testroot/repo && git rm -q beta)
	echo "new file on branch" > $testroot/repo/epsilon/new
	(cd $testroot/repo && git add epsilon/new)
	git_commit $testroot/repo -m "committing more changes on newbranch"

	local orig_commit1=`git_show_parent_commit $testroot/repo`
	local orig_commit2=`git_show_head $testroot/repo`

	(cd $testroot/repo && git checkout -q master)
	echo "modified zeta on master" > $testroot/repo/epsilon/zeta
	git_commit $testroot/repo -m "committing to zeta on master"
	local master_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified file" > $testroot/wt/alpha
	(cd $testroot/wt && got stage alpha > /dev/null)

	(cd $testroot/wt && got rebase newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got rebase command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	echo "got: alpha: file is staged" > $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_stage_update() {
	local testroot=`test_init stage_update`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified file" > $testroot/wt/alpha
	(cd $testroot/wt && got stage alpha > /dev/null)

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"

	(cd $testroot/wt && got update > $testroot/stdout  \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got update command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	echo "got: alpha: file is staged" > $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_stage_commit_non_staged() {
	local testroot=`test_init stage_commit_non_staged`

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
	(cd $testroot/wt && got stage alpha beta foo > /dev/null)

	echo "modified file" > $testroot/wt/gamma/delta
	(cd $testroot/wt && got commit -m "change delta" gamma/delta \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got commit command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	echo "got: gamma/delta: file is not staged" > $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_stage_commit_out_of_date() {
	local testroot=`test_init stage_commit_out_of_date`

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
	(cd $testroot/wt && got stage alpha beta foo > /dev/null)

	echo "changed file" > $testroot/repo/alpha
	git_commit $testroot/repo -m "changed alpha in repo"

	(cd $testroot/wt && got commit -m "try to commit" > $testroot/stdout \
		2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got commit command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	echo -n "got: work tree must be updated before these changes " \
		> $testroot/stderr.expected
	echo "can be committed" >> $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got update > $testroot/stdout \
		2> $testroot/stderr)
	echo -n > $testroot/stdout.expected
	echo "got: alpha: file is staged" > $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got unstage > /dev/null)
	(cd $testroot/wt && got update > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got update command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo "C  alpha" > $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "A  foo" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# resolve conflict
	echo "resolved file" > $testroot/wt/alpha

	(cd $testroot/wt && got stage > /dev/null)

	(cd $testroot/wt && got commit -m "try again" > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	local commit_id=`git_show_head $testroot/repo`
	echo "A  foo" > $testroot/stdout.expected
	echo "M  alpha" >> $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "Created commit $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

test_stage_commit() {
	local testroot=`test_init stage_commit`
	local first_commit=`git_show_head $testroot/repo`

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
	echo "modified file" > $testroot/wt/alpha
	(cd $testroot/wt && got stage alpha beta foo > /dev/null)

	echo "modified file again" > $testroot/wt/alpha
	echo "new file changed" > $testroot/wt/foo
	echo "non-staged change" > $testroot/wt/gamma/delta
	echo "non-staged new file" > $testroot/wt/epsilon/new
	(cd $testroot/wt && got add epsilon/new > /dev/null)
	(cd $testroot/wt && got rm epsilon/zeta > /dev/null)

	(cd $testroot/wt && got stage -l alpha) | cut -d' ' -f 1 \
		> $testroot/blob_id_alpha
	(cd $testroot/wt && got stage -l foo) | cut -d' ' -f 1 \
		> $testroot/blob_id_foo

	(cd $testroot/wt && got commit -m "staged changes" \
		> $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	local head_commit=`git_show_head $testroot/repo`
	echo "A  foo" > $testroot/stdout.expected
	echo "M  alpha" >> $testroot/stdout.expected
	echo "D  beta" >> $testroot/stdout.expected
	echo "Created commit $head_commit" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got diff -r $testroot/repo $first_commit $head_commit \
		> $testroot/stdout

	echo "diff $first_commit $head_commit" \
		> $testroot/stdout.expected
	echo "commit - $first_commit" >> $testroot/stdout.expected
	echo "commit + $head_commit" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i -c $first_commit | \
		grep 'alpha$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	cat $testroot/blob_id_alpha >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '+modified file' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i -c $first_commit \
		| grep 'beta$' | cut -d' ' -f 1 | tr -d '\n' \
		>> $testroot/stdout.expected
	echo " (mode 644)" >> $testroot/stdout.expected
	echo 'blob + /dev/null' >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-beta' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	cat $testroot/blob_id_foo | tr -d '\n' >> $testroot/stdout.expected
	echo " (mode 644)" >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ foo' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'M  alpha' > $testroot/stdout.expected
	echo 'A  epsilon/new' >> $testroot/stdout.expected
	echo 'D  epsilon/zeta' >> $testroot/stdout.expected
	echo 'M  foo' >> $testroot/stdout.expected
	echo 'M  gamma/delta' >> $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_stage_patch() {
	local testroot=`test_init stage_patch`

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

	sed -i '' -e 's/^2$/a/' $testroot/wt/numbers
	sed -i '' -e 's/^7$/b/' $testroot/wt/numbers
	sed -i '' -e 's/^16$/c/' $testroot/wt/numbers

	# don't stage any hunks
	printf "n\nn\nn\n" > $testroot/patchscript
	(cd $testroot/wt && got stage -F $testroot/patchscript -p \
		numbers > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got stage command succeeded unexpectedly" >&2
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
stage this change? [y/n/q] n
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
stage this change? [y/n/q] n
-----------------------------------------------
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 3 of 3)
stage this change? [y/n/q] n
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: no changes to stage" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
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

	# stage middle hunk
	printf "n\ny\nn\n" > $testroot/patchscript
	(cd $testroot/wt && got stage -F $testroot/patchscript -p \
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
stage this change? [y/n/q] n
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
stage this change? [y/n/q] y
-----------------------------------------------
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 3 of 3)
stage this change? [y/n/q] n
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
	echo "--- numbers" >> $testroot/stdout.expected
	echo "+++ numbers" >> $testroot/stdout.expected
	echo "@@ -4,7 +4,7 @@" >> $testroot/stdout.expected
	echo " 4" >> $testroot/stdout.expected
	echo " 5" >> $testroot/stdout.expected
	echo " 6" >> $testroot/stdout.expected
	echo "-7" >> $testroot/stdout.expected
	echo "+b" >> $testroot/stdout.expected
	echo " 8" >> $testroot/stdout.expected
	echo " 9" >> $testroot/stdout.expected
	echo " 10" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got unstage >/dev/null)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got stage command failed unexpectedly" >&2
		test_done "$testroot" "1"
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

	# stage last hunk
	printf "n\nn\ny\n" > $testroot/patchscript
	(cd $testroot/wt && got stage -F $testroot/patchscript -p \
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
stage this change? [y/n/q] n
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
stage this change? [y/n/q] n
-----------------------------------------------
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 3 of 3)
stage this change? [y/n/q] y
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
	echo "--- numbers" >> $testroot/stdout.expected
	echo "+++ numbers" >> $testroot/stdout.expected
	echo "@@ -13,4 +13,4 @@" >> $testroot/stdout.expected
	echo " 13" >> $testroot/stdout.expected
	echo " 14" >> $testroot/stdout.expected
	echo " 15" >> $testroot/stdout.expected
	echo "-16" >> $testroot/stdout.expected
	echo "+c" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_stage_patch_twice() {
	local testroot=`test_init stage_patch_twice`

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

	sed -i '' -e 's/^2$/a/' $testroot/wt/numbers
	sed -i '' -e 's/^7$/b/' $testroot/wt/numbers
	sed -i '' -e 's/^16$/c/' $testroot/wt/numbers

	# stage middle hunk
	printf "n\ny\nn\n" > $testroot/patchscript
	(cd $testroot/wt && got stage -F $testroot/patchscript -p \
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
stage this change? [y/n/q] n
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
stage this change? [y/n/q] y
-----------------------------------------------
@@ -13,4 +13,4 @@
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 3 of 3)
stage this change? [y/n/q] n
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

	# stage last hunk
	printf "n\ny\n" > $testroot/patchscript
	(cd $testroot/wt && got stage -F $testroot/patchscript -p \
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
stage this change? [y/n/q] n
-----------------------------------------------
@@ -13,4 +13,4 @@ b
 13
 14
 15
-16
+c
-----------------------------------------------
M  numbers (change 2 of 2)
stage this change? [y/n/q] y
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
	echo "--- numbers" >> $testroot/stdout.expected
	echo "+++ numbers" >> $testroot/stdout.expected
	cat >> $testroot/stdout.expected <<EOF
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
	echo 'file + numbers' >> $testroot/stdout.expected
	echo "--- numbers" >> $testroot/stdout.expected
	echo "+++ numbers" >> $testroot/stdout.expected
	cat >> $testroot/stdout.expected <<EOF
@@ -1,5 +1,5 @@
 1
-2
+a
 3
 4
 5
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_stage_patch_added() {
	local testroot=`test_init stage_patch_added`
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new" > $testroot/wt/epsilon/new
	(cd $testroot/wt && got add epsilon/new > /dev/null)

	printf "y\n" > $testroot/patchscript
	(cd $testroot/wt && got stage -F $testroot/patchscript -p \
		epsilon/new > $testroot/stdout)

	echo "A  epsilon/new" > $testroot/stdout.expected
	echo "stage this addition? [y/n] y" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo " A epsilon/new" > $testroot/stdout.expected
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
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l epsilon/new) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
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

test_stage_patch_added_twice() {
	local testroot=`test_init stage_patch_added_twice`
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new" > $testroot/wt/epsilon/new
	(cd $testroot/wt && got add epsilon/new > /dev/null)

	printf "y\n" > $testroot/patchscript
	(cd $testroot/wt && got stage -F $testroot/patchscript -p \
		epsilon/new > $testroot/stdout)

	echo "A  epsilon/new" > $testroot/stdout.expected
	echo "stage this addition? [y/n] y" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo " A epsilon/new" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage -F $testroot/patchscript -p \
		epsilon/new > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got stage command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: no changes to stage" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
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

test_stage_patch_removed() {
	local testroot=`test_init stage_patch_removed`
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rm beta > /dev/null)

	printf "y\n" > $testroot/patchscript
	(cd $testroot/wt && got stage -F $testroot/patchscript -p \
		beta > $testroot/stdout)

	echo -n > $testroot/stdout.expected

	echo "D  beta" > $testroot/stdout.expected
	echo "stage this deletion? [y/n] y" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo " D beta" > $testroot/stdout.expected
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
	(cd $testroot/wt && got stage -l beta) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'blob + /dev/null' >> $testroot/stdout.expected
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

test_stage_patch_removed_twice() {
	local testroot=`test_init stage_patch_removed_twice`
	local commit_id=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got rm beta > /dev/null)

	printf "y\n" > $testroot/patchscript
	(cd $testroot/wt && got stage -F $testroot/patchscript -p \
		beta > $testroot/stdout)

	echo -n > $testroot/stdout.expected

	echo "D  beta" > $testroot/stdout.expected
	echo "stage this deletion? [y/n] y" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	echo " D beta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage -F $testroot/patchscript -p beta \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got stage command succeeded unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "got: no changes to stage" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
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

test_stage_patch_reversed() {
	local testroot=`test_init stage_patch_reversed`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'ALPHA' > $testroot/wt/alpha
	(cd $testroot/wt && got stage alpha > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo ' M alpha' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'alpha' > $testroot/wt/alpha
	(cd $testroot/wt && got stage alpha > $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo ' M alpha' > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s /dev/null $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u /dev/null $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

test_stage_patch_quit() {
	local testroot=`test_init stage_patch_quit`

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

	sed -i '' -e 's/^2$/a/' $testroot/wt/numbers
	sed -i '' -e 's/^7$/b/' $testroot/wt/numbers
	sed -i '' -e 's/^16$/c/' $testroot/wt/numbers
	(cd $testroot/wt && got rm zzz > /dev/null)

	# stage first hunk and quit; and don't pass a path argument to
	# ensure that we don't skip asking about the 'zzz' file after 'quit'
	printf "y\nq\nn\n" > $testroot/patchscript
	(cd $testroot/wt && got stage -F $testroot/patchscript -p \
		> $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got stage command failed unexpectedly" >&2
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
stage this change? [y/n/q] y
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
stage this change? [y/n/q] q
D  zzz
stage this deletion? [y/n] n
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
	echo "D  zzz" >> $testroot/stdout.expected
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
	fi
	test_done "$testroot" "$ret"

}

test_stage_patch_incomplete_script() {
	local testroot=`test_init stage_incomplete_script`

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

	sed -i '' -e 's/^2$/a/' $testroot/wt/numbers
	sed -i '' -e 's/^7$/b/' $testroot/wt/numbers
	sed -i '' -e 's/^16$/c/' $testroot/wt/numbers

	# stage first hunk and then stop responding; got should error out
	printf "y\n" > $testroot/patchscript
	(cd $testroot/wt && got stage -F $testroot/patchscript -p \
		> $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got stage command succeeded unexpectedly" >&2
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
stage this change? [y/n/q] y
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
EOF
	echo -n "stage this change? [y/n/q] " >> $testroot/stdout.expected
	echo "got: invalid patch choice" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

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
	fi
	test_done "$testroot" "$ret"

}

test_stage_symlink() {
	local testroot=`test_init stage_symlink`

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
	(cd $testroot/wt && rm epsilon.link && ln -s gamma epsilon.link)
	(cd $testroot/wt && ln -sf ../gamma/delta epsilon/beta.link)
	echo 'this is regular file foo' > $testroot/wt/dotgotfoo.link
	(cd $testroot/wt && got add dotgotfoo.link > /dev/null)
	(cd $testroot/wt && ln -sf .got/bar dotgotbar.link)
	(cd $testroot/wt && got add dotgotbar.link > /dev/null)
	(cd $testroot/wt && got rm nonexistent.link > /dev/null)
	(cd $testroot/wt && ln -sf gamma/delta zeta.link)
	(cd $testroot/wt && got add zeta.link > /dev/null)

	(cd $testroot/wt && got stage > $testroot/stdout 2> $testroot/stderr)
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got stage succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi
	echo -n "got: $testroot/wt/dotgotbar.link: " > $testroot/stderr.expected
	echo "symbolic link points outside of paths under version control" \
		>> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage -S > $testroot/stdout)

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

	rm $testroot/wt/alpha.link
	echo 'this is regular file alpha.link' > $testroot/wt/alpha.link

	(cd $testroot/wt && got diff -s > $testroot/stdout)

	echo "diff -s $testroot/wt" > $testroot/stdout.expected
	echo "commit - $head_commit" >> $testroot/stdout.expected
	echo "path + $testroot/wt (staged changes)" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'alpha.link@ -> alpha$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l alpha.link) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo '--- alpha.link' >> $testroot/stdout.expected
	echo '+++ alpha.link' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo '+beta' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l dotgotbar.link) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ dotgotbar.link' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+.got/bar' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l dotgotfoo.link) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ dotgotfoo.link' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+this is regular file foo' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i epsilon | grep 'beta.link@ -> ../beta$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l epsilon/beta.link) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo '--- epsilon/beta.link' >> $testroot/stdout.expected
	echo '+++ epsilon/beta.link' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-../beta' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo '+../gamma/delta' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'epsilon.link@ -> epsilon$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l epsilon.link) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo '--- epsilon.link' >> $testroot/stdout.expected
	echo '+++ epsilon.link' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-epsilon' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo '+gamma' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'nonexistent.link@ -> nonexistent$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo 'blob + /dev/null' >> $testroot/stdout.expected
	echo '--- nonexistent.link' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-nonexistent' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l zeta.link) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ zeta.link' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+gamma/delta' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got commit -m "staged symlink" \
		> $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	local commit_id=`git_show_head $testroot/repo`
	echo "A  dotgotbar.link" > $testroot/stdout.expected
	echo "A  dotgotfoo.link" >> $testroot/stdout.expected
	echo "A  zeta.link" >> $testroot/stdout.expected
	echo "M  alpha.link" >> $testroot/stdout.expected
	echo "M  epsilon/beta.link" >> $testroot/stdout.expected
	echo "M  epsilon.link" >> $testroot/stdout.expected
	echo "D  nonexistent.link" >> $testroot/stdout.expected
	echo "Created commit $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got tree -r $testroot/repo -c $commit_id > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got tree command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
alpha
alpha.link@ -> beta
beta
dotgotbar.link@ -> .got/bar
dotgotfoo.link
epsilon/
epsilon.link@ -> gamma
gamma/
passwd.link@ -> /etc/passwd
zeta.link@ -> gamma/delta
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		return 1
	fi

	if [ -h $testroot/wt/alpha.link ]; then
		echo "alpha.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	echo 'this is regular file alpha.link' > $testroot/content.expected
	cp $testroot/wt/alpha.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ ! -h $testroot/wt/dotgotbar.link ]; then
		echo "dotgotbar.link is not a symlink"
		test_done "$testroot" "1"
		return 1
	fi
	(cd $testroot/wt && got update > /dev/null)
	if [ -h $testroot/wt/dotgotbar.link ]; then
		echo "dotgotbar.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi
	echo -n ".got/bar" > $testroot/content.expected
	cp $testroot/wt/dotgotbar.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if [ -h $testroot/wt/dotgotfoo.link ]; then
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

	if ! [ -h $testroot/wt/epsilon.link ]; then
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

	if [ -h $testroot/wt/passwd.link ]; then
		echo "passwd.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi
	echo -n "/etc/passwd" > $testroot/content.expected
	cp $testroot/wt/passwd.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if ! [ -h $testroot/wt/zeta.link ]; then
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

test_stage_patch_symlink() {
	local testroot=`test_init stage_patch_symlink`

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
	(cd $testroot/wt && rm epsilon.link && ln -s gamma epsilon.link)
	(cd $testroot/wt && ln -sf ../gamma/delta epsilon/beta.link)
	echo 'this is regular file foo' > $testroot/wt/dotgotfoo.link
	(cd $testroot/wt && got add dotgotfoo.link > /dev/null)
	(cd $testroot/wt && ln -sf .got/bar dotgotbar.link)
	(cd $testroot/wt && got add dotgotbar.link > /dev/null)
	(cd $testroot/wt && got rm nonexistent.link > /dev/null)
	(cd $testroot/wt && ln -sf gamma/delta zeta.link)
	(cd $testroot/wt && got add zeta.link > /dev/null)

	printf "y\nn\ny\nn\ny\ny\ny" > $testroot/patchscript
	(cd $testroot/wt && got stage -F $testroot/patchscript -p \
		> $testroot/stdout)

	cat > $testroot/stdout.expected <<EOF
-----------------------------------------------
@@ -1 +1 @@
-alpha
\ No newline at end of file
+beta
\ No newline at end of file
-----------------------------------------------
M  alpha.link (change 1 of 1)
stage this change? [y/n/q] y
A  dotgotbar.link
stage this addition? [y/n] n
A  dotgotfoo.link
stage this addition? [y/n] y
-----------------------------------------------
@@ -1 +1 @@
-../beta
\ No newline at end of file
+../gamma/delta
\ No newline at end of file
-----------------------------------------------
M  epsilon/beta.link (change 1 of 1)
stage this change? [y/n/q] n
-----------------------------------------------
@@ -1 +1 @@
-epsilon
\ No newline at end of file
+gamma
\ No newline at end of file
-----------------------------------------------
M  epsilon.link (change 1 of 1)
stage this change? [y/n/q] y
D  nonexistent.link
stage this deletion? [y/n] y
A  zeta.link
stage this addition? [y/n] y
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	rm $testroot/wt/alpha.link
	echo 'this is regular file alpha.link' > $testroot/wt/alpha.link

	(cd $testroot/wt && got diff -s > $testroot/stdout)

	echo "diff -s $testroot/wt" > $testroot/stdout.expected
	echo "commit - $head_commit" >> $testroot/stdout.expected
	echo "path + $testroot/wt (staged changes)" >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'alpha.link@ -> alpha$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l alpha.link) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo '--- alpha.link' >> $testroot/stdout.expected
	echo '+++ alpha.link' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-alpha' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo '+beta' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l dotgotfoo.link) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ dotgotfoo.link' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+this is regular file foo' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'epsilon.link@ -> epsilon$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l epsilon.link) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo '--- epsilon.link' >> $testroot/stdout.expected
	echo '+++ epsilon.link' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-epsilon' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo '+gamma' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	got tree -r $testroot/repo -i | grep 'nonexistent.link@ -> nonexistent$' | \
		cut -d' ' -f 1 >> $testroot/stdout.expected
	echo 'blob + /dev/null' >> $testroot/stdout.expected
	echo '--- nonexistent.link' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-nonexistent' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l zeta.link) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ zeta.link' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+gamma/delta' >> $testroot/stdout.expected
	echo '\ No newline at end of file' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got commit -m "staged symlink" \
		> $testroot/stdout)
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got commit command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	local commit_id=`git_show_head $testroot/repo`
	echo "A  dotgotfoo.link" > $testroot/stdout.expected
	echo "A  zeta.link" >> $testroot/stdout.expected
	echo "M  alpha.link" >> $testroot/stdout.expected
	echo "M  epsilon.link" >> $testroot/stdout.expected
	echo "D  nonexistent.link" >> $testroot/stdout.expected
	echo "Created commit $commit_id" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got tree -r $testroot/repo -c $commit_id > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got tree command failed unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
alpha
alpha.link@ -> beta
beta
dotgotfoo.link
epsilon/
epsilon.link@ -> gamma
gamma/
passwd.link@ -> /etc/passwd
zeta.link@ -> gamma/delta
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		return 1
	fi

	if [ -h $testroot/wt/alpha.link ]; then
		echo "alpha.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi

	echo 'this is regular file alpha.link' > $testroot/content.expected
	cp $testroot/wt/alpha.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

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

	if [ -h $testroot/wt/dotgotfoo.link ]; then
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

	if ! [ -h $testroot/wt/epsilon.link ]; then
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

	if [ -h $testroot/wt/passwd.link ]; then
		echo "passwd.link is a symlink"
		test_done "$testroot" "1"
		return 1
	fi
	echo -n "/etc/passwd" > $testroot/content.expected
	cp $testroot/wt/passwd.link $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	if ! [ -h $testroot/wt/zeta.link ]; then
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

test_parseargs "$@"
run_test test_stage_basic
run_test test_stage_no_changes
run_test test_stage_unversioned
run_test test_stage_nonexistent
run_test test_stage_list
run_test test_stage_conflict
run_test test_stage_out_of_date
run_test test_double_stage
run_test test_stage_status
run_test test_stage_add_already_staged_file
run_test test_stage_rm_already_staged_file
run_test test_stage_revert
run_test test_stage_diff
run_test test_stage_histedit
run_test test_stage_rebase
run_test test_stage_update
run_test test_stage_commit_non_staged
run_test test_stage_commit_out_of_date
run_test test_stage_commit
run_test test_stage_patch
run_test test_stage_patch_twice
run_test test_stage_patch_added
run_test test_stage_patch_added_twice
run_test test_stage_patch_removed
run_test test_stage_patch_removed_twice
run_test test_stage_patch_reversed
run_test test_stage_patch_quit
run_test test_stage_patch_incomplete_script
run_test test_stage_symlink
run_test test_stage_patch_symlink
