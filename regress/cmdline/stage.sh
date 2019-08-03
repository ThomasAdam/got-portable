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

function test_stage_basic {
	local testroot=`test_init stage_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
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
	(cd $testroot/wt && got stage alpha beta foo > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_stage_conflict {
	local testroot=`test_init stage_conflict`
	local initial_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "modified alpha" >/dev/null)

	(cd $testroot/wt && got update -c $initial_commit > /dev/null)

	echo "modified alpha, too" > $testroot/wt/alpha

	echo "C  alpha" > $testroot/stdout.expected
	echo -n "Updated to commit " >> $testroot/stdout.expected
	git_show_head $testroot/repo >> $testroot/stdout.expected
	echo >> $testroot/stdout.expected

	(cd $testroot/wt && got update > $testroot/stdout)

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage alpha > $testroot/stdout \
		2> $testroot/stderr)
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "got stage command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	echo "got: alpha: cannot stage file in conflicted status" \
		> $testroot/stderr.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}

function test_stage_out_of_date {
	local testroot=`test_init stage_out_of_date`
	local initial_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "modified alpha" >/dev/null)

	(cd $testroot/wt && got update -c $initial_commit > /dev/null)

	echo "modified alpha again" > $testroot/wt/alpha
	(cd $testroot/wt && got stage alpha > $testroot/stdout \
		2> $testroot/stderr)
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "got stage command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	echo "got: work tree must be updated before changes can be staged" \
		> $testroot/stderr.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done "$testroot" "$ret"
}


function test_double_stage {
	local testroot=`test_init double_stage`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi
	echo "modified file" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta > /dev/null)
	echo "new file" > $testroot/wt/foo
	(cd $testroot/wt && got add foo > /dev/null)
	(cd $testroot/wt && got stage alpha beta foo > /dev/null)

	echo "got: alpha: no changes to stage" > $testroot/stderr.expected
	(cd $testroot/wt && got stage alpha 2> $testroot/stderr)
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got stage beta > $testroot/stdout)
	if [ "$ret" != "0" ]; then
		echo "got stage command failed unexpectedly" >&2
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

	echo "got: foo: no changes to stage" > $testroot/stderr.expected
	(cd $testroot/wt && got stage foo 2> $testroot/stderr)
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
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
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_stage_status {
	local testroot=`test_init stage_status`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
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
	ret="$?"
	if [ "$ret" != "0" ]; then
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
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# test no-op change of added file with new stat(2) timestamp
	echo "new file" > $testroot/wt/foo
	echo ' A foo' > $testroot/stdout.expected
	(cd $testroot/wt && got status foo > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# test staged deleted file which is restored on disk
	echo "new file" > $testroot/wt/beta
	echo ' D beta' > $testroot/stdout.expected
	(cd $testroot/wt && got status beta > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

function test_stage_add_already_staged_file {
	local testroot=`test_init stage_add_already_staged_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified file" > $testroot/wt/alpha
	(cd $testroot/wt && got rm beta > /dev/null)
	echo "new file" > $testroot/wt/foo
	(cd $testroot/wt && got add foo > /dev/null)

	(cd $testroot/wt && got stage alpha beta foo > $testroot/stdout)

	(cd $testroot/wt && got add beta \
		> $testroot/stdout 2> $testroot/stderr)
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "got add command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "got: realpath: beta: No such file or directory" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	for f in alpha foo; do
		(cd $testroot/wt && got add $f \
			> $testroot/stdout 2> $testroot/stderr)
		ret="$?"
		if [ "$ret" != "0" ]; then
			echo "got add command failed unexpectedly" >&2
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
	done

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_stage_rm_already_staged_file {
	local testroot=`test_init stage_rm_already_staged_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
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
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "got rm command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi
	echo "got: realpath: beta: No such file or directory" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	for f in alpha foo; do
		echo "got: $f: file is staged" > $testroot/stderr.expected
		(cd $testroot/wt && got rm $f \
			> $testroot/stdout 2> $testroot/stderr)
		ret="$?"
		if [ "$ret" == "0" ]; then
			echo "got rm command succeeded unexpectedly" >&2
			test_done "$testroot" "1"
			return 1
		fi
		cmp -s $testroot/stderr.expected $testroot/stderr
		ret="$?"
		if [ "$ret" != "0" ]; then
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
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_stage_revert {
	local testroot=`test_init stage_revert`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
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
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "revert command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "R  alpha" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified alpha" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo 'MA foo' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got revert alpha > $testroot/stdout)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "revert command failed unexpectedly" >&2
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

	echo "modified alpha" > $testroot/content.expected
	cat $testroot/wt/alpha > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got revert beta > $testroot/stdout \
		2> $testroot/stderr)
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "revert command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo "got: beta: file is staged" > $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got revert foo > $testroot/stdout)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "revert command failed unexpectedly" >&2
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "R  foo" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "new file" > $testroot/content.expected
	cat $testroot/wt/foo > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got revert foo > $testroot/stdout)
	ret="$?"
	if [ "$ret" != "0" ]; then
		echo "revert command failed unexpectedly" >&2
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

	echo "new file" > $testroot/content.expected
	cat $testroot/wt/foo > $testroot/content
	cmp -s $testroot/content.expected $testroot/content
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/content.expected $testroot/content
		test_done "$testroot" "$ret"
		return 1
	fi

	echo ' M alpha' > $testroot/stdout.expected
	echo ' D beta' >> $testroot/stdout.expected
	echo ' A foo' >> $testroot/stdout.expected
	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_stage_diff {
	local testroot=`test_init stage_diff`
	local head_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
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
	ret="$?"
	if [ "$ret" != "0" ]; then
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
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified file again" > $testroot/wt/alpha
	echo "new file changed" > $testroot/wt/foo

	(cd $testroot/wt && got diff > $testroot/stdout)

	echo "diff $head_commit $testroot/wt" > $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l alpha) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + alpha' >> $testroot/stdout.expected
	echo '--- alpha' >> $testroot/stdout.expected
	echo '+++ alpha' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-modified file' >> $testroot/stdout.expected
	echo '+modified file again' >> $testroot/stdout.expected
	echo -n 'blob - ' >> $testroot/stdout.expected
	(cd $testroot/wt && got stage -l foo) | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'file + foo' >> $testroot/stdout.expected
	echo '--- foo' >> $testroot/stdout.expected
	echo '+++ foo' >> $testroot/stdout.expected
	echo '@@ -1 +1 @@' >> $testroot/stdout.expected
	echo '-new file' >> $testroot/stdout.expected
	echo '+new file changed' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	(cd $testroot/wt && got diff -s > $testroot/stdout)

	echo "diff $head_commit $testroot/wt (staged changes)" \
		> $testroot/stdout.expected
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
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

function test_stage_histedit {
	local testroot=`test_init stage_histedit`
	local orig_commit=`git_show_head $testroot/repo`

	got checkout -c $orig_commit $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
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
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "got histedit command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	echo "got: alpha: file is staged" > $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"

}

function test_stage_rebase {
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
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified file" > $testroot/wt/alpha
	(cd $testroot/wt && got stage alpha > /dev/null)

	(cd $testroot/wt && got rebase newbranch \
		> $testroot/stdout 2> $testroot/stderr)
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "got rebase command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	echo "got: alpha: file is staged" > $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_stage_update {
	local testroot=`test_init stage_update`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo "modified file" > $testroot/wt/alpha
	(cd $testroot/wt && got stage alpha > /dev/null)

	echo "modified alpha" > $testroot/repo/alpha
	git_commit $testroot/repo -m "modified alpha"

	(cd $testroot/wt && got update > $testroot/stdout  \
		2> $testroot/stderr)
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "got update command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	echo "got: alpha: file is staged" > $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_stage_commit_non_staged {
	local testroot=`test_init stage_commit_non_staged`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
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
	ret="$?"
	if [ "$ret" == "0" ]; then
		echo "got commit command succeeded unexpectedly" >&2
		test_done "$testroot" "1"
		return 1
	fi

	echo -n > $testroot/stdout.expected
	echo "got: gamma/delta: file is not staged" > $testroot/stderr.expected

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

function test_stage_commit {
	local testroot=`test_init stage_commit`
	local first_commit=`git_show_head $testroot/repo`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
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
	ret="$?"
	if [ "$ret" != "0" ]; then
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
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got diff -r $testroot/repo $first_commit $head_commit \
		> $testroot/stdout

	echo "diff $first_commit $head_commit" \
		> $testroot/stdout.expected
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
		| grep 'beta$' | cut -d' ' -f 1 \
		>> $testroot/stdout.expected
	echo 'blob + /dev/null' >> $testroot/stdout.expected
	echo '--- beta' >> $testroot/stdout.expected
	echo '+++ /dev/null' >> $testroot/stdout.expected
	echo '@@ -1 +0,0 @@' >> $testroot/stdout.expected
	echo '-beta' >> $testroot/stdout.expected
	echo 'blob - /dev/null' >> $testroot/stdout.expected
	echo -n 'blob + ' >> $testroot/stdout.expected
	cat $testroot/blob_id_foo >> $testroot/stdout.expected
	echo '--- /dev/null' >> $testroot/stdout.expected
	echo '+++ foo' >> $testroot/stdout.expected
	echo '@@ -0,0 +1 @@' >> $testroot/stdout.expected
	echo '+new file' >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 'A  epsilon/new' > $testroot/stdout.expected
	echo 'D  epsilon/zeta' >> $testroot/stdout.expected
	echo 'M  gamma/delta' >> $testroot/stdout.expected

	(cd $testroot/wt && got status > $testroot/stdout)
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done "$testroot" "$ret"
}

run_test test_stage_basic
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
run_test test_stage_commit
