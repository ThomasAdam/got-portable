#!/bin/sh
#
# Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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

make_repo()
{
	local repo_path="$1"
	local no_tree="$2"

	gotadmin init "${repo_path}"

	if [ -n "$no_tree" ]; then
		return
	fi

	test_tree=`mktemp -d "${GOTD_TEST_ROOT}/gotd-test-tree-XXXXXXXXXX"`
	make_test_tree "$test_tree"
	got import -m "import the test tree" -r "${GOTD_TEST_REPO}" "$test_tree" \
		> /dev/null
	rm -r "$test_tree" # TODO: trap
}


if [ -e "${GOTD_TEST_REPO}" ]; then
	rm -rf "${GOTD_TEST_REPO}"
fi

make_repo "${GOTD_TEST_REPO}" "$1"
