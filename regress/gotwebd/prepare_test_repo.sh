#!/bin/sh
#
# Copyright (c) 2024 Mark Jamsek <mark@jamsek.dev>
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

. ${GOTWEBD_TEST_DATA_DIR}/common.sh

make_repo()
{
	local chroot="$1"
	local no_tree="$2"
	local repo_path="${chroot}/got/public/repo.git"

	if [ -e "${chroot}/got" ]; then
		rm -rf "${chroot}/got"
	fi

	mkdir -p "${chroot}/got/public"
	if [ $? -ne 0 ]; then
		echo "failed to make gotweb public repositories tree"
		return 1
	fi

	gotadmin init -A "$GOT_TEST_ALGO" "${repo_path}"

	if [ -n "$no_tree" ]; then
		return
	fi

	test_tree=$(mktemp -d "${chroot}/gotwebd-test-tree-XXXXXXXXXX")
	make_test_tree "$test_tree"

	got import -m "import the test tree" -r "${repo_path}" "$test_tree" \
	    > /dev/null
	if [ $? -ne 0 ]; then
		echo "failed to import test tree"
		return 1
	fi

	rm -r "$test_tree" # TODO: trap
}

make_repo "$@"
