#!/bin/sh
#
# Copyright (c) 2025 Stefan Sperling <stsp@openbsd.org>
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

test_tree=`mktemp -d "${GOTD_TEST_ROOT}/gotd-test-tree-XXXXXXXXXX"`
trap "rm -r $test_tree" HUP INT QUIT PIPE TERM

got checkout -q "${GOTD_TEST_REPO}" "$test_tree" > /dev/null

dd if=/dev/random of="$test_tree/large_file1" count=32768 status=none
(cd "$test_tree" && got add "$test_tree/large_file1" > /dev/null)
for i in 2 3; do
       cp "$test_tree/large_file1" "$test_tree/large_file$i"
       dd if=/dev/random of="$test_tree/large_file$i" seek=32768 count=64 \
              status=none
       (cd "$test_tree" && got add "$test_tree/large_file$i" > /dev/null)
done

(cd "$test_tree" && got commit -m "add large objects" "$test_tree" > /dev/null)

rm -r "$test_tree"
