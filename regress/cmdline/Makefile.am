REGRESS_TARGETS=checkout update status log add rm diff blame branch tag \
	ref commit revert cherrypick backout rebase import histedit \
	integrate stage unstage cat clone fetch tree pack cleanup
NOOBJ=Yes

GOT_TEST_ROOT=/tmp

all: $(REGRESS_TARGETS)

checkout:
	./checkout.sh -q -r "$(GOT_TEST_ROOT)"

update:
	./update.sh -q -r "$(GOT_TEST_ROOT)"

status:
	./status.sh -q -r "$(GOT_TEST_ROOT)"

log:
	./log.sh -q -r "$(GOT_TEST_ROOT)"

add:
	./add.sh -q -r "$(GOT_TEST_ROOT)"

rm:
	./rm.sh -q -r "$(GOT_TEST_ROOT)"

diff:
	./diff.sh -q -r "$(GOT_TEST_ROOT)"

blame:
	./blame.sh -q -r "$(GOT_TEST_ROOT)"

branch:
	./branch.sh -q -r "$(GOT_TEST_ROOT)"

tag:
	./tag.sh -q -r "$(GOT_TEST_ROOT)"

ref:
	./ref.sh -q -r "$(GOT_TEST_ROOT)"

commit:
	./commit.sh -q -r "$(GOT_TEST_ROOT)"

revert:
	./revert.sh -q -r "$(GOT_TEST_ROOT)"

cherrypick:
	./cherrypick.sh -q -r "$(GOT_TEST_ROOT)"

backout:
	./backout.sh -q -r "$(GOT_TEST_ROOT)"

rebase:
	./rebase.sh -q -r "$(GOT_TEST_ROOT)"

import:
	./import.sh -q -r "$(GOT_TEST_ROOT)"

histedit:
	./histedit.sh -q -r "$(GOT_TEST_ROOT)"

integrate:
	./integrate.sh -q -r "$(GOT_TEST_ROOT)"

stage:
	./stage.sh -q -r "$(GOT_TEST_ROOT)"

unstage:
	./unstage.sh -q -r "$(GOT_TEST_ROOT)"

cat:
	./cat.sh -q -r "$(GOT_TEST_ROOT)"

clone:
	./clone.sh -q -r "$(GOT_TEST_ROOT)"

fetch:
	./fetch.sh -q -r "$(GOT_TEST_ROOT)"

send:
	./send.sh -q -r "$(GOT_TEST_ROOT)"

tree:
	./tree.sh -q -r "$(GOT_TEST_ROOT)"

pack:
	./pack.sh -q -r "$(GOT_TEST_ROOT)"

cleanup:
	./cleanup.sh -q -r "$(GOT_TEST_ROOT)"
