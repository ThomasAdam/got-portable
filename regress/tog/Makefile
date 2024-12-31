REGRESS_TARGETS=log diff blame tree ref
NOOBJ=Yes

GOT_TEST_ROOT=/tmp

log:
	./log.sh -q -r "$(GOT_TEST_ROOT)"

diff:
	./diff.sh -q -r "$(GOT_TEST_ROOT)"

blame:
	./blame.sh -q -r "$(GOT_TEST_ROOT)"

tree:
	./tree.sh -q -r "$(GOT_TEST_ROOT)"

ref:
	./ref.sh -q -r "$(GOT_TEST_ROOT)"

.include <bsd.regress.mk>
