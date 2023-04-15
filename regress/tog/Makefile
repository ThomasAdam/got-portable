REGRESS_TARGETS=log diff
NOOBJ=Yes

GOT_TEST_ROOT=/tmp

log:
	./log.sh -q -r "$(GOT_TEST_ROOT)"

diff:
	./diff.sh -q -r "$(GOT_TEST_ROOT)"

.include <bsd.regress.mk>
