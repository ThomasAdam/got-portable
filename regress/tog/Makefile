REGRESS_TARGETS=log
NOOBJ=Yes

GOT_TEST_ROOT=/tmp

log:
	./log.sh -q -r "$(GOT_TEST_ROOT)"
cleanup:
	./cleanup.sh -q -r "$(GOT_TEST_ROOT)"


.include <bsd.regress.mk>
