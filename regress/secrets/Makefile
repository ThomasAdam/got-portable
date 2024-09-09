.PATH:${.CURDIR}/../../gotd/
.PATH:${.CURDIR}/../../lib/

PROG =		secrets
SRCS =		secrets-parser.c error.c hash.c log.c secrets.c 

CPPFLAGS +=	-I${.CURDIR}/../../include -I${.CURDIR}/../../lib
CPPFLAGS +=	-I${.CURDIR}/../../gotd

REGRESS_TARGETS =	empty comments quotes unclosed invalid-escape syntax

empty:
	./secrets /dev/null | diff -u /dev/null -

comments:
	./secrets ${.CURDIR}/01.conf | diff -u ${.CURDIR}/01.exp -

quotes:
	./secrets ${.CURDIR}/02.conf | diff -u ${.CURDIR}/02.exp -

unclosed:
	! ./secrets ${.CURDIR}/03.conf
	@echo "expected failure; it's OK"

invalid-escape:
	! ./secrets ${.CURDIR}/04.conf
	@echo "expected failure; it's OK"

syntax:
	! ./secrets ${.CURDIR}/05.conf
	@echo "expected failure; it's OK"

.include <bsd.regress.mk>
