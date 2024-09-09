.PATH:${.CURDIR}/../../gotd/
.PATH:${.CURDIR}/../../lib/

PROG =		secrets
SRCS =		secrets-parser.c error.c hash.c log.c secrets.c 

CPPFLAGS +=	-I${.CURDIR}/../../include -I${.CURDIR}/../../lib
CPPFLAGS +=	-I${.CURDIR}/../../gotd

REGRESS_TARGETS =	test_empty test_comments test_quotes test_unclosed \
			test_invalid_escape test_syntax

test_empty:
	@echo -n '$@ '
	@(./secrets /dev/null | diff -u /dev/null -) && echo ok

test_comments:
	@echo -n '$@ '
	@(./secrets ${.CURDIR}/01.conf | diff -u ${.CURDIR}/01.exp -) && echo ok

test_quotes:
	@echo -n '$@ '
	@(./secrets ${.CURDIR}/02.conf | diff -u ${.CURDIR}/02.exp -) && echo ok

test_unclosed:
	@echo -n '$@ '
	@./secrets ${.CURDIR}/03.conf 2> ${.CURDIR}/stderr || true
	@echo 'secrets: ${.CURDIR}/03.conf:1 no closing quote' > ${.CURDIR}/stderr.expected
	@echo 'secrets: failed to parse ${.CURDIR}/03.conf: configuration file syntax error' >> ${.CURDIR}/stderr.expected
	@if ! cmp -s ${.CURDIR}/stderr.expected ${.CURDIR}/stderr; then \
		diff -u ${.CURDIR}/stderr.expected ${.CURDIR}/stderr; \
	else \
		echo ok; \
	fi

test_invalid_escape:
	@echo -n '$@ '
	@./secrets ${.CURDIR}/04.conf 2> ${.CURDIR}/stderr || true
	@echo 'secrets: ${.CURDIR}/04.conf:1 unterminated escape at end of line' > ${.CURDIR}/stderr.expected
	@echo 'secrets: failed to parse ${.CURDIR}/04.conf: configuration file syntax error' >> ${.CURDIR}/stderr.expected
	@if ! cmp -s ${.CURDIR}/stderr.expected ${.CURDIR}/stderr; then \
		diff -u ${.CURDIR}/stderr.expected ${.CURDIR}/stderr; \
	else \
		echo ok; \
	fi

test_syntax:
	@echo -n '$@ '
	@./secrets ${.CURDIR}/05.conf 2> ${.CURDIR}/stderr || true
	@echo 'secrets: ${.CURDIR}/05.conf:1 unterminated escape at end of line' > ${.CURDIR}/stderr.expected
	@echo 'secrets: failed to parse ${.CURDIR}/05.conf: configuration file syntax error' >> ${.CURDIR}/stderr.expected
	@if ! cmp -s ${.CURDIR}/stderr.expected ${.CURDIR}/stderr; then \
		diff -u ${.CURDIR}/stderr.expected ${.CURDIR}/stderr; \
	else \
		echo ok; \
	fi

.include <bsd.regress.mk>
