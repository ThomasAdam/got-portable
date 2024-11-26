.PATH:${.CURDIR}/../../lib

REGRESS_TARGETS=test_gotwebd

PROG = gotwebd_test
SRCS = gotwebd_test.c error.c hash.c pollfd.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib

NOMAN = yes

.PHONY: ensure_root prepare_test_env prepare_test_repo start_gotwebd

GOTWEBD_TEST_TMPDIR=/tmp
GOTWEBD_TEST_ROOT?!!=mktemp -d "${GOTWEBD_TEST_TMPDIR}/gotwebd-test-XXXXXXXXXX"
GOTWEBD_TEST_CHROOT=${GOTWEBD_TEST_ROOT}/var/www
GOTWEBD_TEST_CONF=${GOTWEBD_TEST_ROOT}/gotwebd.conf
GOTWEBD_TEST_SOCK=${GOTWEBD_TEST_CHROOT}/gotweb.sock
GOTWEBD_TEST_FCGI=${.OBJDIR}/${PROG}

GOTWEBD_TEST_USER?=${DOAS_USER}
.if empty(GOTWEBD_TEST_USER)
GOTWEBD_TEST_USER=${SUDO_USER}
.endif
.if empty(GOTWEBD_TEST_USER)
GOTWEBD_TEST_USER=${USER}
.endif

GOTWEBD_TEST_USER_HOME!=getent passwd ${GOTWEBD_TEST_USER} | cut -d: -f6

PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/sbin

GOTWEBD_START_CMD?=${BINDIR}/gotwebd -vvf ${GOTWEBD_TEST_CONF}
GOTWEBD_STOP_CMD?=pkill -TERM -fx '${GOTWEBD_START_CMD}'
GOTWEBD_TRAP=trap "${GOTWEBD_STOP_CMD}" HUP INT QUIT PIPE TERM

GOTWEBD_TEST_ENV=GOTWEBD_TEST_SOCK=${GOTWEBD_TEST_SOCK} \
	GOTWEBD_TEST_CHROOT=${GOTWEBD_TEST_CHROOT} \
	GOTWEBD_TEST_ROOT=${GOTWEBD_TEST_ROOT} \
	GOTWEBD_TEST_CONF=${GOTWEBD_TEST_CONF} \
	GOTWEBD_TEST_USER=${GOTWEBD_TEST_USER} \
	GOTWEBD_TEST_FCGI=${GOTWEBD_TEST_FCGI} \
	PATH=$(GOTWEBD_TEST_USER_HOME)/bin:${PATH} \
	HOME=$(GOTWEBD_TEST_USER_HOME) \
	GOTWEBD_TEST_DATA_DIR=${.CURDIR}

ensure_root:
	@if [[ `id -u` -ne 0 ]]; then \
		echo gotwebd test suite must be started by root >&2; \
		false; \
	fi ; \
	if [[ "${GOTWEBD_TEST_USER}" = "root" ]]; then \
		echo GOTWEBD_TEST_USER must be a non-root user >&2; \
		false; \
	fi

gotwebd_libexec:
	@su -m ${GOTWEBD_TEST_USER} -c \
	    '${MAKE} -C ${.CURDIR}/../../gotwebd/libexec' >/dev/null 2>&1

prepare_test_env: gotwebd_libexec ensure_root
	@mkdir -p "${GOTWEBD_TEST_CHROOT}"
	@DESTDIR=${GOTWEBD_TEST_ROOT} \
	    ${MAKE} -C ${.CURDIR}/../../gotwebd/libexec install >/dev/null 2>&1
	@chown ${GOTWEBD_TEST_USER} "${GOTWEBD_TEST_ROOT}" \
	    "${GOTWEBD_TEST_CHROOT}"

prepare_test_repo: prepare_test_env
	@su -m ${GOTWEBD_TEST_USER} -c 'env ${GOTWEBD_TEST_ENV} \
	    sh ${.CURDIR}/prepare_test_repo.sh "${GOTWEBD_TEST_CHROOT}"'

start_gotwebd: prepare_test_repo gotwebd_test
	@echo 'user "${GOTWEBD_TEST_USER}"' > ${GOTWEBD_TEST_CONF}
	@echo 'chroot "${GOTWEBD_TEST_CHROOT}"' >> ${GOTWEBD_TEST_CONF}
	@echo 'listen on socket "${GOTWEBD_TEST_SOCK}"' >> ${GOTWEBD_TEST_CONF}
	@echo 'server "localhost" {' >> ${GOTWEBD_TEST_CONF}
	@echo '    show_repo_owner off' >> ${GOTWEBD_TEST_CONF}
	@echo '}' >> ${GOTWEBD_TEST_CONF}
	@${GOTWEBD_TRAP}; ${GOTWEBD_START_CMD}
	@${GOTWEBD_TRAP}; sleep .5

test_gotwebd: start_gotwebd
	@-$(GOTWEBD_TRAP); su -m ${GOTWEBD_TEST_USER} -c \
		'env $(GOTWEBD_TEST_ENV) sh ${.CURDIR}/test_gotwebd.sh'
	@${GOTWEBD_STOP_CMD} 2>/dev/null

.include <bsd.regress.mk>
