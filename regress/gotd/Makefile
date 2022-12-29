.include "../../got-version.mk"

REGRESS_TARGETS=test_repo_read test_repo_read_group \
	test_repo_read_denied_user test_repo_read_denied_group \
	test_repo_read_bad_user test_repo_read_bad_group \
	test_repo_write test_repo_write_empty test_request_bad
NOOBJ=Yes

.PHONY: ensure_root prepare_test_repo check_test_repo start_gotd

GOTD_TEST_ROOT=/tmp
GOTD_DEVUSER?=gotdev
GOTD_DEVUSER_HOME!=userinfo $(GOTD_DEVUSER) | awk '/^dir/ {print $$2}'
GOTD_TEST_REPO!?=mktemp -d "$(GOTD_TEST_ROOT)/gotd-test-repo-XXXXXXXXX"
GOTD_TEST_REPO_URL=ssh://${GOTD_DEVUSER}@127.0.0.1/test-repo

GOTD_TEST_USER?=${DOAS_USER}
.if empty(GOTD_TEST_USER)
GOTD_TEST_USER=${SUDO_USER}
.endif
.if empty(GOTD_TEST_USER)
GOTD_TEST_USER=${USER}
.endif
GOTD_TEST_USER_HOME!=userinfo $(GOTD_TEST_USER) | awk '/^dir/ {print $$2}'

# gotd.conf parameters
GOTD_USER?=got
GOTD_GROUP?=gotsh
GOTD_SOCK=${GOTD_DEVUSER_HOME}/gotd.sock

.if "${GOT_RELEASE}" == "Yes"
PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/bin
.else
PREFIX ?= ${GOTD_TEST_USER_HOME}
BINDIR ?= ${PREFIX}/bin
.endif

GOTD_START_CMD?=$(BINDIR)/gotd -vv -f $(PWD)/gotd.conf
GOTD_STOP_CMD?=$(BINDIR)/gotctl -f $(GOTD_SOCK) stop
GOTD_TRAP=trap "$(GOTD_STOP_CMD)" HUP INT QUIT PIPE TERM

GOTD_TEST_ENV=GOTD_TEST_ROOT=$(GOTD_TEST_ROOT) \
	GOTD_TEST_REPO_URL=$(GOTD_TEST_REPO_URL) \
	GOTD_TEST_REPO=$(GOTD_TEST_REPO) \
	GOTD_SOCK=$(GOTD_SOCK) \
	GOTD_DEVUSER=$(GOTD_DEVUSER) \
	HOME=$(GOTD_TEST_USER_HOME) \
	PATH=$(GOTD_TEST_USER_HOME)/bin:$(PATH)

ensure_root:
	@if [[ `id -u` -ne 0 ]]; then \
		echo gotd test suite must be started by root >&2; \
		false; \
	fi ; \
	if [[ "$(GOTD_TEST_USER)" = "root" ]]; then \
		echo GOTD_TEST_USER must be a non-root user >&2; \
		false; \
	fi

start_gotd_ro: ensure_root
	@echo 'unix_socket "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "unix_group $(GOTD_GROUP)" >> $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit ro $(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

start_gotd_ro_group: ensure_root
	@echo 'unix_socket "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "unix_group $(GOTD_GROUP)" >> $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit ro :$(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

# try a permit rule followed by a deny rule; last matched rule wins
start_gotd_ro_denied_user: ensure_root
	@echo 'unix_socket "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "unix_group $(GOTD_GROUP)" >> $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit ro $(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo '    deny $(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

# try a permit rule followed by a deny rule; last matched rule wins
start_gotd_ro_denied_group: ensure_root
	@echo 'unix_socket "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "unix_group $(GOTD_GROUP)" >> $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit ro $(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo '    deny :$(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

# $GOTD_DEVUSER should not equal $GOTD_USER
start_gotd_ro_bad_user: ensure_root
	@echo 'unix_socket "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "unix_group $(GOTD_GROUP)" >> $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit ro $(GOTD_USER)' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

# $GOTD_DEVUSER should not be in group wheel
start_gotd_ro_bad_group: ensure_root
	@echo 'unix_socket "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "unix_group $(GOTD_GROUP)" >> $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit ro :wheel' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

start_gotd_rw: ensure_root
	@echo 'unix_socket "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "unix_group $(GOTD_GROUP)" >> $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo '    permit rw $(GOTD_DEVUSER)' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

prepare_test_repo: ensure_root
	@chown ${GOTD_USER} "${GOTD_TEST_REPO}"
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./prepare_test_repo.sh'

prepare_test_repo_empty: ensure_root
	@chown ${GOTD_USER} "${GOTD_TEST_REPO}"
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./prepare_test_repo.sh 1'

test_repo_read: prepare_test_repo start_gotd_ro
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_read.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_repo_read_group: prepare_test_repo start_gotd_ro_group
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_read.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_repo_read_denied_user: prepare_test_repo start_gotd_ro_denied_user
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_read_access_denied.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_repo_read_denied_group: prepare_test_repo start_gotd_ro_denied_group
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_read_access_denied.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_repo_read_bad_user: prepare_test_repo start_gotd_ro_bad_user
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_read_access_denied.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_repo_read_bad_group: prepare_test_repo start_gotd_ro_bad_group
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_read_access_denied.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_repo_write: prepare_test_repo start_gotd_rw
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_write.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_repo_write_empty: prepare_test_repo_empty start_gotd_rw
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_write_empty.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'
	
test_request_bad: prepare_test_repo_empty start_gotd_ro
	@-$(GOTD_TRAP); su -m ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./request_bad.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null

.include <bsd.regress.mk>
