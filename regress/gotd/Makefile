REGRESS_TARGETS=test_repo_read test_repo_write
NOOBJ=Yes

.PHONY: ensure_root prepare_test_repo check_test_repo start_gotd

GOTD_TEST_ROOT=/tmp
GOTD_DEVUSER?=gotdev
GOTD_DEVUSER_HOME!=userinfo $(GOTD_DEVUSER) | awk '/^dir/ {print $$2}'
GOTD_TEST_REPO!?=mktemp -d "$(GOTD_TEST_ROOT)/gotd-test-repo-XXXXXXXXX"
GOTD_TEST_REPO_URL=ssh://${GOTD_DEVUSER}@127.0.0.1/test-repo

GOTD_TEST_USER?=${LOGNAME}
GOTD_TEST_USER_HOME!=userinfo $(GOTD_TEST_USER) | awk '/^dir/ {print $$2}'

# gotd.conf parameters
GOTD_USER?=got
GOTD_GROUP?=gotsh
GOTD_SOCK=${GOTD_DEVUSER_HOME}/gotd.sock

GOTD_START_CMD=../../gotd/obj/gotd -vv -f $(PWD)/gotd.conf
GOTD_STOP_CMD=../../gotctl/obj/gotctl -f $(GOTD_SOCK) stop
GOTD_TRAP=trap "$(GOTD_STOP_CMD)" HUP INT QUIT PIPE TERM

GOTD_TEST_ENV=GOTD_TEST_ROOT=$(GOTD_TEST_ROOT) \
	GOTD_TEST_REPO_URL=$(GOTD_TEST_REPO_URL) \
	GOTD_TEST_REPO=$(GOTD_TEST_REPO) \
	GOTD_SOCK=$(GOTD_SOCK) \
	HOME=$(GOTD_TEST_USER_HOME) \
	PATH=$(GOTD_TEST_USER_HOME)/bin:$(PATH)

ensure_root:
	@if [[ `id -u` -ne 0 ]]; then \
		echo gotd test suite must be run by root >&2; \
		false; \
	fi

start_gotd: ensure_root
	@echo 'unix_socket "$(GOTD_SOCK)"' > $(PWD)/gotd.conf
	@echo "unix_group $(GOTD_GROUP)" >> $(PWD)/gotd.conf
	@echo "user $(GOTD_USER)" >> $(PWD)/gotd.conf
	@echo 'repository "test-repo" {' >> $(PWD)/gotd.conf
	@echo '    path "$(GOTD_TEST_REPO)"' >> $(PWD)/gotd.conf
	@echo "}" >> $(PWD)/gotd.conf
	@$(GOTD_TRAP); $(GOTD_START_CMD)
	@$(GOTD_TRAP); sleep .5

prepare_test_repo: ensure_root
	@chown ${GOTD_USER} "${GOTD_TEST_REPO}"
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./prepare_test_repo.sh'

test_repo_read: prepare_test_repo start_gotd
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_read.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'

test_repo_write: prepare_test_repo start_gotd
	@-$(GOTD_TRAP); su ${GOTD_TEST_USER} -c \
		'env $(GOTD_TEST_ENV) sh ./repo_write.sh'
	@$(GOTD_STOP_CMD) 2>/dev/null
	@su -m ${GOTD_USER} -c 'env $(GOTD_TEST_ENV) sh ./check_test_repo.sh'
	
.include <bsd.regress.mk>
