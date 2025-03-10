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

. ../cmdline/common.sh
. ./common.sh

test_user_add() {
	local testroot=`test_init user_add 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
user deleteme {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
EOF
	(cd ${testroot}/wt && got commit \
		-m "create user ${GOTSYSD_DEV_USER}" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	# Ensure that the GOTSYSD_DEV_USER account does not exist yet.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} userinfo ${GOTSYSD_DEV_USER} \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 1 ]; then
		echo "user ${GOTSYSD_DEV_USER} already exists" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "userinfo: can't find user \`${GOTSYSD_DEV_USER}'" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure that the GOTSYSD_DEV_USER login group does not exist yet.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} groupinfo ${GOTSYSD_DEV_USER} \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 1 ]; then
		echo "group ${GOTSYSD_DEV_USER} already exists" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "groupinfo: can't find group \`${GOTSYSD_DEV_USER}'" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Until gotd can do so we have to trigger reconfiguration manually.
	ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} gotsys apply

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The GOTSYSD_DEV_USER account should now exist.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} userinfo ${GOTSYSD_DEV_USER} \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "userinfo ${GOTSYSD_DEV_USER} failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
login	${GOTSYSD_DEV_USER}
passwd	*
uid	5000
groups	${GOTSYSD_DEV_USER}
change	NEVER
class	
gecos	gotsys user account
dir	/home/${GOTSYSD_DEV_USER}
shell	/usr/local/bin/gotsh
expire	NEVER
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# GOTSYSD_DEV_USER should be present in /etc/passwd.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} grep ${GOTSYSD_DEV_USER} /etc/passwd \
		> $testroot/stdout

	cat > $testroot/stdout.expected <<EOF
${GOTSYSD_DEV_USER}:*:5000:5000:gotsys user account:/home/${GOTSYSD_DEV_USER}:/usr/local/bin/gotsh
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The user's login group should now exist.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} groupinfo ${GOTSYSD_DEV_USER} \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "groupinfo ${GOTSYSD_DEV_USER} failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
name	${GOTSYSD_DEV_USER}
passwd	*
gid	5000
members	
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The user should have a home directory and ~/.ssh.
	# TODO: stat ~ and ~/.ssh, then verify owership and permissions.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} ls /home/${GOTSYSD_DEV_USER} \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "ls /home/${GOTSYSD_DEV_USER} failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
.ssh
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The user should have an ssh key installed.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		${GOTSYSD_DEV_USER}@${VMIP} true \
			> $testroot/stdout 2>$testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "ssh ${GOTSYSD_DEV_USER}@${VMIP}succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stderr.expected <<EOF
usage: gotsh -c 'git-receive-pack|git-upload-pack repository-path'
EOF
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	# The "deleteme" user should be present in /etc/passwd.
	# A later test will remove it from gotsys.conf.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} grep ^deleteme /etc/passwd \
		> $testroot/stdout

	cat > $testroot/stdout.expected <<EOF
deleteme:*:5001:5001:gotsys user account:/home/deleteme:/usr/local/bin/gotsh
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The deleteme user should have an ssh key installed as well.
	ssh -q -i ${GOTSYSD_SSH_KEY} deleteme@${VMIP} true \
			> $testroot/stdout 2>$testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "ssh deleteme@${VMIP}succeeded unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stderr.expected <<EOF
usage: gotsh -c 'git-receive-pack|git-upload-pack repository-path'
EOF
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi
	test_done "$testroot" "$ret"
}

test_user_mod() {
	local testroot=`test_init user_mod 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD}1234 | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
user deleteme {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
EOF
	(cd ${testroot}/wt && got commit \
		-m "change password of ${GOTSYSD_DEV_USER}" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} grep ${GOTSYSD_DEV_USER} /etc/master.passwd \
		> $testroot/master.passwd.before
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "could not find ${GOTSYSD_DEV_USER} in master.passwd" >&2
		test_done "$testroot" 1
		return 1
	fi

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Until gotd can do so we have to trigger reconfiguration manually.
	ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} gotsys apply

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} grep ${GOTSYSD_DEV_USER} /etc/master.passwd \
		> $testroot/master.passwd.after
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "could not find ${GOTSYSD_DEV_USER} in master.passwd" >&2
		test_done "$testroot" 1
		return 1
	fi

	cmp -s $testroot/master.passwd.before $testroot/master.passwd.after
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "${GOTSYSD_DEV_USER}'s line in master.passwd is unchanged"
		test_done "$testroot" "1"
		return 1
	fi

	test_done "$testroot" "0"
}

test_user_del() {
	local testroot=`test_init user_del 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD}1234 | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
EOF
	(cd ${testroot}/wt && got commit \
		-m "remove the deleteme user from gotsys.conf" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} grep ${GOTSYSD_DEV_USER} /etc/master.passwd \
		> $testroot/master.passwd.before
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "could not find ${GOTSYSD_DEV_USER} in master.passwd" >&2
		test_done "$testroot" 1
		return 1
	fi

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Until gotd can do so we have to trigger reconfiguration manually.
	ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} gotsys apply

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} grep deleteme /etc/master.passwd \
		> $testroot/master.passwd.after
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "could not find deleteme in master.passwd" >&2
		test_done "$testroot" 1
		return 1
	fi

	cmp -s $testroot/master.passwd.before $testroot/master.passwd.after
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "${GOTSYSD_DEV_USER}'s line in master.passwd is unchanged"
		test_done "$testroot" "1"
		return 1
	fi

	# The deleteme account should still exist because we oo not
	# allow UIDs to be recycled.
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} userinfo deleteme \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "userinfo deleteme failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
login	deleteme
passwd	*
uid	5001
groups	deleteme
change	NEVER
class	
gecos	gotsys user account
dir	/home/deleteme
shell	/usr/local/bin/gotsh
expire	NEVER
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The deleteme account's password should be locked.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} grep ^deleteme /etc/master.passwd | cut -d: -f2 \
		> $testroot/stdout
	cat > $testroot/stdout.expected <<EOF
*************
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# There should be no authorized keys for this user anymore.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} cat /home/deleteme/.ssh/authorized_keys \
		> $testroot/stdout 2> $testroot/stderr

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	cat > $testroot/stderr.expected <<EOF
cat: /home/deleteme/.ssh/authorized_keys: No such file or directory
EOF
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "0"
}

test_group_add() {
	local testroot=`test_init group_add 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
group developers
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
	group developers
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
EOF
	(cd ${testroot}/wt && got commit \
		-m "create user ${GOTSYSD_DEV_USER}" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	# Ensure that the developers group does not exist yet.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} groupinfo developers \
		2> $testroot/stderr
	ret=$?
	if [ $ret -ne 1 ]; then
		echo "user already exists" >&2
		test_done "$testroot" 1
		return 1
	fi

	echo "groupinfo: can't find group \`developers'" \
		> $testroot/stderr.expected
	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done "$testroot" "$ret"
		return 1
	fi

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Until gotd can do so we have to trigger reconfiguration manually.
	ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} gotsys apply

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The developers group should now exist.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} groupinfo developers > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "groupinfo developers failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
name	developers
passwd	*
gid	5002
members	${GOTSYSD_DEV_USER} 
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The user account should now be a developers group member.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} userinfo ${GOTSYSD_DEV_USER} \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "userinfo ${GOTSYSD_DEV_USER} failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
login	${GOTSYSD_DEV_USER}
passwd	*
uid	5000
groups	${GOTSYSD_DEV_USER} developers
change	NEVER
class	
gecos	gotsys user account
dir	/home/${GOTSYSD_DEV_USER}
shell	/usr/local/bin/gotsh
expire	NEVER
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure that the slackers group now exists.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} groupinfo slackers > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "groupinfo slackers failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
name	slackers
passwd	*
gid	5003
members	
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_group_del() {
	local testroot=`test_init group_del 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	crypted_vm_pw=`echo ${GOTSYSD_VM_PASSWORD} | encrypt | tr -d '\n'`
	crypted_pw=`echo ${GOTSYSD_DEV_PASSWORD} | encrypt | tr -d '\n'`
	sshkey=`cat ${GOTSYSD_SSH_PUBKEY}`
	cat > ${testroot}/wt/gotsys.conf <<EOF
group slackers

user ${GOTSYSD_TEST_USER} {
	password "${crypted_vm_pw}" 
	authorized key ${sshkey}
}
user ${GOTSYSD_DEV_USER} {
	password "${crypted_pw}" 
	authorized key ${sshkey}
}
repository gotsys.git {
	permit rw ${GOTSYSD_TEST_USER}
	permit rw ${GOTSYSD_DEV_USER}
}
EOF
	(cd ${testroot}/wt && got commit \
		-m "remove the developers group" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	# Ensure that the developers group exists.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} groupinfo developers > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "groupinfo developers failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
name	developers
passwd	*
gid	5002
members	${GOTSYSD_DEV_USER} 
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Until gotd can do so we have to trigger reconfiguration manually.
	ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} gotsys apply

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The developers group should still exist because we do not
	# recycle GIDs. But the group should have no members.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} groupinfo developers > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "groupinfo developers failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
name	developers
passwd	*
gid	5002
members	
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The user account should no longer be a developers group member.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} userinfo ${GOTSYSD_DEV_USER} \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "userinfo ${GOTSYSD_DEV_USER} failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
login	${GOTSYSD_DEV_USER}
passwd	*
uid	5000
groups	${GOTSYSD_DEV_USER}
change	NEVER
class	
gecos	gotsys user account
dir	/home/${GOTSYSD_DEV_USER}
shell	/usr/local/bin/gotsh
expire	NEVER
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# Ensure that the slackers group still exists.
	ssh -q -i ${GOTSYSD_SSH_KEY} \
		root@${VMIP} groupinfo slackers > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "groupinfo slackers failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
name	slackers
passwd	*
gid	5003
members	
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_repo_create() {
	local testroot=`test_init repo_create 1`

	got checkout -q $testroot/${GOTSYS_REPO} $testroot/wt >/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got checkout failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat >> ${testroot}/wt/gotsys.conf <<EOF
repository "foo" {
	permit rw ${GOTSYSD_DEV_USER}
}
EOF
	(cd ${testroot}/wt && got commit -m "create repository foo" >/dev/null)
	local commit_id=`git_show_head $testroot/${GOTSYS_REPO}`

	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/${GOTSYS_REPO}
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	# Until gotd can do so we have to trigger reconfiguration manually.
	ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} gotsys apply

	# Wait for gotsysd to apply the new configuration.
	echo "$commit_id" > $testroot/stdout.expected
	for i in 1 2 3 4 5; do
		sleep 1
		ssh -i ${GOTSYSD_SSH_KEY} root@${VMIP} \
			cat /var/db/gotsysd/commit > $testroot/stdout
		if cmp -s $testroot/stdout.expected $testroot/stdout; then
			break;
		fi
	done
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "gotsysd failed to apply configuration" >&2
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The new repository should now exist.
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} ls /git \
		> $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "ls /git failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
foo.git
gotsys.git
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# The repositories should have 700 permissions and be owned by _gotd.
	ssh -q -i ${GOTSYSD_SSH_KEY} root@${VMIP} ls -l /git | \
		grep -v ^total | awk '{print $1" "$3}' > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "ls /git failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	cat > $testroot/stdout.expected <<EOF
drwx------ _gotd
drwx------ _gotd
EOF
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done "$testroot" "$ret"
		return 1
	fi

	# We should be able to import data into the newly created repository.
	got init $testroot/foo.git
	mkdir $testroot/foo
	echo alpha > $testroot/foo/alpha
	got import -m init -r $testroot/foo.git $testroot/foo >/dev/null

	cat > $testroot/foo.git/got.conf <<EOF
remote "origin" {
	server ${GOTSYSD_DEV_USER}@${VMIP}
	protocol ssh
	repository "foo.git"
	branch "main"
}
EOF
	got send -q -i ${GOTSYSD_SSH_KEY} -r ${testroot}/foo.git
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "got send failed unexpectedly" >&2
		test_done "$testroot" 1
		return 1
	fi

	test_done "$testroot" "$ret"
}

test_parseargs "$@"
run_test test_user_add
run_test test_user_mod
run_test test_user_del
run_test test_group_add
run_test test_group_del
run_test test_repo_create
