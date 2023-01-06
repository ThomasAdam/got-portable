#!/bin/sh

if [ "x$(uname)" = "xOpenBSD" ]; then
	[ -z "$AUTOMAKE_VERSION" ] && export AUTOMAKE_VERSION=1.16
	[ -z "$AUTOCONF_VERSION" ] && export AUTOCONF_VERSION=2.69
fi


die()
{
    echo "$1" >&2
    exit $2
}

autoreconf -f -i -v || die "autoreconf failed" $?
