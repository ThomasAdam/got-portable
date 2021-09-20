#!/bin/sh

die()
{
    echo "$@" >&2
    exit $2
}

autoreconf -f -i -v || die "autoreconf failed" $?
