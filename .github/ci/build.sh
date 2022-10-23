#!/bin/sh

./autogen.sh || exit 1
./configure --enable-gotd || exit 1
exec make
