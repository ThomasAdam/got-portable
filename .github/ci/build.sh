#!/bin/sh

[ "$CIRRUS_OS" = "darwin" ] && {
	export PATH="/usr/local/opt/bison/bin:$PATH"
	export LDFLAGS="-L/usr/local/opt/ncurses/lib -L/usr/local/opt/openssl@3/lib"
	export CPPFLAGS="-I/usr/local/opt/ncurses/include -I/usr/local/opt/openssl@3/include"
	export PKG_CONFIG_PATH="/usr/local/opt/ncurses/lib/pkgconfig"
	export PKG_CONFIG_PATH="$PKG_CONFIG_PATH:/usr/local/opt/openssl@3/lib/pkgconfig"
}

./autogen.sh || exit 1
./configure || exit 1
exec make
