#!/bin/sh

if [ "$CIRRUS_OS" = "linux" ]; then
	apt-get update -qq && \
	apt-get -y install bison autoconf \
				autotools-dev \
				libncurses5-dev \
				pkg-config \
				build-essential \
				libmd-dev \
				libssl-dev \
				libbsd-dev \
				uuid-dev \
				zlib1g-dev \
				git \
				athena-jot \
				ed
fi

if [ "$CIRRUS_OS" = "freebsd" ]; then
	pkg install -y \
		automake \
		pkgconf \
		git \
		coreutils
fi

if [ "$CIRRUS_OS" = "darwin" ]; then
	brew install autoconf \
		automake \
		pkg-config \
		ncurses \
		ossp-uuid \
		git
fi
