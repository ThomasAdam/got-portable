#!/bin/sh
# requires zlib-flate which is part of the qpdf package: pkg_add qpdf

if [ "$1" != "" ]; then
	zlib-flate -uncompress < "$1"
else
	zlib-flate -uncompress
fi
