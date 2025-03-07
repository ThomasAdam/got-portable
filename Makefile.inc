CPPFLAGS += -DGOT_LIBEXECDIR=${LIBEXECDIR} -DGOT_SBINDIR=${SBINDIR}
CPPFLAGS += -DGOT_VERSION=${GOT_VERSION}
#CFLAGS += -DGOT_PACK_NO_MMAP
#CFLAGS += -DGOT_NO_OBJ_CACHE
#CFLAGS += -DGOT_NO_DELTA_CACHE
#CFLAGS += -DGOT_OBJ_CACHE_DEBUG
#CFLAGS += -DGOT_DELTA_CACHE_DEBUG
#CFLAGS += -DGOT_DIFF_NO_MMAP

.if "${GOT_RELEASE}" == "Yes"
PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/bin
SBINDIR ?= ${PREFIX}/sbin
LIBEXECDIR ?= ${PREFIX}/libexec
MANDIR ?= ${PREFIX}/man/man
.else
CFLAGS += -Werror -Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS += -Wwrite-strings -Wunused-variable
PREFIX ?= ${HOME}
BINDIR ?= ${PREFIX}/bin
LIBEXECDIR ?= ${BINDIR}
SBINDIR ?= ${BINDIR}

BINOWN ?= ${USER}
.if !defined(BINGRP)
BINGRP != id -g -n
.endif

.if defined(PROFILE)
CPPFLAGS += -DPROFILE
DEBUG = -O0 -pg -g -static
.else
DEBUG = -O0 -g
.endif

.endif
