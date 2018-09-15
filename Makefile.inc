GOT_LIBEXECDIR = ${HOME}/bin

CFLAGS += -Werror -Wall -Wstrict-prototypes -Wunused-variable
#CFLAGS += -DGOT_PACK_NO_MMAP
#CFLAGS += -DGOT_NO_OBJ_CACHE
#CFLAGS += -DGOT_OBJ_CACHE_DEBUG

.if defined(PROFILE)
CC = gcc
CPPFLAGS += -DPROFILE
DEBUG = -O0 -pg
.else
DEBUG = -O0 -g
.endif
