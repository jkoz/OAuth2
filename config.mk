# oauth2 version
VERSION = 1.0

# paths
PREFIX = /usr/local
MANPREFIX = ${PREFIX}/share/man

# includes and libs
INCS = -I /usr/include/curl -I/usr/include/yajl
LIBS = -lcurl -lyajl

# flags
CPPFLAGS = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_POSIX_C_SOURCE=2 -DVERSION=\"${VERSION}\"
CFLAGS   = -std=c99 -pedantic -Wall -Wno-deprecated-declarations -Os ${INCS} ${CPPFLAGS}
LDFLAGS  = -s ${LIBS}

# debug
DEBUG ?= 1
ifeq (${DEBUG}, 1)
	CFLAGS += -g3 -DDEBUG
else
	CFLAGS += -DNDEBUG
endif

# compiler and linker
CC = gcc
