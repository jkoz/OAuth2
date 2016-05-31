include config.mk

PROG = oauth2
SRC = oauth2.c
OBJ = ${SRC:.c=.o}

all: ${PROG}

debug: CFLAGS += -DDEBUG -g
debug: ${PROG}

.c.o:
	${CC} -c ${CFLAGS} $<

${OBJ}: config.h config.mk

config.h:
	cp config.def.h $@

${PROG}: ${OBJ}
	${CC} -o $@ ${OBJ} ${LDFLAGS}

clean:
	rm -f ${PROG} ${OBJ} ${PROG}-${VERSION}.tar.gz

install: all
	cp -f ${PROG} ${DESTDIR}${PREFIX}/bin

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/${PROG}
