# $OpenBSD$

.include <bsd.own.mk>
CFLAGS+= -Wall -Wundef -Wno-unused
.if ${COMPILER_VERSION:L} == "gcc4"
CFLAGS+= -Werror
.endif
CFLAGS+= -DLIBRESSL_INTERNAL
CFLAGS+= -I${.CURDIR} -I{.CURDIR}/..

SRCS=   tls13_both.c

all:	tls13_both.o pool.o

.PATH:	${.CURDIR}

.include <bsd.prog.mk>
.include <bsd.subdir.mk>
