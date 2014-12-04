#	$ANA: Makefile,v 1.1.1.1 1996/09/25 21:12:57 wollman Exp $
# $FreeBSD$

PROG=	pciconf
SRCS=	pciconf.c cap.c err.c slot.c
.if ${MACHINE_ARCH} == "amd64" || ${MACHINE_ARCH} == "i386"
SRCS+=	bios.c
.endif
MAN=	pciconf.8

WARNS?=	3

LDADD=	-lutil
DPADD=	${LIBUTIL}

.include <bsd.prog.mk>
