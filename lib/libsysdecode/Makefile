# $FreeBSD$

.include <src.opts.mk>

LIB=	sysdecode

SRCS=	ioctl.c utrace.c
INCS=	sysdecode.h

MAN+=	sysdecode.3 \
	sysdecode_utrace.3

#MAN+=	sysdecode_ioctlname.3

CLEANFILES= ioctl.c

.if defined(COMPAT_32BIT)
CPP+=	-m32
.endif

.if ${MK_PF} != "no"
CFLAGS+=-DPF
.endif

ioctl.c: mkioctls
	env MACHINE=${MACHINE} CPP="${CPP}" \
		/bin/sh ${.CURDIR}/mkioctls ${DESTDIR}${INCLUDEDIR} > ${.TARGET}

beforedepend: ioctl.c

.include <bsd.lib.mk>
