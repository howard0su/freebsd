#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD$

.include <src.opts.mk>

.PATH: ${.CURDIR}/../ktrace

PROG=		kdump
SRCS=		kdump.c subr.c
CFLAGS+=	-I${.CURDIR}/../ktrace #-I${.CURDIR}/../...

LIBADD=		sysdecode
.if ${MK_CASPER} != "no"
LIBADD+=	capsicum
CFLAGS+=-DHAVE_LIBCAPSICUM
.endif

NO_WERROR?=	YES

.include <bsd.prog.mk>
