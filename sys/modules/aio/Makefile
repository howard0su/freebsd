# $FreeBSD$

.PATH: ${.CURDIR}/../../kern

KMOD=	aio
SRCS=	vfs_aio.c opt_vfs_aio.h vnode_if.h opt_compat.h

EXPORT_SYMS= aio_init_aioinfo aio_aqueue aio_complete aio_queue

.include <bsd.kmod.mk>
