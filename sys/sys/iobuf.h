/*-
 * Copyright (c) 2015 Chelsio Communications, Inc.
 * All rights reserved.
 * Written by: John Baldwin <jhb@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef __SYS_IOBUF_H__
#define	__SYS_IOBUF_H__

#ifdef _KERNEL
struct iobuf {
	STAILQ_ENTRY(iobuf) io_link;
	struct iobuf_pool *io_pool;
	int	io_id;
};
#endif

#if defined(_KERNEL) || defined(_WANT_FILE)
struct iobuf_pool {
	size_t	ip_size;
	size_t	ip_nbufs;
	size_t	ip_bufsize;
	size_t	ip_nfreebuf;
	vm_object_t ip_object;
	STAILQ_HEAD(, iobuf) ip_freebufs;

	/*
	 * Values maintained solely to make this a better-behaved file
	 * descriptor for fstat() to run on.
	 */
	uid_t	ip_uid;
	gid_t	ip_gid;
	struct timespec	ip_atime;
	struct timespec	ip_mtime;
	struct timespec	ip_ctime;
	struct timespec	ip_birthtime;
	ino_t	ip_ino;

#if 0
	struct mtx ip_lock;
	int ip_refs;
#endif
};
#endif

#ifndef _KERNEL

__BEGIN_DECLS
#if __BSD_VISIBLE
int	iobuf_pool_create(size_t, size_t);
#endif
__END_DECLS

#endif /* !_KERNEL */

#endif /* !__IOBUF_INTERNAL_H__ */
