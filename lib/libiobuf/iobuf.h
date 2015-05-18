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

#ifndef __IOBUF_H__
#define	__IOBUF_H__

struct iobuf;
struct iobuf_pool;

struct iobuf_vec {
	struct iobuf *iv_buf;
	size_t	iv_offset;
	size_t	iv_len;
};

typedef struct iobuf *iobuf_t;
typedef struct iobuf_pool *iobuf_pool_t;
typedef struct iobuf_vec *iobuf_vec_t;

iobuf_pool_t iobuf_pool_create(size_t _number, size_t _size);
int	iobuf_pool_delete(iobuf_pool_t _pool);

iobuf_t	iobuf_alloc(iobuf_pool_t _pool);
iobuf_t	iobuf_ref(iobuf_t _iobuf);
int	iobuf_free(iobuf_t _iobuf);

void	*iobuf_base(iobuf_t _iobuf);

ssize_t	iobuf_read(int _fd, iobuf_vec_t _vec, int _veccnt);
ssize_t	iobuf_pread(int _fd, iobuf_vec_t _vec, int _veccnt, off_t _offset);
ssize_t	iobuf_write(int _fd, iobuf_vec_t _vec, int _veccnt);
ssize_t	iobuf_pwrite(int _fd, iobuf_vec_t _vec, int _veccnt, off_t _offset);

#endif /* !__IOBUF_H__ */
