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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/mman.h>
#include <iobuf.h>
#include <stdlib.h>

#include "iobuf_internal.h"

iobuf_pool_t
iobuf_pool_create(size_t number, size_t size)
{
	iobuf_pool_t pool;
	void *mapping;
	size_t total;
	int fd, save_errno;

	total = number * size;
	if (total == 0) {
		errno = EINVAL;
		return (NULL);
	}
	if (total / size != number) {
		errno = EINVAL;
		return (NULL);
	}
	if (size % getpagesize != 0) {
		errno = EINVAL;
		return (NULL);
	}		
	fd = shm_open(SHM_ANON, O_RDWR, 0666);
	if (fd == -1)
		return (NULL);
	if (ftruncate(fd, total) == -1) {
		save_errno = errno;
		close(fd);
		errno = save_errno;
		return (NULL);
	}
	mapping = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (mapping == MAP_FAILED) {
		save_errno = errno;
		close(fd);
		errno = save_errno;
		return (NULL);
	}
	if (mprotect(mapping, total, PROT_READ) == -1) {
		save_errno = errno;
		munmap(mapping, total);
		close(fd);
		errno = save_errno;
		return (NULL);
	}
	pool = calloc(1, sizeof(*pool));
	if (pool == NULL) {
		save_errno = errno;
		munmap(mapping, total);
		close(fd);
		errno = save_errno;
		return (NULL);
	}
	pool->ip_fd = fd;
	pool->ip_nbufs = number;
	pool->ip_bufsize = size;
	pool->ip_mapping = mapping;
	pool->ip_mapping_len = total;
	return (pool);
}

void
iobuf_pool_delete(iobuf_pool_t pool)
{

	close(pool->ip_fd);
	munmap(pool->ip_mapping, pool->ip_mapping_len);
	free(pool);
}
