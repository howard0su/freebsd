/*-
 * Copyright (c) 2015 John H. Baldwin <jhb@FreeBSD.org>
 * All rights reserved.
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

/*
 * Map system call codes to names for the supported ABIs on each
 * platform.  Rather than regnerating system call name tables locally
 * during the build, use the generated tables in the kernel source
 * tree.
 */

#include <sys/param.h>
#include <stdio.h>
#include <sysdecode.h>

static
#include <kern/syscalls.c>

const char *
sysdecode_freebsd(unsigned int code)
{

	if (code < nitems(syscallnames))
		return (syscallnames[code]);
	return (NULL);
}

#if defined(__amd64__) || defined(__powerpc64__)
static
#include <compat/freebsd32/freebsd32_syscalls.c>

const char *
sysdecode_freebsd32(unsigned int code)
{

	if (code < nitems(freebsd32_syscallnames))
		return (freebsd32_syscallnames[code]);
	return (NULL);
}
#endif

#if defined(__amd64__) || defined(__i386__)

static
#ifdef __amd64__
#include <amd64/linux/linux_syscalls.c>
#else
#include <i386/linux/linux_syscalls.c>
#endif

const char *
sysdecode_linux(unsigned int code)
{

	if (code < nitems(linux_syscallnames))
		return (linux_syscallnames[code]);
	return (NULL);
}
#endif

#ifdef __amd64__

static
#include <amd64/linux32/linux32_syscalls.c>

const char *
sysdecode_linux32(unsigned int code)
{

	if (code < nitems(linux32_syscallnames))
		return (linux32_syscallnames[code]);
	return (NULL);
}
#endif
