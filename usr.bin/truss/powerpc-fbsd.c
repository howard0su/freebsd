/*
 * Copyright 2006 Peter Grehan <grehan@freebsd.org>
 * Copyright 2005 Orlando Bassotto <orlando@break.net>
 * Copyright 1998 Sean Eric Fagan
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

/* FreeBSD/powerpc-specific system call handling. */

#if 0
#include <sys/types.h>
#endif
#include <sys/ptrace.h>
#include <sys/syscall.h>

#include <machine/reg.h>
#include <machine/frame.h>

#if 0
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#endif
#include <stdio.h>
#if 0
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#endif

#include "truss.h"
#if 0
#include "syscall.h"
#include "extern.h"
#endif

#ifdef __powerpc64__	/* 32-bit compatibility */
#include "freebsd32_syscalls.h"
#define	syscallnames	freebsd32_syscallnames
#else			/* native 32-bit */
#include "syscalls.h"
#endif

static int
powerpc_fetch_args(struct trussinfo *trussinfo)
{
	struct ptrace_io_desc iorequest;
	struct reg regs;
	struct current_syscall *cs;
	struct syscall *sc;
	lwpid_t tid;
	int i, reg;

#if 0
	/* Account for a 64-bit argument with corresponding alignment. */
	nargs += 2;
#endif

	tid = trussinfo->curthread->tid;
	cs = &trussinfo->curthread->cs;
	if (ptrace(PT_GETREGS, tid, (caddr_t)&regs, 0) < 0) {
		fprintf(trussinfo->outfile, "-- CANNOT READ REGISTERS --\n");
		return (-1);
	}

	/*
	 * FreeBSD has two special kinds of system call redirections --
	 * SYS_syscall, and SYS___syscall.  The former is the old syscall()
	 * routine, basically; the latter is for quad-aligned arguments.
	 *
	 * The system call argument count and code from ptrace() already
	 * account for these, but we need to skip over the first argument.
	 */
	reg = 0;
	switch (regs.fixreg[0]) {
	case SYS_syscall:
		reg += 1;
		break;
	case SYS___syscall:
		reg += 2;
		break;
	}

	for (i = 0; i < cs->nargs && reg < NARGREG; i++, reg++) {
#ifdef __powerpc64__
		cs->args[i] = regs.fixreg[FIRSTARG + reg] & 0xffffffff;
#else
		cs->args[i] = regs.fixreg[FIRSTARG + reg];
#endif
	}
	if (cs->nargs > i) {
#ifdef __powerpc64__
		uint32_t *args32;
		int j;

		args32 = calloc(cs->nargs - i, sizeof(uint32_t));
#endif
		iorequest.piod_op = PIOD_READ_D;
		iorequest.piod_offs = (void *)(regs.fixreg[1] + 8);
#ifdef __powerpc64__
		iorequest.piod_addr = args32;
		iorequest.piod_len = (cs->nargs - i) * sizeof(args32[0]);
#else
		iorequest.piod_addr = &cs->args[i];
		iorequest.piod_len = (cs->nargs - i) * sizeof(cs->args[0]);
#endif
		ptrace(PT_IO, tid, (caddr_t)&iorequest, 0);
		if (iorequest.piod_len == 0)
			return (-1);
#ifdef __powerpc64__
		for (j = 0; j < cs->nargs - i; j++)
			cs->args[i + j] = args32[j];
		free(args32);
#endif
	}

	return (0);
}

static int
powerpc_fetch_retval(struct trussinfo *trussinfo, long *retval, int *errorp)
{
	struct reg regs;
	lwpid_t tid;

	tid = trussinfo->curthread->tid;
	if (ptrace(PT_GETREGS, tid, (caddr_t)&regs, 0) < 0) {
		fprintf(trussinfo->outfile, "-- CANNOT READ REGISTERS --\n");
		return (-1);
	}

	*retval = regs.fixreg[3];
	*errorp = !!(regs.cr & 0x10000000);
	return (0);
}

static struct procabi powerpc_fbsd = {
	"FreeBSD ELF32",
	syscallnames,
	nitems(syscallnames),
	powerpc_fetch_args,
	powerpc_fetch_retval
};

PROCABI(powerpc_fbsd);
