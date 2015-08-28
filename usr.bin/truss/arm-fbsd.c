/*
 * Copyright 1997 Sean Eric Fagan
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Sean Eric Fagan
 * 4. Neither the name of the author may be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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

/* FreeBSD/arm-specific system call handling. */

#if 0
#include <sys/types.h>
#endif
#include <sys/ptrace.h>
#include <sys/syscall.h>

#include <machine/reg.h>
#include <machine/armreg.h>
#include <machine/ucontext.h>

#if 0
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
#include <err.h>
#endif

#include "truss.h"
#if 0
#include "syscall.h"
#include "extern.h"
#endif

#include "syscalls.h"

static int
arm_fetch_args(struct trussinfo *trussinfo)
{
	struct ptrace_io_desc iorequest;
	struct reg regs;
	struct current_syscall *cs;
	lwpid_t tid;
	int i, syscall_num;
	register_t *ap;

	tid = trussinfo->curthread->tid;
	cs = &trussinfo->curthread->cs;
	if (ptrace(PT_GETREGS, tid, (caddr_t)&regs, 0) < 0) {
		fprintf(trussinfo->outfile, "-- CANNOT READ REGISTERS --\n");
		return (-1);
	}
	ap = &regs.r[0];

	/*
	 * FreeBSD has two special kinds of system call redirctions --
	 * SYS_syscall, and SYS___syscall.  The former is the old syscall()
	 * routine, basically; the latter is for quad-aligned arguments.
	 *
	 * The system call argument count and code from ptrace() already
	 * account for these, but we need to skip over %rax if it contains
	 * either of these values.
	 */
#ifdef __ARM_EABI__
	syscall_num = regs.r[7];
#else
	if ((syscall_num = ptrace(PT_READ_I, tid, 
	    (caddr_t)(regs.r[_REG_PC] - INSN_SIZE), 0)) == -1) {
		fprintf(trussinfo->outfile, "-- CANNOT READ PC --\n");
		return (-1);
	}
	syscall_num = syscall_num & 0x000fffff;
#endif

	/*
	 * XXX: This doesn't seem correct.  The code below always reads
	 * 4 args from ap[] even if these are used.  If this needs to be
	 * fixed, the approach in amd64-fbsd.c would probably work well.
	 */
	switch (syscall_num) {
	case SYS_syscall:
		ap += 1;
		break;
	case SYS___syscall:
		ap += 2;
		break;
	}

	switch (cs->nargs) {
	default:
		/*
		 * The OS doesn't seem to allow more than 10 words of
		 * parameters (yay!).	So we shouldn't be here.
		 */
		warn("More than 10 words (%d) of arguments!\n", cs->nargs);
		break;
	case 10:
	case 9:
	case 8:
	case 7:
	case 6:
	case 5:
		/*
		 * If there are 7-10 words of arguments, they are placed
		 * on the stack, as is normal for other processors.
		 * The fall-through for all of these is deliberate!!!
		 */
		// XXX BAD constant used here
		iorequest.piod_op = PIOD_READ_D;
		iorequest.piod_offs = (void *)(regs.r_sp +
		    4 * sizeof(uint32_t));
		iorequest.piod_addr = &cs->args[4];
		iorequest.piod_len = (cs->nargs - 4) * sizeof(cs->args[0]);
		ptrace(PT_IO, tid, (caddr_t)&iorequest, 0);
		if (iorequest.piod_len == 0)
			return (-1);
	case 4:	cs->args[3] = ap[3];
	case 3:	cs->args[2] = ap[2];
	case 2:	cs->args[1] = ap[1];
	case 1:	cs->args[0] = ap[0];
	case 0: break;
	}

	return (0);
}

static int
arm_fetch_retval(struct trussinfo *trussinfo, long *retval, int *errorp)
{
{
	struct reg regs;
	lwpid_t tid;

	tid = trussinfo->curthread->tid;
	if (ptrace(PT_GETREGS, tid, (caddr_t)&regs, 0) < 0) {
		fprintf(trussinfo->outfile, "-- CANNOT READ REGISTERS --\n");
		return (-1);
	}

	*retval = regs.r[0];
	*errorp = !!(regs.r_cpsr & PSR_C);
	return (0);
}

static struct procabi arm_fbsd = {
	"FreeBSD ELF32",
	syscallnames,
	nitems(syscallnames),
	arm_fetch_args,
	arm_fetch_retval
};

PROCABI(arm_fbsd);
