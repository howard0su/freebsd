/*-
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

/*
 * Various setup functions for truss.  Not the cleanest-written code,
 * I'm afraid.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <machine/reg.h>

#include "truss.h"
#include "extern.h"

static sig_atomic_t detaching;

/*
 * setup_and_wait() is called to start a process.  All it really does
 * is fork(), set itself up to stop on exec or exit, and then exec
 * the given command.  At that point, the child process stops, and
 * the parent can wake up and deal with it.
 */

int
setup_and_wait(char *command[])
{
	pid_t pid;

	pid = vfork();
	if (pid == -1)
		err(1, "fork failed");
	if (pid == 0) {	/* Child */
		ptrace(PT_TRACE_ME, 0, 0, 0);
		execvp(command[0], command);
		err(1, "execvp %s", command[0]);
	}

	/* Only in the parent here */
	if (waitpid(pid, NULL, 0) < 0)
		err(1, "unexpect stop in waitpid");

	return (pid);
}

/*
 * start_tracing picks up where setup_and_wait() dropped off -- namely,
 * it sets the event mask for the given process id.  Called for both
 * monitoring an existing process and when we create our own.
 */

int
start_tracing(pid_t pid)
{
	int ret, retry;

	retry = 10;
	do {
		ret = ptrace(PT_ATTACH, pid, NULL, 0);
		usleep(200);
	} while (ret && retry-- > 0);
	if (ret)
		err(1, "can not attach to target process");

	if (waitpid(pid, NULL, 0) < 0)
		err(1, "Unexpect stop in waitpid");

	return (0);
}

/*
 * Restore a process back to it's pre-truss state.
 * Called for SIGINT, SIGTERM, SIGQUIT.  This only
 * applies if truss was told to monitor an already-existing
 * process.
 */

void
restore_proc(int signo __unused)
{

	detaching = 1;
}

static void
detach_proc(pid_t pid)
{

	/* stop the child so that we can detach */
	kill(pid, SIGSTOP);
	if (waitpid(pid, NULL, 0) < 0)
		err(1, "Unexpected stop in waitpid");

	if (ptrace(PT_DETACH, pid, (caddr_t)1, 0) < 0)
		err(1, "Can not detach the process");

	kill(pid, SIGCONT);
}

/*
 * Change curthread member based on lwpid.
 * If it is a new thread, create a threadinfo structure
 */
static void
find_thread(struct trussinfo *info, lwpid_t lwpid)
{
	struct threadinfo *np;

	info->curthread = NULL;
	SLIST_FOREACH(np, &info->threadlist, entries) {
		if (np->tid == lwpid) {
			info->curthread = np;
			return;
		}
	}

	np = (struct threadinfo *)calloc(1, sizeof(struct threadinfo));
	if (np == NULL)
		err(1, "calloc() failed");
	np->tid = lwpid;
	SLIST_INSERT_HEAD(&info->threadlist, np, entries);
	info->curthread = np;
}

/*
 * Start the traced process and wait until it stoped.
 * Fill trussinfo structure.
 * When this even returns, the traced process is in stop state.
 */
void
waitevent(struct trussinfo *info)
{
	siginfo_t si;

	ptrace(PT_SYSCALL, info->pid, (caddr_t)1, info->pending_signal);
	info->pending_signal = 0;

	for (;;) {
		if (detaching) {
			detach_proc(info->pid);
			info->pr_why = DETACHED;
			return;
		}

		if (waitid(P_PID, info->pid, &si, WTRAPPED | WEXITED) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "Unexpected error from waitid");
		}

		assert(si.si_signo == SIGCHLD);
		assert(si.si_pid == info->pid);

		info->pr_data = si.si_status;
		switch (si.si_code) {
		case CLD_EXITED:
			info->pr_why = EXIT;
			return;
		case CLD_KILLED:
			info->pr_why = KILLED;
			return;
		case CLD_DUMPED:
			info->pr_why = CORED;
			return;
		case CLD_TRAPPED:
			if (ptrace(PT_LWPINFO, si.si_pid,
			    (caddr_t)&info->pr_lwpinfo,
			    sizeof(info->pr_lwpinfo)) == -1)
				err(1, "ptrace(PT_LWPINFO)");
			find_thread(info, info->pr_lwpinfo.pl_lwpid);

			if (si.si_status == SIGTRAP) {
				if (info->pr_lwpinfo.pl_flags & PL_FLAG_SCE) {
					info->pr_why = SCE;
					info->curthread->in_syscall = 1;
				} else if (info->pr_lwpinfo.pl_flags &
				    PL_FLAG_SCX) {
					info->pr_why = SCX;
					info->curthread->in_syscall = 0;
				} else
					errx(1,
		   "pl_flags %x contains neither PL_FLAG_SCE nor PL_FLAG_SCX",
					    info->pr_lwpinfo.pl_flags);
			} else {
				info->pr_why = SIG;
				info->pending_signal = si.si_status;
			}
			return;
		case CLD_STOPPED:
			errx(1, "waitid reported CLD_STOPPED");
		case CLD_CONTINUED:
			break;
		}
	}
}
