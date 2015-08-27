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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <machine/reg.h>

#include "truss.h"
#include "extern.h"

static sig_atomic_t detaching;

static void	new_proc(struct trussinfo *, pid_t);

/*
 * setup_and_wait() is called to start a process.  All it really does
 * is fork(), enable tracing in the child, and then exec the given
 * command.  At that point, the child process stops, and the parent
 * can wake up and deal with it.
 */
void
setup_and_wait(struct trussinfo *info, char *command[])
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

	new_proc(info, pid);
}

/*
 * start_tracing is called to attach to an existing process.
 */
void
start_tracing(struct trussinfo *info, pid_t pid)
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

	new_proc(info, pid);
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

static void
new_proc(struct trussinfo *info, pid_t pid)
{
	struct procinfo *np;

	/*
	 * If this happens it means there is a bug in truss.  Unfortunately
	 * this will kill any processes are attached to.
	 */
	LIST_FOREACH(np, &info->proclist, entries) {
		if (np->pid == pid)
			errx(1, "Duplicate process for pid %ld", (long)pid);
	}

	if (info->flags & FOLLOWFORKS)
		ptrace(PT_FOLLOW_FORK, pid, NULL, 1);
	np = calloc(1, sizeof(struct procinfo));
	np->pid = pid;
	np->abi = find_abi(pid);
	SLIST_INIT(&np->threadlist);
	LIST_INSERT_HEAD(&info->proclist, np, entries);
}

static void
free_proc(struct procinfo *p)
{
	struct threadinfo *t, *t2;

	SLIST_FOREACH_SAFE(t, &p->threadlist, entries, t2) {
		free(t);
	}
	LIST_REMOVE(p, entries);
	free(p);
}

static void
detach_all_procs(struct trussinfo *info)
{
	struct procinfo *p, *p2;

	LIST_FOREACH_SAFE(p, &info->proclist, entries, p2) {
		detach_proc(p->pid);
		free_proc(p);
	}
}

static struct procinfo *
find_proc(struct trussinfo *info, pid_t pid)
{
	struct procinfo *np;

	LIST_FOREACH(np, &info->proclist, entries) {
		if (np->pid == pid)
			return (np);
	}

	return (NULL);
}

/*
 * Change curthread member based on (pid, lwpid).
 * If it is a new thread, create a threadinfo structure.
 */
static void
find_thread(struct trussinfo *info, pid_t pid, lwpid_t lwpid)
{
	struct procinfo *np;
	struct threadinfo *nt;

	np = find_proc(info, pid);
	assert(np != NULL);

	SLIST_FOREACH(nt, &np->threadlist, entries) {
		if (nt->tid == lwpid) {
			info->curthread = nt;
			return;
		}
	}

	nt = calloc(1, sizeof(struct threadinfo));
	if (nt == NULL)
		err(1, "calloc() failed");
	nt->proc = np;
	nt->tid = lwpid;
	SLIST_INSERT_HEAD(&np->threadlist, nt, entries);
	info->curthread = nt;
}

/*
 * When a process exits, it no longer has any threads left.  However,
 * the main loop expects a valid curthread.  In cases when a thread
 * triggers the termination (e.g. calling exit or triggering a fault)
 * we would ideally use that thread.  However, if a process is killed
 * by a signal sent from another process then there is no "correct"
 * thread.  We just punt and use the first thread.
 */
static void
find_exit_thread(struct trussinfo *info, pid_t pid)
{
	struct procinfo *np;
	struct threadinfo *nt;

	np = find_proc(info, pid);
	assert(np != NULL);

	if (SLIST_EMPTY(&np->threadlist)) {
		/*
		 * If an existing process exits right after we attach
		 * to it but before it posts any events, there won't
		 * be any threads.  Create a dummy thread and set its
		 * "after" time to the global start time.
		 */
		nt = calloc(1, sizeof(struct threadinfo));
		if (nt == NULL)
			err(1, "calloc() failed");
		nt->proc = np;
		nt->tid = 0;
		SLIST_INSERT_HEAD(&np->threadlist, nt, entries);
		nt->after = nt->before = info->start_time;
	}
	info->curthread = SLIST_FIRST(&np->threadlist);
}

static void
enter_syscall(struct trussinfo *info)
{

	info->curthread->proc->abi->enter_syscall(info);
	clock_gettime(CLOCK_REALTIME, &info->curthread->before);
}

static void
exit_syscall(struct trussinfo *info, struct ptrace_lwpinfo *pl)
{
	struct procinfo *p;

	p = info->curthread->proc;
	clock_gettime(CLOCK_REALTIME, &info->curthread->after);
	p->abi->exit_syscall(info);

	if (pl->pl_flags & PL_FLAG_EXEC) {
		p->abi = find_abi(p->pid);
		if (p->abi == NULL) {
			detach_proc(p->pid);
			free_proc(p);
		}
	}
}

/*
 * Wait for events until all the processes have exited or truss has been
 * asked to stop.
 */
void
eventloop(struct trussinfo *info)
{
	struct ptrace_lwpinfo pl;
	struct timespec timediff;
	siginfo_t si;
	char *signame;
	int pending_signal;

	while (!LIST_EMPTY(&info->proclist)) {
		if (detaching) {
			detach_all_procs(info);
			return;
		}

		if (waitid(P_ALL, 0, &si, WTRAPPED | WEXITED) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "Unexpected error from waitid");
		}

		assert(si.si_signo == SIGCHLD);

		switch (si.si_code) {
		case CLD_EXITED:
		case CLD_KILLED:
		case CLD_DUMPED:
			find_exit_thread(info, si.si_pid);
			if ((info->flags & COUNTONLY) == 0) {
				if (info->flags & FOLLOWFORKS)
					fprintf(info->outfile, "%5d: ",
					    si.si_pid);
				if (info->flags & ABSOLUTETIMESTAMPS) {
					timespecsubt(&info->curthread->after,
					    &info->start_time, &timediff);
					fprintf(info->outfile, "%jd.%09ld ",
					    (intmax_t)timediff.tv_sec,
					    timediff.tv_nsec);
				}
				if (info->flags & RELATIVETIMESTAMPS) {
					timespecsubt(&info->curthread->after,
					    &info->curthread->before,
					    &timediff);
					fprintf(info->outfile, "%jd.%09ld ",
					    (intmax_t)timediff.tv_sec,
					    timediff.tv_nsec);
				}
				if (si.si_code == CLD_EXITED)
					fprintf(info->outfile,
					    "process exit, rval = %u\n",
					    si.si_status);
				else
					fprintf(info->outfile,
					    "process killed, signal = %u%s\n",
					    si.si_status,
					    si.si_code == CLD_DUMPED ?
					    " (core dumped)" : "");
			}
			free_proc(info->curthread->proc);
			info->curthread = NULL;
			break;
		case CLD_TRAPPED:
			if (ptrace(PT_LWPINFO, si.si_pid, (caddr_t)&pl,
			    sizeof(pl)) == -1)
				err(1, "ptrace(PT_LWPINFO)");

			if (pl.pl_flags & PL_FLAG_CHILD) {
				new_proc(info, si.si_pid);
				assert(LIST_FIRST(&info->proclist)->abi !=
				    NULL);
			}
			find_thread(info, si.si_pid, pl.pl_lwpid);
			info->pr_lwpinfo = pl;  // XXX: Temporary

			if (si.si_status == SIGTRAP) {
				if (pl.pl_flags & PL_FLAG_SCE) {
					info->curthread->in_syscall = 1;
					enter_syscall(info);
				} else if (pl.pl_flags &
				    PL_FLAG_SCX) {
					info->curthread->in_syscall = 0;
					exit_syscall(info, &pl);
					
				} else
					errx(1,
		   "pl_flags %x contains neither PL_FLAG_SCE nor PL_FLAG_SCX",
					    pl.pl_flags);
				pending_signal = 0;
			} else if (pl.pl_flags & PL_FLAG_CHILD) {
				clock_gettime(CLOCK_REALTIME,
				    &info->curthread->after);
				assert(info->flags & FOLLOWFORKS);
				fprintf(info->outfile, "%5d: ", si.si_pid);
				if (info->flags & ABSOLUTETIMESTAMPS) {
					timespecsubt(&info->curthread->after,
					    &info->start_time, &timediff);
					fprintf(info->outfile, "%jd.%09ld ",
					    (intmax_t)timediff.tv_sec,
					    timediff.tv_nsec);
				}
				if (info->flags & RELATIVETIMESTAMPS) {
					timediff.tv_sec = 0;
					timediff.tv_nsec = 0;
					fprintf(info->outfile, "%jd.%09ld ",
					    (intmax_t)timediff.tv_sec,
					    timediff.tv_nsec);
				}
				fprintf(info->outfile, "<new process>\n");
				pending_signal = 0;
			} else if ((info->flags & NOSIGS) == 0) {
				if (info->flags & FOLLOWFORKS)
					fprintf(info->outfile, "%5d: ",
					    si.si_pid);
				if (info->flags & ABSOLUTETIMESTAMPS) {
					timespecsubt(&info->curthread->after,
					    &info->start_time, &timediff);
					fprintf(info->outfile, "%jd.%09ld ",
					    (intmax_t)timediff.tv_sec,
					    timediff.tv_nsec);
				}
				if (info->flags & RELATIVETIMESTAMPS) {
					timespecsubt(&info->curthread->after,
					    &info->curthread->before,
					    &timediff);
					fprintf(info->outfile, "%jd.%09ld ",
					    (intmax_t)timediff.tv_sec,
					    timediff.tv_nsec);
				}
				signame = strsig(si.si_status);
				fprintf(info->outfile,
				    "SIGNAL %u (%s)\n", si.si_status,
				    signame == NULL ? "?" : signame);
				pending_signal = si.si_status;
			}
			ptrace(PT_SYSCALL, si.si_pid, (caddr_t)1,
			    pending_signal);
			break;
		case CLD_STOPPED:
			errx(1, "waitid reported CLD_STOPPED");
		case CLD_CONTINUED:
			break;
		}
	}
}
