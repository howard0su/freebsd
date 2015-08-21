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
 * The main module for truss.  Surprisingly simple, but, then, the other
 * files handle the bulk of the work.  And, of course, the kernel has to
 * do a lot of the work :).
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

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

#include "truss.h"
#include "extern.h"
#include "syscall.h"

static void
usage(void)
{
	fprintf(stderr, "%s\n%s\n",
	    "usage: truss [-cfaedDS] [-o file] [-s strsize] -p pid",
	    "       truss [-cfaedDS] [-o file] [-s strsize] command [args]");
	exit(1);
}

static struct procabi abis[] = {
#ifdef __arm__
	{ "FreeBSD ELF32", arm_syscall_entry, arm_syscall_exit },
#endif
#ifdef __amd64__
	{ "FreeBSD ELF64", amd64_syscall_entry, amd64_syscall_exit },
	{ "FreeBSD ELF32", amd64_fbsd32_syscall_entry, amd64_fbsd32_syscall_exit },
	{ "Linux ELF32", amd64_linux32_syscall_entry, amd64_linux32_syscall_exit },
#endif
#ifdef __i386__
	{ "FreeBSD a.out", i386_syscall_entry, i386_syscall_exit },
	{ "FreeBSD ELF", i386_syscall_entry, i386_syscall_exit },
	{ "FreeBSD ELF32", i386_syscall_entry, i386_syscall_exit },
	{ "Linux ELF", i386_linux_syscall_entry, i386_linux_syscall_exit },
#endif
#ifdef __powerpc__
	{ "FreeBSD ELF", powerpc_syscall_entry, powerpc_syscall_exit },
	{ "FreeBSD ELF32", powerpc_syscall_entry, powerpc_syscall_exit },
#ifdef __powerpc64__
	{ "FreeBSD ELF64", powerpc64_syscall_entry, powerpc64_syscall_exit },
#endif
#endif
#ifdef __sparc64__
	{ "FreeBSD ELF64", sparc64_syscall_entry, sparc64_syscall_exit },
#endif
#ifdef __mips__
	{ "FreeBSD ELF", mips_syscall_entry, mips_syscall_exit },
	{ "FreeBSD ELF32", mips_syscall_entry, mips_syscall_exit },
	{ "FreeBSD ELF64", mips_syscall_entry, mips_syscall_exit }, // XXX
#endif
	{ 0, 0, 0 },
};

/*
 * Determine the ABI.  This is called after every exec, and when
 * a process is first monitored.
 */
struct procabi *
find_abi(pid_t pid)
{
	struct procabi *abi;
	size_t len;
	int error;
	int mib[4];
	char progt[32];

	len = sizeof(progt);
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_SV_NAME;
	mib[3] = pid;
	error = sysctl(mib, 4, progt, &len, NULL, 0);
	if (error != 0)
		err(2, "can not get sysvec name");

	for (abi = abis; abi->type; abi++)
		if (strcmp(abi->type, progt) == 0)
			break;

	if (abi->type == NULL) {
		warnx("ABI %s for pid %ld is not supported", abi->type,
		    (long)pid);
		return (NULL);
	}
	return (abi);
}

char *
strsig(int sig)
{
	static char tmp[64];

	if (sig > 0 && sig < NSIG) {
		snprintf(tmp, sizeof(tmp), "SIG%s", sys_signame[sig]);
		return (tmp);
	}
	return (NULL);
}

static void
enter_syscall(struct trussinfo *info)
{

	info->curthread->proc->abi->enter_syscall(info);
	clock_gettime(CLOCK_REALTIME, &info->curthread->before);
}

static void
exit_syscall(struct trussinfo *info)
{
	struct procinfo *p;

	p = info->curthread->proc;
	clock_gettime(CLOCK_REALTIME, &info->curthread->after);
	p->abi->exit_syscall(info);

	if (info->curthread->pr_lwpinfo.pl_flags & PL_FLAG_EXEC) {
		p->abi = find_abi(p->pid);
		if (p->abi == NULL) {
			detach_proc(p->pid);
			free_proc(p);
		}
	}
}

int
main(int ac, char **av)
{
	struct timespec timediff;
	struct sigaction sa;
	struct trussinfo *trussinfo;
	char *fname;
	char *signame;
	char **command;
	pid_t pid;
	int c, status, quit;

	fname = NULL;

	/* Initialize the trussinfo struct */
	trussinfo = (struct trussinfo *)calloc(1, sizeof(struct trussinfo));
	if (trussinfo == NULL)
		errx(1, "calloc() failed");

	pid = 0;
	trussinfo->outfile = stderr;
	trussinfo->strsize = 32;
	trussinfo->curthread = NULL;
	SLIST_INIT(&trussinfo->proclist);
	while ((c = getopt(ac, av, "p:o:facedDs:S")) != -1) {
		switch (c) {
		case 'p':	/* specified pid */
			pid = atoi(optarg);
			/* make sure i don't trace me */
			if (pid == getpid()) {
				errx(2, "attempt to grab self.");
			}
			break;
		case 'f': /* Follow fork()'s */
			trussinfo->flags |= FOLLOWFORKS;
			break;
		case 'a': /* Print execve() argument strings. */
			trussinfo->flags |= EXECVEARGS;
			break;
		case 'c': /* Count number of system calls and time. */
			trussinfo->flags |= COUNTONLY;
			break;
		case 'e': /* Print execve() environment strings. */
			trussinfo->flags |= EXECVEENVS;
			break;
		case 'd': /* Absolute timestamps */
			trussinfo->flags |= ABSOLUTETIMESTAMPS;
			break;
		case 'D': /* Relative timestamps */
			trussinfo->flags |= RELATIVETIMESTAMPS;
			break;
		case 'o':	/* Specified output file */
			fname = optarg;
			break;
		case 's':	/* Specified string size */
			trussinfo->strsize = atoi(optarg);
			break;
		case 'S':	/* Don't trace signals */
			trussinfo->flags |= NOSIGS;
			break;
		default:
			usage();
		}
	}

	ac -= optind; av += optind;
	if ((pid == 0 && ac == 0) ||
	    (pid != 0 && ac != 0))
		usage();

	if (fname != NULL) { /* Use output file */
		/*
		 * Set close-on-exec ('e'), so that the output file is not
		 * shared with the traced process.
		 */
		if ((trussinfo->outfile = fopen(fname, "we")) == NULL)
			err(1, "cannot open %s", fname);
	}

	/*
	 * If truss starts the process itself, it will ignore some signals --
	 * they should be passed off to the process, which may or may not
	 * exit.  If, however, we are examining an already-running process,
	 * then we restore the event mask on these same signals.
	 */
	if (pid == 0) {
		/* Start a command ourselves */
		command = av;
		setup_and_wait(command);
		signal(SIGINT, SIG_IGN);
		signal(SIGTERM, SIG_IGN);
		signal(SIGQUIT, SIG_IGN);
	} else {
		sa.sa_handler = restore_proc;
		sa.sa_flags = 0;
		sigemptyset(&sa.sa_mask);
		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGQUIT, &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);
		start_tracing(trussinfo->pid);
	}

	/*
	 * At this point, if we started the process, it is stopped waiting to
	 * be woken up, either in exit() or in execve().
	 */
	trussinfo->curthread->proc->abi =
	    find_abi(trussinfo->curthread->proc->pid);
	if (trussinfo->curthread->proc->abi == NULL) {
		/*
		 * If we are not able to handle this ABI, detach from the
		 * process and exit.  If we just created a new process to
		 * run a command, kill the new process rather than letting
		 * it run untraced.
		 *
		 * XXX: I believe this fetches the ABI before exec so not
		 * quite what we want?
		 */
		if (pid == 0)
			kill(trussinfo->curthread->proc->pid, 9);
		ptrace(PT_DETACH, trussinfo->curthread->proc->pid);
		return (1);
	}

	/*
	 * At this point, it's a simple loop, waiting for the process to
	 * stop, finding out why, printing out why, and then continuing it.
	 * All of the grunt work is done in the support routines.
	 */
	clock_gettime(CLOCK_REALTIME, &trussinfo->start_time);

	do {
		waitevent(trussinfo);

		switch (trussinfo->pr_why) {
		case SCE:
			enter_syscall(trussinfo);
			break;
		case SCX:
			exit_syscall(trussinfo);
			break;
		case SIG:
			if (trussinfo->flags & NOSIGS)
				break;
			if (trussinfo->flags & FOLLOWFORKS)
				fprintf(trussinfo->outfile, "%5d: ",
				    trussinfo->pid);
			if (trussinfo->flags & ABSOLUTETIMESTAMPS) {
				timespecsubt(&trussinfo->curthread->after,
				    &trussinfo->start_time, &timediff);
				fprintf(trussinfo->outfile, "%jd.%09ld ",
				    (intmax_t)timediff.tv_sec,
				    timediff.tv_nsec);
			}
			if (trussinfo->flags & RELATIVETIMESTAMPS) {
				timespecsubt(&trussinfo->curthread->after,
				    &trussinfo->curthread->before, &timediff);
				fprintf(trussinfo->outfile, "%jd.%09ld ",
				    (intmax_t)timediff.tv_sec,
				    timediff.tv_nsec);
			}
			signame = strsig(trussinfo->pr_data);
			fprintf(trussinfo->outfile,
			    "SIGNAL %u (%s)\n", trussinfo->pr_data,
			    signame == NULL ? "?" : signame);
			break;
		case EXIT:
		case KILLED:
		case CORED:
			if (trussinfo->flags & COUNTONLY)
				break;
			if (trussinfo->flags & FOLLOWFORKS)
				fprintf(trussinfo->outfile, "%5d: ",
				    trussinfo->curthread->proc->pid);
			if (trussinfo->flags & ABSOLUTETIMESTAMPS) {
				timespecsubt(&trussinfo->curthread->after,
				    &trussinfo->start_time, &timediff);
				fprintf(trussinfo->outfile, "%jd.%09ld ",
				    (intmax_t)timediff.tv_sec,
				    timediff.tv_nsec);
			}
			if (trussinfo->flags & RELATIVETIMESTAMPS) {
				timespecsubt(&trussinfo->curthread->after,
				    &trussinfo->curthread->before, &timediff);
				fprintf(trussinfo->outfile, "%jd.%09ld ",
				    (intmax_t)timediff.tv_sec,
				    timediff.tv_nsec);
			}
			if (trussinfo->pr_why == EXIT)
				fprintf(trussinfo->outfile,
				    "process exit, rval = %u\n",
				    trussinfo->pr_data);
			else
				fprintf(trussinfo->outfile,
				    "process killed, signal = %u%s\n",
				    trussinfo->pr_data,
				    trussinfo->pr_why == CORED ?
				    " (core dumped)" : "");
			free_proc(trussinfo->curthread->proc);
			trussinfo->curthread = NULL;
			break;
		default:
			break;
		}
	} while (!LIST_EMPTY(&trussinfo->proclist));

	if (trussinfo->flags & COUNTONLY)
		print_summary(trussinfo);

	fflush(trussinfo->outfile);

	return (0);
}
