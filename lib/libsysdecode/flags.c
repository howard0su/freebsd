/*
 * Copyright (c) 2006 "David Kirchner" <dpk@dpk.net>. All rights reserved.
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#define _KERNEL
#include <sys/socket.h>
#undef _KERNEL
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/procctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/reboot.h>
#include <sched.h>
#include <sys/linker.h>
#define _KERNEL
#include <sys/thr.h>
#undef _KERNEL
#include <sys/extattr.h>
#include <sys/acl.h>
#include <aio.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include <sys/rtprio.h>
#include <sys/shm.h>
#include <sys/umtx.h>
#include <nfsserver/nfs.h>
#include <ufs/ufs/quota.h>
#include <sys/capsicum.h>
#include <vm/vm.h>
#include <vm/vm_param.h>

#include <sysdecode.h>
#include "local.h"

/*
 * This is taken from the xlat tables originally in truss which were
 * in turn taken from strace.
 */
struct name_table {
	uintmax_t val;
	const char *str;
};

#define	X(a)	{ a, #a },
#define	XEND	{ 0, NULL }

#define	TABLE_START(n)	static struct name_table n[] = {
#define	TABLE_ENTRY(x)	X(x)
#define	TABLE_END	XEND };

#include "tables.h"

#undef TABLE_START
#undef TABLE_ENTRY
#undef TABLE_END

/*
 * These are simple support macros. print_or utilizes a variable
 * defined in the calling function to track whether or not it should
 * print a logical-OR character ('|') before a string. if_print_or
 * simply handles the necessary "if" statement used in many lines
 * of this file.
 */
#define print_or(fp,str,orflag) do {                     \
	if (orflag) fputc(fp, '|'); else orflag = true;  \
	fprintf(fp, str); }                              \
	while (0)
#define if_print_or(fp,i,flag,orflag) do {         \
	if ((i & flag) == flag)                    \
	print_or(fp,#flag,orflag); }               \
	while (0)

static const char *
lookup_value(struct name_table *table, uintmax_t val)
{

	for (; table->str != NULL; table++)
		if (table->val == val)
			return (table->str);
	return (NULL);
}

/*
 * Used when the value maps to a bitmask of #definition values in the
 * table.  This is a helper routine which outputs a symbolic mask of
 * matched masks.  Multiple masks are separated by a pipe ('|').
 * This function returns true if it outputs anything.  The value is
 * modified on return to only hold unmatched bits.
 */
static bool
print_mask_part(FILE *fp, struct name_table *table, uintmax_t *valp)
{
	uintmax_t rem;
	bool or;

	or = false;
	rem = *valp;
	for (; table->str != NULL; table++) {
		if ((table->val & rem) == table->val) {
			/*
			 * Only print a zero mask if the raw value is
			 * zero.
			 */
			if (table->val == 0 && *valp != 0)
				continue;
			fprintf(fp, "%s%s", or ? "|" : "", table->str);
			or = true;
			rem &= ~table->val;
		}
	}

	*valp = rem;
	return (!or);
}

static void
print_mask_prefix(FILE *fp, uintmax_t val)
{

	if (_sd_flags_format == KDUMP)
		fprintf(fp, "%#jx<", val);
}

static void
print_mask_suffix(FILE *fp, uintmax_t rem, bool printed)
{

	if (_sd_flags_format == KDUMP) {
		fprintf(fp, ">");
		if (!printed)
			fprintf(fp, "<invalid>%ju", rem);
	} else {
		if (!printed || rem != 0)
			fprintf(fp, "%s0x%jx", printed ? "|" : "", rem);
	}
}

/*
 * Used when the value maps to a bitmask of #definition values in the
 * table.
 */
static void
print_mask(FILE *fp, struct name_table *table, uintmax_t val)
{
	bool printed;

	print_mask_prefix(fp, val);
	printed = print_mask_part(fp, table, &val);
	print_mask_suffix(fp, val, printed);
}

/*
 * Used for a mask of optional flags where a value of 0 is valid.
 */
static void
print_mask_0(FILE *fp, struct name_table *table, uintmax_t val)
{

	if (val == 0)
		fputs("0", fp);
	else
		print_mask(fp, table, val);
}

static void
print_integer(FILE *fp, uintmax_t val, int base)
{

	switch (base) {
	case 8:
		fprintf(fp, "0%jo", val);
		break;
	case 10:
		fprintf(fp, "%ju", val);
		break;
	case 16:
		fprintf(fp, "0x%jx", val);
		break;
	default:
		abort2("bad base", 0, NULL);
		break;
	}
}

/*
 * Used when the value maps to a single, specific #definition.  The
 * raw value is output for unknown values.
 */
static void
print_value(FILE *fp, struct name_table *table, uintmax_t val, int base)
{
	const char *str;

	str = lookup_value(table, val);
	if (str != NULL)
		fputs(str, fp);
	else {
		if (_sd_flags_format == KDUMP)
			fprintf(fp, "<invalid=");
		print_integer(fp, val, base);
		if (_sd_flags_format == KDUMP)
			fprintf(fp, ">");
	}
}

void
sysdecode_atfd(FILE *fp, int fd, int decimal)
{

	if (fd == AT_FDCWD)
		fprintf(fp, "AT_FDCWD");
	else if (decimal)
		fprintf(fp, "%d", fd);
	else
		fprintf(fp, "%#x", fd);
}

void
sysdecode_signal(FILE *fp, int sig)
{

	if (sig > 0 && sig < NSIG)
		fprintf(fp, "SIG%s", sys_signames[sig]);
	else
		fprintf(fp, "SIG %d", sig);
}

static struct name_table semctlops[] = {
	X(GETNCNT) X(GETPID) X(GETVAL) X(GETALL) X(GETZCNT) X(SETVAL) X(SETALL)
	X(IPC_RMID) X(IPC_SET) X(IPC_STAT) XEND
};

void
sysdecode_semctl_op(FILE *fp, int cmd)
{

	print_value(fp, semctlops, cmd, 10);
}

static struct name_table shmctlops[] = {
	X(IPC_RMID) X(IPC_SET) X(IPC_STAT) XEND
};

void
sysdecode_shmctl_op(FILE *fp, int cmd)
{

	print_value(fp, shmctlops, cmd, 10);
}

static struct name_table semgetflags[] = {
	X(IPC_CREAT) X(IPC_EXCL) X(SEM_R) X(SEM_A) X((SEM_R>>3)) X((SEM_A>>3))
	X((SEM_R>>6)) X((SEM_A>>6)) XEND
};

void
sysdecode_semget_flags(FILE *fp, int flag)
{

	print_mask(fp, semgetflags, flag);
}

/*
 * Only used by SYS_open. Unless O_CREAT is set in flags, the
 * mode argument is unused (and often bogus and misleading).
 *
 * XXX: I think this belongs in kdump.c not in libsysdecode.
 */
void
sysdecode_flagsandmode(FILE *fp, int flags, int mode, int decimal)
{
	sysdecode_openflags(fp, flags);
	fputc(',', fp);
	if ((flags & O_CREAT) == O_CREAT) {
		modename (mode);
	} else {
		if (decimal) {
			fprintf(fp, "<unused>%d", mode);
		} else {
			fprintf(fp, "<unused>%#x", (unsigned int)mode);
		}
	}
}

static struct name_table idtypenames[] = {
	X(P_PID) X(P_PPID) X(P_PGID) X(P_SID) X(P_CID) X(P_UID) X(P_GID)
	X(P_ALL) X(P_LWPID) X(P_TASKID) X(P_PROJID) X(P_POOLID) X(P_JAILID)
	X(P_CTID) X(P_CPUID) X(P_PSETID) XEND
};

void
sysdecode_idtype(FILE *fp, idtype_t idtype, int base)
{

	print_value(fp, idtypenames, idtype, base);
}

/*
 * [g|s]etsockopt's level argument can either be SOL_SOCKET or a value
 * referring to a line in /etc/protocols . It might be appropriate
 * to use getprotoent(3) here.
 */
void
sysdecode_sockopt_level(FILE *fp, int level, int decimal)
{
	if (level == SOL_SOCKET) {
		fprintf(fp, "SOL_SOCKET");
	} else {
		if (decimal) {
			fprintf(fp, "%d", level);
		} else {
			fprintf(fp, "%#x", (unsigned int)level);
		}
	}
}

void
sysdecode_vmprot(FILE *fp, int type)
{

	print_mask(fp, vmprot, type);
}

void
sysdecode_sockettypewithflags(FILE *fp, int type, int base)
{

	sysdecode_sockettype(fp, type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK), base);
	if (type & SOCK_CLOEXEC)
		fprintf(fp, "|SOCK_CLOEXEC");
	if (type & SOCK_NONBLOCK)
		fprintf(fp, "|SOCK_NONBLOCK");
}

/* auto_or_type - print_mask(fp, table, val) */
/* base is almost always 10 for kdump, but can vary for truss */
/* auto_switch_type - print_value(fp, table, val, base) */
/* auto_if_type - print_value(fp, table, val, base) */

void
sysdecode_accessmode(FILE *fp, int mode)
{

	print_mask(fp, accessmodename, mode);
}

void
sysdecode_acltype(FILE *fp, acl_type_t type)
{

	print_value(fp, acltypename, type, base);
}

void
sysdecode_capfcntlrights(FILE *fp, uint32_t rights)
{

	print_mask(fp, capfcntlname, rights);
}

void
sysdecode_extattrnamespace(FILE *fp, int namespace, int base)
{

	print_value(fp, extattrns, namespace, base);
}

void
sysdecode_fadvice(FILE *fp, int advice, int base)
{

	print_value(fp, fadvisebehavname, advice, base);
}

void
sysdecode_open_flags(FILE *fp, int flags)
{

	/* XXX: Need to handle O_ACCMODE specially. */
	print_mask(fp, fileflags, flags);
}

void
sysdecode_fcntl_fileflags(FILE *fp, int flags)
{
	uintmax_t val;
	bool printed;

	/*
	 * The file flags used with F_GETFL/F_SETFL mostly match the
	 * flags passed to open(2).  However, a few open-only flag
	 * bits have been repurposed for fcntl-only flags.
	 */

	print_mask_prefix(fp, flags);
	val = flags & ~(O_NOFOLLOW | FRDAHEAD);
	printed = print_mask_part(fp, fileflags, &val);
	if (flags & O_NOFOLLOW) {
		fprintf(fp, "%sFPOIXSHM", printed ? "|" : "");
		printed = true;
	}
	if (flags & FRDAHEAD) {
		fprintf(fp, "%sFRDAHEAD", printed ? "|" : "");
		printed = true;
	}
	print_mask_suffix(fp, val, printed);
}

void
sysdecode_flock_op(FILE *fp, int operation)
{

	print_mask(fp, flockname, operation);
}

void
sysdecode_getfsstat_flags(FILE *fp, int flags)
{

	print_mask(fp, getfsstatflagsname, flags);
}

void
sysdecode_kldsym_cmd(FILE *fp, int command, int base)
{

	print_value(fp, kldsymcmdname, command, base);
}

void
sysdecode_kldunload_flags(FILE *fp, int flags, int base)
{

	print_value(fp, kldunloadfflagsname, flags, base);
}

void
sysdecode_lio_listio_mode(FILE *fp, int mode, int base)
{

	print_value(fp, lio_listiomodes, mode, base);
}

void
sysdecode_madvice(FILE *fp, int advice, int base)
{

	print_value(fp, madvisebehavname, advice, base);
}

void
sysdecode_minherit_flags(FILE *fp, int inherit, int base)
{

	print_value(fp, minheritname, inherit, base);
}

void
sysdecode_mlockall_flags(FILE *fp, int flags)
{

	print_mask(fp, mlockallname, flags);
}

void
sysdecode_mmap_prot(FILE *fp, int prot)
{

	print_mask(fp, mmapprotname, prot);
}

void
sysdecode_filemode(FILE *fp, int mode)
{

	print_mask(fp, modename, mode);
}

void
sysdecode_mount_flags(FILE *fp, int flags)
{

	print_mask(fp, mountflagsname, flags);
}

void
sysdecode_msync_flags(FILE *fp, int flags)
{

	print_mask(fp, msyncflagsname, flags);
}

void
sysdecode_nfssvc_flags(FILE *fp, int flags, int base)
{

	print_value(fp, nfssvcname, flags, base);
}

void
sysdecode_getpriority_which(FILE *fp, int which, int base)
{

	print_value(fp, prioname, which, base);
}

void
sysdecode_procctl_cmd(FILE *fp, int cmd, int base)
{

	print_value(fp, procctlcmdname, cmd, base);
}

void
sysdecode_ptrace_request(FILE *fp, int request, int base)
{

	print_value(fp, ptraceopname, request, base);
}

void
sysdecode_quotactl_cmd(FILE *fp, int cmd, int base)
{

	/*
	 * XXX: This is not correct, this needs to decompose 'cmd'
	 * into its components and rebuild the corresponding QCMD()
	 * invocation.
	 */
	print_value(fp, quotactlcmds, cmd, base);
}

void
sysdecode_reboot_howto(FILE *fp, int howto)
{

	print_mask(fp, rebootoptname, howto);
}

void
sysdecode_rfork_flags(FILE *fp, int flags)
{

	print_mask(fp, rforkname, flags);
}

void
sysdecode_rlimit(FILE *fp, int resource, int base)
{

	print_value(fp, rlimitname, resource, base);
}

void
sysdecode_scheduler_policy(FILE *fp, int policy, int base)
{

	print_value(fp, schedpolicyname, policy, base);
}

void
sysdecode_sendfile_flags(FILE *fp, int flags)
{

	print_mask(fp, sendfileflagsname, flags);
}

void
sysdecode_shmat_flags(FILE *fp, int flags)
{

	print_mask(fp, shmatflags, flags);
}

void
sysdecode_shutdown_how(FILE *fp, int how, int base)
{

	print_value(fp, shutdownhow, how, base);
}

void
sysdecode_sigbus_code(FILE *fp, int si_code, int base)
{

	print_value(fp, sigbuscode, si_code, base);
}

void
sysdecode_sigchld_code(FILE *fp, int si_code, int base)
{

	print_value(fp, sigchldcode, si_code, base);
}

void
sysdecode_sigfpe_code(FILE *fp, int si_code, int base)
{

	print_value(fp, sigfpecode, si_code, base);
}

void
sysdecode_sigill_code(FILE *fp, int si_code, int base)
{

	print_value(fp, sigillcode, si_code, base);
}

void
sysdecode_sigsegv_code(FILE *fp, int si_code, int base)
{

	print_value(fp, sigsegvcode, si_code, base);
}

void
sysdecode_sigtrap_code(FILE *fp, int si_code, int base)
{

	print_value(fp, sigtrapcode, si_code, base);
}

void
sysdecode_sigprocmask_how(FILE *fp, int how, int base)
{

	print_value(fp, sigprocmaskhow, how, base);
}

void
sysdecode_socketdomain(FILE *fp, int domain, int base)
{

	print_value(fp, sockdomain, domain, base);
}

void
sysdecode_sockaddr_family(FILE *fp, int sa_family, int base)
{

	print_value(fp, sockfamily, sa_family, base);
}

void
sysdecode_ipproto(FILE *fp, int protocol, int base)
{

	print_value(fp, sockipproto, protocol, base);
}

/* Accept level and optname? */
void
sysdecode_sockopt_name(FILE *fp, int optname, int base)
{

	print_value(fp, sockopt, optname, base);
}

void
sysdecode_sockettype(FILE *fp, int type, int base)
{

	print_value(fp, socktype, type, base);
}

void
sysdecode_thr_create_flags(FILE *fp, int flags)
{

	print_mask(fp, thrcreateflags, flags);
}

void
sysdecode_umtx_op(FILE *fp, int op, int base)
{

	print_value(fp, umtxop, op, base);
}

void
sysdecode_vmresult(FILE *fp, int result, int base)
{

	print_value(fp, vmresult, result, base);
}

void
sysdecode_wait6_options(FILE *fp, int options)
{

	print_mask(fp, wait6opt, options);
}

void
sysdecode_whence(FILE *fp, int whence, int base)
{

	print_value(fp, whence, whence, base);
}

void
sysdecode_fcntl_cmd(FILE *fp, int cmd, int base)
{

	print_value(fp, fcntlcmd, cmd, base);
}

static struct name_table fcntl_fd_arg[] = {
	X(FD_CLOEXEC) X(0) XEND
};

void
sysdecode_fcntl_arg(FILE *fp, int cmd, int arg, int base)
{

	switch (cmd) {
	case F_SETFD:
		print_value(fp, fcntl_fd_arg, arg, base);
		break;
	case F_SETFL:
		sysdecode_fcntl_fileflags(fp, arg);
		break;
	default:
		print_integer(fp, arg, base);
		break;
	}
}

void
sysdecode_mmap_flags(FILE *fp, int flags)
{
	uintmax_t val;
	bool printed;
	int align;

	/*
	 * MAP_ALIGNED can't be handled directly by print_mask().
	 * MAP_32BIT is also problematic since it isn't defined for
	 * all platforms.
	 */
	print_mask_prefix(fp, flags);
	align = flags & MAP_ALIGNMENT_MASK;
	val = flags & ~MAP_ALIGNMENT_MASK;
	printed = print_mask_part(fp, table, &val);
#ifdef MAP_32BIT
	if (val & MAP_32BIT) {
		fprintf(fp, "%sMAP_32BIT", printed ? "|" : "");
		printed = true;
	}
#endif
	if (align != 0) {
		if (printed)
			fputc('|', fp);
		if (align == MAP_ALIGNED_SUPER)
			fputs("MAP_ALIGNED_SUPER", fp);
		else
			fprintf(fp, "MAP_ALIGNED(%d)",
			    align >> MAP_ALIGNMENT_SHIFT);
		printed = true;
	}
	print_mask_suffix(fp, val, printed);
}

void
sysdecode_rtprio_function(FILE *fp, int function, int base)
{

	print_value(fp, rtpriofuncs, function, base);
}

void
sysdecode_msg_flags(FILE *fp, int flags)
{

	print_mask_0(fp, msgflags, flags);
}

void
sysdecode_sigcode(FILE *fp, int sig, int code)
{
	const char *s;

	s = lookup_value(sigcode, code);
	if (s != NULL) {
		fputs(s, fp);
		return;
	}
	
	switch (sig) {
	case SIGILL:
		sysdecode_sigill_code(fp, code);
		break;
	case SIGBUS:
		sysdecode_sigbus_code(fp, code);
		break;
	case SIGSEGV:
		sysdecode_sigsegv_code(fp, code);
		break;
	case SIGFPE:
		sysdecode_sigfpe_code(fp, code);
		break;
	case SIGTRAP:
		sysdecode_sigtrap_code(fp, code);
		break;
	case SIGCHLD:
		sysdecode_sigchld_code(fp, code);
		break;
	default:
		fprintf(fp, "<invalid=%#x>", code);
	}
}

void
sysdecode_umtx_cvwait_flags(FILE *fp, u_long flags)
{

	print_mask_0(fp, umtxcvwaitflags, flags);
}

void
sysdecode_umtx_rwlock_flags(FILE *fp, u_long flags)
{

	print_mask_0(fp, umtxrwlockflags, flags);
}

/* XXX: This should be in <sys/capsicum.h> */
#define	CAPMASK(right)	((right) && (((uint64_t)1 << 57) - 1))

void
sysdecode_capname(FILE *fp, cap_rights_t *rightsp)
{
	struct name_table *t;
	int idx;
	bool comma;

	comma = false;
	for (t = caprights; t->str != NULL; t++) {
		idx = ffs(CAPIDXBIT(t->val)) - 1;
		if (CAPARSIZE(rightsp) < idx)
			continue;
		if ((rightsp->cr_rights[CAPIDXBIT(t->val)] & CAPMASK(t->val)) ==
		    CAPMASK(t->val)) {
			fprintf(fp, "%s%s", comma ? "," : "", t->str);
			comma = true;
		}
	}
}
