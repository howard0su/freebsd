/*-
 * Copyright (c) 1997 John S. Dyson.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. John S. Dyson's name may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * DISCLAIMER:  This code isn't warranted to do anything useful.  Anything
 * bad that happens because of using this software isn't the responsibility
 * of the author.  This software is distributed AS-IS.
 *
 * $FreeBSD$
 */

#ifndef _SYS_AIO_H_
#define	_SYS_AIO_H_

#include <sys/types.h>
#include <sys/signal.h>

/*
 * Returned by aio_cancel:
 */
#define	AIO_CANCELED		0x1
#define	AIO_NOTCANCELED		0x2
#define	AIO_ALLDONE		0x3

/*
 * LIO opcodes
 */
#define	LIO_NOP			0x0
#define LIO_WRITE		0x1
#define	LIO_READ		0x2
#ifdef _KERNEL
#define	LIO_SYNC		0x3
#define	LIO_MLOCK		0x4
#endif

/*
 * LIO modes
 */
#define	LIO_NOWAIT		0x0
#define	LIO_WAIT		0x1

/*
 * Maximum number of allowed LIO operations
 */
#define	AIO_LISTIO_MAX		16

/*
 * Private members for aiocb -- don't access
 * directly.
 */
struct __aiocb_private {
	long	status;
	long	error;
	void	*kernelinfo;
};

/*
 * I/O control block
 */
typedef struct aiocb {
	int	aio_fildes;		/* File descriptor */
	off_t	aio_offset;		/* File offset for I/O */
	volatile void *aio_buf;         /* I/O buffer in process space */
	size_t	aio_nbytes;		/* Number of bytes for I/O */
	int	__spare__[2];
	void	*__spare2__;
	int	aio_lio_opcode;		/* LIO opcode */
	int	aio_reqprio;		/* Request priority -- ignored */
	struct	__aiocb_private	_aiocb_private;
	struct	sigevent aio_sigevent;	/* Signal to deliver */
} aiocb_t;

#ifndef _KERNEL

struct timespec;

__BEGIN_DECLS
/*
 * Asynchronously read from a file
 */
int	aio_read(struct aiocb *);

/*
 * Asynchronously write to file
 */
int	aio_write(struct aiocb *);

/*
 * List I/O Asynchronously/synchronously read/write to/from file
 *	"lio_mode" specifies whether or not the I/O is synchronous.
 *	"acb_list" is an array of "nacb_listent" I/O control blocks.
 *	when all I/Os are complete, the optional signal "sig" is sent.
 */
int	lio_listio(int, struct aiocb * const [], int, struct sigevent *);

/*
 * Get completion status
 *	returns EINPROGRESS until I/O is complete.
 *	this routine does not block.
 */
int	aio_error(const struct aiocb *);

/*
 * Finish up I/O, releasing I/O resources and returns the value
 *	that would have been associated with a synchronous I/O request.
 *	This routine must be called once and only once for each
 *	I/O control block who has had I/O associated with it.
 */
ssize_t	aio_return(struct aiocb *);

/*
 * Cancel I/O
 */
int	aio_cancel(int, struct aiocb *);

/*
 * Suspend until all specified I/O or timeout is complete.
 */
int	aio_suspend(const struct aiocb * const[], int, const struct timespec *);

/*
 * Asynchronous mlock
 */
int	aio_mlock(struct aiocb *);

#ifdef __BSD_VISIBLE
int	aio_waitcomplete(struct aiocb **, struct timespec *);
#endif

int	aio_fsync(int op, struct aiocb *aiocbp);
__END_DECLS

#else

/* Forward declarations for prototypes below. */
struct socket;
struct sockbuf;

/* XXX: A bit of a hack to put this here for now. */
#include <sys/queue.h>
#include <sys/event.h>  /* XXX: For knlist */
#include <sys/signalvar.h>

typedef void aio_cancel_fn_t(struct kaiocb *);
typedef void aio_handle_fn_t(struct kaiocb *);

TAILQ_HEAD(kaiocbhead,kaiocb);

struct kaiocb {
	TAILQ_ENTRY(kaiocb) list;	/* (b) internal list of for backend */
	TAILQ_ENTRY(kaiocb) plist;	/* (a) list of jobs for each backend */
	TAILQ_ENTRY(kaiocb) allist;	/* (a) list of all jobs in proc */
	int	jobflags;		/* (a) job flags */
	int	inputcharge;		/* (*) input blocks */
	int	outputcharge;		/* (*) output blocks */
	struct	bio *bp;		/* (*) BIO backend BIO pointer */
	struct	buf *pbuf;		/* (*) BIO backend buffer pointer */
	struct	vm_page *pages[btoc(MAXPHYS)+1]; /* BIO backend pages */
	int	npages;			/* BIO backend number of pages */
	struct	proc *userproc;		/* (*) user process */
	struct	ucred *cred;		/* (*) active credential when created */
	struct	file *fd_file;		/* (*) pointer to file structure */
	struct	aioliojob *lio;		/* (*) optional lio job */
	struct	aiocb *ujob;		/* (*) pointer in userspace of aiocb */
	struct	knlist klist;		/* (a) list of knotes */
	struct	aiocb uaiocb;		/* (*) kernel I/O control block */
	ksiginfo_t ksi;			/* (a) realtime signal info */
	uint64_t seqno;			/* (*) job number */
	int	pending;		/* (a) number of pending I/O, aio_fsync only */
	aio_cancel_fn_t *cancel_fn;
	aio_handle_fn_t *handle_fn;
};

bool	aio_cancel_cleared(struct kaiocb *job);
void	aio_cancel(struct kaiocb *job);
bool	aio_clear_cancel_function(struct kaiocb *job);
void	aio_complete(struct kaiocb *job, long status, int error);
void	aio_schedule(struct kaiocb *job, aio_handle_fn_t *func);
bool	aio_set_cancel_function(struct kaiocb *job, aio_cancel_fn_t *func);
void	aio_switch_vmspace(struct kaiocb *job);

/* XXX: Hacks for the current socket code. */
void	aio_cancel_scheduled_job(struct kaiocb *job);
void	aio_kick_nowait(struct proc *userp);
extern struct mtx aio_job_mtx;
extern struct aiocbhead aio_jobs;

#endif

#endif
