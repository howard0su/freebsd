/*-
 * A hackish cross between ktrace and kdump that allows for targeted
 * inspection of individual processes and/or threads.  Each thread has
 * a bitmask of enabled inspection events.  When an inspected event
 * occurs some sort of message is logged to the console.
 */

#ifndef _SYS_INSPECT_H_
#define	_SYS_INSPECT_H_

/*
 * Inspection flags to enable specific thread inspection checks.
 */
#define	INSPECT_SLEEPS		0x00000001	/* Time thread sleeps. */
#define	INSPECT_LOCKS		0x00000002	/* Time thread lock waits. */
#define	INSPECT_PREEMPTIONS	0x00000004	/* Time preemptions. */

#ifdef _KERNEL
/* Don't log events with a duration shorter than this. */
extern long	inspect_minwait_sleep;
extern long	inspect_minwait_lock;
extern long	inspect_minwait_preempt;

long	inspect_duration(const struct bintime *start);
void	inspect_finish(const struct bintime *start, long minwait,
	    const char *action, const char *fmt, ...);
#endif

#endif /* !_SYS_INSPECT_H_ */
/*-
 * A hackish cross between ktrace and kdump that allows for targeted
 * inspection of individual processes and/or threads.  Each thread has
 * a bitmask of enabled inspection events.  When an inspected event
 * occurs some sort of message is logged to the console.
 */

#ifndef _SYS_INSPECT_H_
#define	_SYS_INSPECT_H_

/*
 * Inspection flags to enable specific thread inspection checks.
 */
#define	INSPECT_SLEEPS		0x00000001	/* Time thread sleeps. */
#define	INSPECT_LOCKS		0x00000002	/* Time thread lock waits. */
#define	INSPECT_PREEMPTIONS	0x00000004	/* Time preemptions. */

#ifdef _KERNEL
/* Don't log events with a duration shorter than this. */
extern long	inspect_minwait_sleep;
extern long	inspect_minwait_lock;
extern long	inspect_minwait_preempt;

long	inspect_duration(const struct bintime *start);
void	inspect_finish(const struct bintime *start, long minwait,
	    const char *action, const char *fmt, ...);
#endif

#endif /* !_SYS_INSPECT_H_ */
