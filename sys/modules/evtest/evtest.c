/*
 * Copyright (c) 2003
 *	John Baldwin <jhb@FreeBSD.org>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY JOHN BALDWIN AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL JOHN BALDWIN OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * This module is used to test eventhandlers.
 */

#define	INVARIANTS
#define	INVARIANT_SUPPORT
#define	KTR
#define	KTR_COMPILE (KTR_EVH|KTR_PROC)

#include <sys/param.h>
#include <sys/condvar.h>
#include <sys/errno.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/unistd.h>
#include <sys/sched.h>
#include <sys/sema.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#define	MAX_EVENT	11
#define	NUM_THREADS	2

#define	EVENT_TYPE_BROADCAST	0x1

static eventhandler_tag first_tag, foo_tag;
static struct cv event_cv, broadcast_cv, event_recvd, sync_cv;
static struct mtx event_mtx;
static struct sema evtest_sema;
static int event, broadcast_count, num_threads, sync_threads;

struct thread_info {
	struct thread *ti_td;
	int ti_event;
} threads[NUM_THREADS];

struct proc *kproc;

struct event_info {
	const char *ei_help;
	int ei_flags;
} events[MAX_EVENT + 1] = {
	{ NULL },		/* 0 - no event */
	{ "help" },
	{ "invoke handlers on both threads", EVENT_TYPE_BROADCAST },
	{ "hello world", EVENT_TYPE_BROADCAST },
	{ "dump list" },
	{ "clear list" },
	{ "add print foo handler" },
	{ "add wait handler" },
	{ "add post handler" },
	{ "add dump handler" },
	{ "add removefoo handler" },
	{ "add synchronization handler" },
};

static int	mod_event(struct module *module, int cmd, void *arg);
static int	load(void *arg);
static int	unload(void *arg);
static int	shutdown(void *arg);
static void	event_thread(void *arg);

TAILQ_HEAD(eventhandler_entry_head, eventhandler_entry);

typedef void (evtest_fn)(void *);
EVENTHANDLER_DECLARE(evtest, evtest_fn *);

static evtest_fn evtest_print, evtest_wait, evtest_post, evtest_dumplist,
    evtest_removefoo, evtest_sync;

struct evtest_fninfo {
	evtest_fn *ev_fn;
	const char *ev_name;
};

struct evtest_fninfo evtest_info[] = {
	{ &evtest_print, "evtest_print" },
	{ &evtest_wait, "evtest_wait" },
	{ &evtest_post, "evtest_post" },
	{ &evtest_dumplist, "evtest_dumplist" },
	{ &evtest_removefoo, "evtest_removefoo" },
	{ &evtest_sync, "evtest_sync" },
	{ NULL, NULL }
};
	
SYSCTL_NODE(_debug, OID_AUTO, ev, CTLFLAG_RD, 0, "eventhandler tree");

static int
evtest_postevent(int new_event)
{
	struct event_info *ei;
	int i;

	if (new_event < 1 || new_event > MAX_EVENT)
		return (EINVAL);

	ei = &events[new_event];
printf("%s: posting event %d (%s, %d)\n", __func__, new_event, ei->ei_help,
    ei->ei_flags);
	mtx_lock(&event_mtx);
	KASSERT(event == 0, ("event %d was unhandled", event));
	if (ei->ei_flags & EVENT_TYPE_BROADCAST) {
		for (i = 0; i < NUM_THREADS; i++) {
			if (threads[i].ti_td != NULL)
				threads[i].ti_event = new_event;
			broadcast_count++;
		}
		event = -1;
		cv_broadcast(&event_cv);
	} else {
		event = new_event;
		cv_signal(&event_cv);
	}
	cv_wait(&event_recvd, &event_mtx);
	mtx_unlock(&event_mtx);
	return (0);
}

static int
sysctl_debug_ev_test(SYSCTL_HANDLER_ARGS)
{
	int error, i = 0;

	error = sysctl_handle_int(oidp, &i, sizeof(i), req);
	if (error == 0 && req->newptr != NULL)
		error = evtest_postevent(i);
	return (error);
}
SYSCTL_PROC(_debug_ev, OID_AUTO, test, CTLTYPE_INT | CTLFLAG_RW, 0, 0,
    sysctl_debug_ev_test, "I", "");

static int
evtest_lookupthread(void)
{
	int i;

	for (i = 0; i < NUM_THREADS; i++)
		if (threads[i].ti_td == curthread)
			return (i);
	return (-1);
}

static const char *
evtest_funcname(evtest_fn *func)
{
	struct evtest_fninfo *ef;

	ef = evtest_info;
	while (ef->ev_fn != NULL) {
		if (ef->ev_fn == func)
			return (ef->ev_name);
		ef++;
	}
	return ("unknown");
}

static void
evtest_print(void *arg)
{
	const char *string;

	string = (const char *)arg;
	printf("thread %d: \"%s\"\n", evtest_lookupthread(), string);
}

static void
evtest_wait(void *arg)
{

	printf("thread %d: waiting\n", evtest_lookupthread());
	sema_wait(&evtest_sema);
}

static void
evtest_post(void *arg)
{

	printf("thread %d: posting to other thread\n", evtest_lookupthread());
	sema_post(&evtest_sema);
}

static void
evtest_removefoo(void *arg)
{

	mtx_lock(&event_mtx);
	if (foo_tag != NULL) {
		EVENTHANDLER_DEREGISTER(evtest, foo_tag);
		foo_tag = NULL;
	}
	mtx_unlock(&event_mtx);
}

static void
evtest_sync(void *arg)
{

	mtx_lock(&event_mtx);
	sync_threads++;
	if (sync_threads == num_threads)
		cv_broadcast(&sync_cv);
	else
		cv_wait(&sync_cv, &event_mtx);
	mtx_unlock(&event_mtx);
}

/*
 * Yes, this is really gross and greatly violates the eventhandler
 * abstraction.  Deal.
 */
static void
evtest_dumplist(void *arg)
{
	struct eventhandler_entry *ee;
	struct eventhandler_entry_evtest *ev;

	printf("thread %d: dump:\n", evtest_lookupthread());
	ee = (struct eventhandler_entry *)first_tag;
	if (ee != NULL) {
		while (TAILQ_PREV(ee, eventhandler_entry_head, ee_link) != NULL)
			ee = TAILQ_PREV(ee, eventhandler_entry_head, ee_link);
		for (; ee != NULL; ee = TAILQ_NEXT(ee, ee_link)) {
			ev = (struct eventhandler_entry_evtest *)ee;
			printf("  pri %d, func %s()\n", ee->ee_priority,
			    evtest_funcname(ev->eh_func));
		}
	}
}

static void
evtest_clearlist(void)
{
	struct eventhandler_entry *ee;

	ee = (struct eventhandler_entry *)first_tag;
	if (ee != NULL) {
		while (TAILQ_PREV(ee, eventhandler_entry_head, ee_link) != NULL)
			ee = TAILQ_PREV(ee, eventhandler_entry_head, ee_link);
		for (; ee != NULL; ee = TAILQ_NEXT(ee, ee_link))
			EVENTHANDLER_DEREGISTER(evtest, ee);
		first_tag = NULL;
	}
}

static void
event_thread(void *arg)
{
	int ev;
	int *td_ev = (int *)arg;

	while (1) {
		mtx_lock(&event_mtx);
		if (event == -1) {
			broadcast_count--;
			if (broadcast_count == 0)
				cv_broadcast(&broadcast_cv);
			else {
				cv_wait(&broadcast_cv, &event_mtx);
				MPASS(broadcast_count == 0);
			}
		}
		event = 0;
		sync_threads = 0;
		cv_signal(&event_recvd);
		while ((ev = event) == 0)
			cv_wait(&event_cv, &event_mtx);
		mtx_unlock(&event_mtx);
		/* Give sysctl time to finish. */
		pause("delay", hz / 5);
		if (ev >= 1 && ev <= MAX_EVENT && events[ev].ei_help != NULL)
			printf("evtest: %s\n", events[ev].ei_help);
		switch (ev) {
		case -1:
			/* Handle broadcast events. */
			switch (*td_ev) {
			case -1:
				mtx_lock(&event_mtx);
				broadcast_count--;
				if (broadcast_count == 0)
					cv_broadcast(&broadcast_cv);
				mtx_unlock(&event_mtx);
				printf("%s: thread %d dying\n", __func__,
				    evtest_lookupthread());
				kthread_exit();
				break;
			case 0:
				printf("%s: thread %d doing nothing\n",
				    __func__, evtest_lookupthread());
				break;
			case 2:
				EVENTHANDLER_INVOKE(evtest);
				break;
			case 3:
				printf("thread %d: hello world\n",
				    evtest_lookupthread());
				break;
			default:
				printf("Unknown broadcast event %d\n", *td_ev);
			}
			*td_ev = 0;
			break;
		case 1:
			for (ev = 1; ev <= MAX_EVENT; ev++)
				if (events[ev].ei_help != NULL)
					printf("%4d  %s\n", ev,
					    events[ev].ei_help);
			break;
		case 4:
			evtest_dumplist(NULL);
			break;
		case 5:
			evtest_clearlist();
			break;
		case 6:
			foo_tag = first_tag = EVENTHANDLER_REGISTER(evtest,
			    evtest_print, "foo", 5);
			break;
		case 7:
			first_tag = EVENTHANDLER_REGISTER(evtest, evtest_wait,
			    NULL, 5);
			break;
		case 8:
			first_tag = EVENTHANDLER_REGISTER(evtest, evtest_post,
			    NULL, 5);
			break;
		case 9:
			first_tag = EVENTHANDLER_REGISTER(evtest,
			    evtest_dumplist, NULL, 5);
			break;
		case 10:
			first_tag = EVENTHANDLER_REGISTER(evtest,
			    evtest_removefoo, NULL, 5);
			break;
		case 11:
			first_tag = EVENTHANDLER_REGISTER(evtest,
			    evtest_sync, NULL, 5);
			break;
		default:
			panic("event %d is bogus\n", event);
		}
	}
}

static int
thread_create(int i, const char *name)
{
	struct thread *td;
	int error;

	if (i < 0 || i >= NUM_THREADS || threads[i].ti_td != NULL)
		return (EINVAL);
	error = kproc_kthread_add(event_thread, &threads[i].ti_event, &kproc,
	    &threads[i].ti_td, RFSTOPPED, 0, "evtest", name);
	if (error)
		return (error);
	td = threads[i].ti_td;
	thread_lock(td);
	sched_prio(td, PRI_MIN_IDLE);
	TD_SET_CAN_RUN(td);
	sched_add(td, SRQ_BORING);
	thread_unlock(td);
	mtx_lock(&event_mtx);
	num_threads++;
	mtx_unlock(&event_mtx);
	return (0);
}

static void
thread_destroy(int i)
{

	if (i < 0 || i >= NUM_THREADS || threads[i].ti_td == NULL)
		return;
	mtx_assert(&event_mtx, MA_OWNED);
	printf("%s: killing thread %d\n", __func__, i);
	threads[i].ti_event = -1;
	broadcast_count = num_threads;
	event = -1;
	cv_broadcast(&event_cv);
	msleep(threads[i].ti_td, &event_mtx, PWAIT, "evtstun", 0);
	threads[i].ti_td = NULL;
	num_threads--;
	if (event != 0 && num_threads > 0)
		cv_wait(&event_recvd, &event_mtx);
}

static void
cleanup(void)
{
	int i;

	evtest_clearlist();
	mtx_lock(&event_mtx);
	for (i = 0; i < NUM_THREADS; i++)
		thread_destroy(i);
	cv_destroy(&sync_cv);
	cv_destroy(&broadcast_cv);
	sema_destroy(&evtest_sema);
	mtx_destroy(&event_mtx);
	cv_destroy(&event_recvd);
	cv_destroy(&event_cv);
}

static int
load(void *arg)
{
	int error;

	event = 0;
	broadcast_count = 0;
	num_threads = 0;
	mtx_init(&event_mtx, "evtest event", NULL, MTX_DEF);
	cv_init(&event_cv, "evtest");
	cv_init(&event_recvd, "evrcvd");
	sema_init(&evtest_sema, 1, "evtest semaphore");
	cv_init(&broadcast_cv, "evbcast");
	cv_init(&sync_cv, "evsync");
	error = thread_create(0, "event thread 0");
	if (error) {
		cleanup();
		return (error);
	}
	error = thread_create(1, "event thread 1");
	if (error) {
		cleanup();
		return (error);
	}
	return (0);
}

static int
unload(void *arg)
{

	cleanup();
	return (0);
}


static int
shutdown(void *arg)
{

	return (0);
}

static int
mod_event(struct module *module, int cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		error = load(arg);
		break;
	case MOD_UNLOAD:
		error = unload(arg);
		break;
	case MOD_SHUTDOWN:
		error = shutdown(arg);
		break;
	default:
		error = EINVAL;
		break;
	}
	return (error);
}

static moduledata_t mod_data = {
	"evtest",
	mod_event,
	0
};

DECLARE_MODULE(evtest, mod_data, SI_SUB_SMP, SI_ORDER_ANY);
