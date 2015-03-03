#include <sys/param.h>
#include <sys/inspect.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/taskqueue.h>

struct taskqueue *tq;

static void
inspect_set(int flag)
{
	struct thread *td;

	td = curthread;
	thread_lock(td);
	td->td_inspect |= flag;
	thread_unlock(td);
}

static void
inspect_clear(void)
{
	struct thread *td;

	td = curthread;
	thread_lock(td);
	td->td_inspect = 0;
	thread_unlock(td);
}

static void
test_sleep(void *arg, int pending)
{

	printf("Testing INSPECT_SLEEPS...\n");
	inspect_set(INSPECT_SLEEPS);
	pause("slp", 1);
	inspect_clear();
	printf("    finished\n");
}

static void
test_locks_helper(void *arg, int pending)
{
	struct mtx *m = arg;

	inspect_set(INSPECT_LOCKS);
	mtx_lock(m);
	mtx_unlock(m);
	inspect_clear();
}

static void
test_locks(void *arg, int pending)
{
	struct task extra;
	struct mtx m;
	int i;

	printf("Testing INSPECT_LOCKS...\n");
	mtx_init(&m, "inspect locks test", NULL, MTX_DEF);
	TASK_INIT(&extra, 0, test_locks_helper, &m);
	mtx_lock(&m);
	taskqueue_enqueue(tq, &extra);

	for (i = 0; i < 1000; i++) {
		DELAY(1000);
		mi_switch(SW_VOL, NULL);
	}
	mtx_unlock(&m);
	
	taskqueue_drain(tq, &extra);
	mtx_destroy(&m);
	printf("    finished\n");
}

static void
test_preempt(void *arg, int pending)
{
	struct thread *td;
	int pri;

	printf("Testing INSPECT_PREEMPTIONS...\n");
	td = curthread;
	inspect_set(INSPECT_PREEMPTIONS);
	thread_lock(td);
	td->td_flags |= TDF_NEEDRESCHED;
	pri = td->td_base_pri;
	sched_prio(td, PRI_MIN_IDLE);

	/* Wait for a preemption (which should clear TDF_NEEDRESCHED) .*/
	do {
		thread_unlock(td);
		DELAY(1000);
		thread_lock(td);
	} while (td->td_flags & TDF_NEEDRESCHED);
	sched_prio(td, pri);
	thread_unlock(td);
	inspect_clear();
	printf("    finished\n");
}

struct task tasks[] = {
	{ .ta_func = test_sleep },
	{ .ta_func = test_locks },
	{ .ta_func = test_preempt },
};

#define NTASKS	(sizeof(tasks) / sizeof(struct task))

SYSCTL_DECL(_inspect);

static int
sysctl_inspect_test(SYSCTL_HANDLER_ARGS)
{
	int error, index;

	index = 0;
	error = sysctl_handle_int(oidp, &index, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (index <= 0 || index > NTASKS)
		return (EINVAL);
	taskqueue_enqueue(tq, tasks + index - 1);
	return (0);
}
SYSCTL_PROC(_inspect, OID_AUTO, test, CTLTYPE_INT | CTLFLAG_RW, 0, 0,
    sysctl_inspect_test, "I", "Queue a specific test");

static int
load(void)
{
	tq = taskqueue_create("inspect", M_WAITOK, taskqueue_thread_enqueue,
	    &tq);
	taskqueue_start_threads(&tq, 2, PWAIT, "inspect taskq");
	return (0);
}

static int
unload(void)
{
	int i;

	for (i = 0; i < NTASKS; i++)
		taskqueue_drain(tq, tasks + i);
	taskqueue_free(tq);
	return (0);
}

static int
mod_event(struct module *module, int cmd, void *arg)
{

	switch (cmd) {
	case MOD_LOAD:
		return (load());
	case MOD_UNLOAD:
		return (unload());
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t mod_data = {
	"inspect",
	mod_event,
	0
};

DECLARE_MODULE(inspect, mod_data, SI_SUB_SMP, SI_ORDER_ANY);
