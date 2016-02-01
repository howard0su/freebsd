/*-
 * Copyright (c) 2012
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
 * This module is used to benchmark eventhandlers.
 */

#include <sys/param.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

static int	mod_event(struct module *module, int cmd, void *arg);
static int	load(void *arg);
static int	unload(void *arg);
static int	shutdown(void *arg);

typedef void (*evbench_fn)(void *);
EVENTHANDLER_DECLARE(evbench, evbench_fn);

static EVENTHANDLER_FAST_DEFINE(evbench);

static SYSCTL_NODE(_debug, OID_AUTO, evbench, CTLFLAG_RD, 0,
    "eventhandler tree");

static int loops = 1;
SYSCTL_INT(_debug_evbench, OID_AUTO, loops, CTLFLAG_RW, &loops, 0,
    "Iterations to perform for each run");

static void
null_handler(void *arg)
{
}

static void
benchmark(void)
{
	uint64_t start, times[4];
	int i;

	if (loops <= 0)
		return;
	sched_pin();

	/* "Fast" invocation with no handlers. */
	start = rdtsc();
	for (i = 0; i < loops; i++)
		EVENTHANDLER_FAST_INVOKE(evbench);
	times[0] = rdtsc() - start;

	/* Default invocation with no handlers. */
	start = rdtsc();
	for (i = 0; i < loops; i++)
		EVENTHANDLER_INVOKE(evbench);
	times[1] = rdtsc() - start;

	/* Add null handler. */
	(void)EVENTHANDLER_REGISTER(evbench, null_handler, NULL, 0);

	/* "Fast" invocation with one handler. */
	start = rdtsc();
	for (i = 0; i < loops; i++)
		EVENTHANDLER_FAST_INVOKE(evbench);
	times[2] = rdtsc() - start;

	/* "Slow" invocation with one handler. */
	start = rdtsc();
	for (i = 0; i < loops; i++)
		EVENTHANDLER_INVOKE(evbench);
	times[3] = rdtsc() - start;

	sched_unpin();

	/* Cleanup. */
	EVENTHANDLER_DEREGISTER(fast_evbench, NULL);
	EVENTHANDLER_DEREGISTER(evbench, NULL);

	printf("empty fast: %ju (%ju)\n", times[0], times[0] / loops);
	printf("empty slow: %ju (%ju)\n", times[1], times[1] / loops);
	printf("null fast : %ju (%ju)\n", times[2], times[2] / loops);
	printf("null slow : %ju (%ju)\n", times[3], times[3] / loops);
}


static int
sysctl_debug_evbench_run(SYSCTL_HANDLER_ARGS)
{
	int error, i = 0;

	error = sysctl_handle_int(oidp, &i, sizeof(i), req);
	if (error == 0 && req->newptr != NULL)
		benchmark();
	return (error);
}
SYSCTL_PROC(_debug_evbench, OID_AUTO, run, CTLTYPE_INT | CTLFLAG_RW, 0, 0,
    sysctl_debug_evbench_run, "I", "Run benchmarks");

static int
load(void *arg)
{

	return (0);
}

static int
unload(void *arg)
{

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
	"evbench",
	mod_event,
	0
};

DECLARE_MODULE(evbench, mod_data, SI_SUB_SMP, SI_ORDER_ANY);
