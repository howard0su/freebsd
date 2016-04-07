/*-
 * Copyright (c) 2009-2012 Microsoft Corp.
 * Copyright (c) 2012 NetApp Inc.
 * Copyright (c) 2012 Citrix Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Implements low-level interactions with Hypver-V/Azure
 */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/timetc.h>
#include <sys/kernel.h>
#include <machine/bus.h>
#include <machine/md_var.h>
#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>

#include <machine/intr_machdep.h>
#include <x86/apicvar.h>

#include "hv_vmbus_priv.h"

#define HV_NANOSECONDS_PER_SEC		1000000000L

uint32_t hv_features;
uint32_t hv_recommendations;

static u_int hv_get_timecount(struct timecounter *tc);

static void*		hypercall_page = NULL;

static struct timecounter hv_timecounter = {
	hv_get_timecount, 0, ~0u, HV_NANOSECONDS_PER_SEC/100, "Hyper-V", HV_NANOSECONDS_PER_SEC/100
};

static u_int
hv_get_timecount(struct timecounter *tc)
{
	u_int now = rdmsr(HV_X64_MSR_TIME_REF_COUNT);
	return (now);
}

/**
 * @brief Query the cpuid for presence of windows hypervisor
 */
int
hv_vmbus_query_hypervisor_presence(void)
{
	if (vm_guest != VM_GUEST_HV)
		return (0);

	return (hv_high >= HV_X64_CPUID_MIN && hv_high <= HV_X64_CPUID_MAX);
}

/**
 * @brief Get information of the hypervisor
 * @return 0 if hyperisor info is not present.
 */
static int
hv_vmbus_get_hypervisor_info(void)
{
	u_int regs[4];
	unsigned int maxLeaf;
	unsigned int op;

	op = HV_CPU_ID_FUNCTION_HV_VENDOR_AND_MAX_FUNCTION;
	do_cpuid(op, regs);

	maxLeaf = regs[0];
	op = HV_CPU_ID_FUNCTION_HV_INTERFACE;
	do_cpuid(op, regs);
	if (regs[0] != 0x31237648 /* HV#1 */
		|| maxLeaf < HV_CPU_ID_FUNCTION_MS_HV_IMPLEMENTATION_LIMITS)
		return (0);

	if (maxLeaf >= HV_CPU_ID_FUNCTION_MS_HV_VERSION) {
		op = HV_CPU_ID_FUNCTION_MS_HV_VERSION;
		do_cpuid(op, regs);
		printf("Hyper-V Version: %d.%d.%d [SP%d]\n",
			regs[1] >> 16, regs[1] & 0xffff, regs[0], regs[2]);
	}

	if (maxLeaf >= HV_CPU_ID_FUNCTION_MS_HV_FEATURES) {
		op = HV_CPU_ID_FUNCTION_MS_HV_FEATURES;
		do_cpuid(op, regs);
		hv_features = regs[0];
		if (bootverbose)
			printf("Hyper-V Features: %08X %08X %08X %08X\n",
				regs[0], regs[1], regs[2], regs[3]);
	}

	if (maxLeaf >= HV_CPU_ID_FUNCTION_MS_HV_ENLIGHTENMENT_INFORMATION) {
		op = HV_CPU_ID_FUNCTION_MS_HV_ENLIGHTENMENT_INFORMATION;
		do_cpuid(op, regs);
		hv_recommendations = regs[0];
		if (bootverbose)
			printf("Hyper-V Recommendations: %08X %08X\n", regs[0], regs[1]);
	}

	if (maxLeaf >= HV_CPU_ID_FUNCTION_MS_HV_IMPLEMENTATION_LIMITS) {
		op = HV_CPU_ID_FUNCTION_MS_HV_IMPLEMENTATION_LIMITS;
		do_cpuid(op, regs);
		if (bootverbose)
			printf("Hyper-V Limits: Vcpu:%d Lcpu:%d Int:%d\n",
				regs[0], regs[1], regs[2]);
	}

	if (maxLeaf >= HV_CPU_ID_FUNCTION_MS_HV_HARDWARE_FEATURE) {
		op = HV_CPU_ID_FUNCTION_MS_HV_HARDWARE_FEATURE;
		do_cpuid(op, regs);
		if (bootverbose)
			printf("Hyper-V HW Features: %08x AMD: %08x\n",
				regs[0], regs[3]);
	}

	return (1);
}

/**
 * @brief Invoke the specified hypercall
 */
static uint64_t
hv_vmbus_do_hypercall(uint64_t control, void* input, void* output)
{
#ifdef __x86_64__
	uint64_t hv_status = 0;
	uint64_t input_address = (input) ? hv_get_phys_addr(input) : 0;
	uint64_t output_address = (output) ? hv_get_phys_addr(output) : 0;

	__asm__ __volatile__ ("mov %0, %%r8" : : "r" (output_address): "r8");
	__asm__ __volatile__ ("call *%3" : "=a"(hv_status):
				"c" (control), "d" (input_address),
				"m" (hypercall_page));
	return (hv_status);
#else
	uint32_t control_high = control >> 32;
	uint32_t control_low = control & 0xFFFFFFFF;
	uint32_t hv_status_high = 1;
	uint32_t hv_status_low = 1;
	uint64_t input_address = (input) ? hv_get_phys_addr(input) : 0;
	uint32_t input_address_high = input_address >> 32;
	uint32_t input_address_low = input_address & 0xFFFFFFFF;
	uint64_t output_address = (output) ? hv_get_phys_addr(output) : 0;
	uint32_t output_address_high = output_address >> 32;
	uint32_t output_address_low = output_address & 0xFFFFFFFF;

	__asm__ __volatile__ ("call *%8" : "=d"(hv_status_high),
				"=a"(hv_status_low) : "d" (control_high),
				"a" (control_low), "b" (input_address_high),
				"c" (input_address_low),
				"D"(output_address_high),
				"S"(output_address_low), "m" (hypercall_page));
	return (hv_status_low | ((uint64_t)hv_status_high << 32));
#endif /* __x86_64__ */
}

static void
hv_idle_hook(sbintime_t sbt)
{
	rdmsr(HV_X64_MSR_GUEST_IDLE);
}

static void
hv_lapic_eoi(void)
{
	wrmsr(HV_X64_MSR_EOI, 0);
}

/**
 *  @brief Main initialization routine.
 *
 *  This routine must be called
 *  before any other routines in here are called
 */
static int
hv_vmbus_init(void* context)
{
	hv_vmbus_x64_msr_hypercall_contents	hypercall_msr;
	void*					virt_addr;

	if (vm_guest != VM_GUEST_HV)
		return (ENOTSUP);

	if (!hv_vmbus_get_hypervisor_info())
		return (ENOTSUP);

	if (!(hv_features & HV_MSR_FEATURE_HYPERCALL))
		return (ENOTSUP);

	/*
	 * Write our OS info
	 */
	uint64_t os_guest_info = HV_FREEBSD_GUEST_ID;
	wrmsr(HV_X64_MSR_GUEST_OS_ID, os_guest_info);

	/*
	 * See if the hypercall page is already set
	 */
	hypercall_msr.as_uint64_t = rdmsr(HV_X64_MSR_HYPERCALL);
	virt_addr = malloc(PAGE_SIZE, M_DEVBUF, M_WAITOK | M_ZERO);

	hypercall_msr.u.enable = 1;
	hypercall_msr.u.guest_physical_address =
	    (hv_get_phys_addr(virt_addr) >> PAGE_SHIFT);
	wrmsr(HV_X64_MSR_HYPERCALL, hypercall_msr.as_uint64_t);

	/*
	 * Confirm that hypercall page did get set up
	 */
	hypercall_msr.as_uint64_t = 0;
	hypercall_msr.as_uint64_t = rdmsr(HV_X64_MSR_HYPERCALL);

	if (!hypercall_msr.u.enable)
	    goto cleanup;

	hypercall_page = virt_addr;

	if (hv_features & HV_MSR_FEATURE_REF_COUNT) {
		/* register virtual timecounter */
		tc_init(&hv_timecounter);
	}

	if (hv_features & HV_MSR_FEATURE_IDLESTATE) {
		cpu_idle_hook = hv_idle_hook;
	}

	if ((hv_features & HV_MSR_FEATURE_APIC) &&
		(hv_recommendations & HV_REC_USE_MSR_FOR_APIC)) {
		apic_ops.eoi = hv_lapic_eoi;
	}

	return (0);

	cleanup:
	if (hypercall_msr.u.enable) {
		hypercall_msr.as_uint64_t = 0;
		wrmsr(HV_X64_MSR_HYPERCALL, hypercall_msr.as_uint64_t);
	}

	free(virt_addr, M_DEVBUF);
	return (ENOTSUP);
}

/**
 * @brief Cleanup routine, called normally during driver unloading or exiting
 */
static void
hv_vmbus_cleanup(void* context)
{
	hv_vmbus_x64_msr_hypercall_contents hypercall_msr;

	if (hypercall_page != NULL) {
		hypercall_msr.as_uint64_t = 0;
		wrmsr(HV_X64_MSR_HYPERCALL,
					hypercall_msr.as_uint64_t);
		free(hypercall_page, M_DEVBUF);
		hypercall_page = NULL;
	}
}

/**
 * @brief Post a message using the hypervisor message IPC.
 * (This involves a hypercall.)
 */
hv_vmbus_status
hv_vmbus_post_msg_via_msg_ipc(
	hv_vmbus_connection_id	connection_id,
	hv_vmbus_msg_type	message_type,
	void*			payload,
	size_t			payload_size)
{
	struct alignedinput {
	    uint64_t alignment8;
	    hv_vmbus_input_post_message msg;
	};

	hv_vmbus_input_post_message*	aligned_msg;
	hv_vmbus_status 		status;
	size_t				addr;

	if (payload_size > HV_MESSAGE_PAYLOAD_BYTE_COUNT)
	    return (EMSGSIZE);

	addr = (size_t) malloc(sizeof(struct alignedinput), M_DEVBUF,
			    M_ZERO | M_NOWAIT);
	KASSERT(addr != 0,
	    ("Error VMBUS: malloc failed to allocate message buffer!"));
	if (addr == 0)
	    return (ENOMEM);

	aligned_msg = (hv_vmbus_input_post_message*)
	    (HV_ALIGN_UP(addr, HV_HYPERCALL_PARAM_ALIGN));

	aligned_msg->connection_id = connection_id;
	aligned_msg->message_type = message_type;
	aligned_msg->payload_size = payload_size;
	memcpy((void*) aligned_msg->payload, payload, payload_size);

	status = hv_vmbus_do_hypercall(
		    HV_CALL_POST_MESSAGE, aligned_msg, 0) & 0xFFFF;

	free((void *) addr, M_DEVBUF);
	return (status);
}

/**
 * @brief Signal an event on the specified connection using the hypervisor
 * event IPC. (This involves a hypercall.)
 */
hv_vmbus_status
hv_vmbus_signal_event(void *con_id)
{
	hv_vmbus_status status;

	status = hv_vmbus_do_hypercall(
		    HV_CALL_SIGNAL_EVENT,
		    con_id,
		    0) & 0xFFFF;

	return (status);
}

SYSINIT(hv_init, SI_SUB_HYPERVISOR, SI_ORDER_FIRST, hv_vmbus_init, NULL);
SYSUNINIT(hv_cleanup, SI_SUB_HYPERVISOR, SI_ORDER_ANY, hv_vmbus_cleanup, NULL);
