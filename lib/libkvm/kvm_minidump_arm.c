/*-
 * Copyright (c) 2008 Semihalf, Grzegorz Bernacki
 * Copyright (c) 2006 Peter Wemm
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
 *
 * From: FreeBSD: src/lib/libkvm/kvm_minidump_i386.c,v 1.2 2006/06/05 08:51:14
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

/*
 * ARM machine dependent routines for kvm and minidumps.
 */

#include <sys/endian.h>
#include <sys/param.h>
#if 0
#ifndef CROSS_LIBKVM
#include <sys/user.h>
#endif
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/fnv_hash.h>
#include <nlist.h>
#endif
#include <kvm.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../sys/arm/include/minidump.h"

#include "kvm_private.h"
#include "kvm_arm.h"

#define	arm_round_page(x)	roundup2((kvaddr_t)(x), ARM_PAGE_SIZE)

struct vmstate {
	struct		minidumphdr hdr;
	struct		hpt hpt;
	uint32_t	*bitmap;
	void		*ptemap;
	unsigned char	ei_data;
};

static uint32_t
_arm32toh(kvm_t *kd, uint32_t val)
{

	if (kd->vmst->ei_data == ELFDATA2LSB)
		return (le32toh(val));
	else
		return (be32toh(val));
}

static int
inithash(kvm_t *kd, uint32_t *base, int len, off_t off)
{
	uint64_t idx;
	uint32_t bits;
	arm_physaddr_t pa;

	for (idx = 0; idx < len / sizeof(*base); idx++) {
		bits = _arm32toh(kd, base[idx]);
		pa = (idx * sizeof(*base) * NBBY) * ARM_PAGE_SIZE;
		for (; bits != 0; bits >>= 1, pa += ARM_PAGE_SIZE) {
			if ((bits & 1) == 0)
				continue;
			_kvm_hpt_insert(&kd->vmst->hpt, pa, off);
			off += ARM_PAGE_SIZE;
		}
	}
	return (off);
}

static int
_arm_minidump_probe(kvm_t *kd)
{

	return (_kvm_probe_elf_kernel(kd, ELFCLASS32, EM_ARM) &&
	    _kvm_is_minidump(kd));
}

static void
_arm_minidump_freevtop(kvm_t *kd)
{
	struct vmstate *vm = kd->vmst;

	_kvm_hpt_free(&vm->hpt);
	if (vm->bitmap)
		free(vm->bitmap);
	if (vm->ptemap)
		free(vm->ptemap);
	free(vm);
	kd->vmst = NULL;
}

static int
_arm_minidump_initvtop(kvm_t *kd)
{
	struct vmstate *vmst;
	off_t off;

	vmst = _kvm_malloc(kd, sizeof(*vmst));
	if (vmst == 0) {
		_kvm_err(kd, kd->program, "cannot allocate vm");
		return (-1);
	}

	kd->vmst = vmst;
	vmst->ei_data = _kvm_elf_kernel_data_encoding(kd);
	if (!(vmst->ei_data == ELFDATA2LSB || vmst->ei_data == ELFDATA2MSB)) {
		_kvm_err(kd, kd->program, "cannot determine endianness");
		return (-1);
	}

	if (pread(kd->pmfd, &vmst->hdr,
	    sizeof(vmst->hdr), 0) != sizeof(vmst->hdr)) {
		_kvm_err(kd, kd->program, "cannot read dump header");
		return (-1);
	}

	if (strncmp(MINIDUMP_MAGIC, vmst->hdr.magic,
	    sizeof(vmst->hdr.magic)) != 0) {
		_kvm_err(kd, kd->program, "not a minidump for this platform");
		return (-1);
	}
	vmst->hdr.version = _arm32toh(kd, vmst->hdr.version);
	if (vmst->hdr.version != MINIDUMP_VERSION) {
		_kvm_err(kd, kd->program, "wrong minidump version. "
		    "Expected %d got %d", MINIDUMP_VERSION, vmst->hdr.version);
		return (-1);
	}
	vmst->hdr.msgbufsize = _arm32toh(kd, vmst->hdr.msgbufsize);
	vmst->hdr.bitmapsize = _arm32toh(kd, vmst->hdr.bitmapsize);
	vmst->hdr.ptesize = _arm32toh(kd, vmst->hdr.ptesize);
	vmst->hdr.kernbase = _arm32toh(kd, vmst->hdr.kernbase);

	/* Skip header and msgbuf */
	off = ARM_PAGE_SIZE + arm_round_page(vmst->hdr.msgbufsize);

	vmst->bitmap = _kvm_malloc(kd, vmst->hdr.bitmapsize);
	if (vmst->bitmap == NULL) {
		_kvm_err(kd, kd->program, "cannot allocate %d bytes for "
		    "bitmap", vmst->hdr.bitmapsize);
		return (-1);
	}

	if (pread(kd->pmfd, vmst->bitmap, vmst->hdr.bitmapsize, off) !=
	    (ssize_t)vmst->hdr.bitmapsize) {
		_kvm_err(kd, kd->program, "cannot read %d bytes for page bitmap",
		    vmst->hdr.bitmapsize);
		return (-1);
	}
	off += arm_round_page(vmst->hdr.bitmapsize);

	vmst->ptemap = _kvm_malloc(kd, vmst->hdr.ptesize);
	if (vmst->ptemap == NULL) {
		_kvm_err(kd, kd->program, "cannot allocate %d bytes for "
		    "ptemap", vmst->hdr.ptesize);
		return (-1);
	}

	if (pread(kd->pmfd, vmst->ptemap, vmst->hdr.ptesize, off) !=
	    (ssize_t)vmst->hdr.ptesize) {
		_kvm_err(kd, kd->program, "cannot read %d bytes for ptemap",
		    vmst->hdr.ptesize);
		return (-1);
	}

	off += vmst->hdr.ptesize;

	/* Build physical address hash table for sparse pages */
	inithash(kd, vmst->bitmap, vmst->hdr.bitmapsize, off);

	return (0);
}

static int
_arm_minidump_kvatop(kvm_t *kd, kvaddr_t va, off_t *pa)
{
	struct vmstate *vm;
	arm_pt_entry_t pte;
	arm_physaddr_t offset, a;
	kvaddr_t pteindex;
	off_t ofs;
	arm_pt_entry_t *ptemap;

	if (ISALIVE(kd)) {
		_kvm_err(kd, 0, "_arm_minidump_kvatop called in live kernel!");
		return (0);
	}

	vm = kd->vmst;
	ptemap = vm->ptemap;

	if (va >= vm->hdr.kernbase) {
		pteindex = (va - vm->hdr.kernbase) >> ARM_PAGE_SHIFT;
		pte = _arm32toh(kd, ptemap[pteindex]);
		if (!pte) {
			_kvm_err(kd, kd->program,
			    "_arm_minidump_kvatop: pte not valid");
			goto invalid;
		}
		if ((pte & ARM_L2_TYPE_MASK) == ARM_L2_TYPE_L) {
			offset = va & ARM_L2_L_OFFSET;
			a = pte & ARM_L2_L_FRAME;
		} else if ((pte & ARM_L2_TYPE_MASK) == ARM_L2_TYPE_S) {
			offset = va & ARM_L2_S_OFFSET;
			a = pte & ARM_L2_S_FRAME;
		} else
			goto invalid;

		ofs = _kvm_hpt_find(&vm->hpt, a);
		if (ofs == -1) {
			_kvm_err(kd, kd->program, "_arm_minidump_kvatop: "
			    "physical address 0x%jx not in minidump",
			    (uintmax_t)a);
			goto invalid;
		}

		*pa = ofs + offset;
		return (ARM_PAGE_SIZE - offset);

	} else
		_kvm_err(kd, kd->program, "_arm_minidump_kvatop: virtual "
		    "address 0x%jx not minidumped", (uintmax_t)va);

invalid:
	_kvm_err(kd, 0, "invalid address (0x%jx)", (uintmax_t)va);
	return (0);
}

struct kvm_arch kvm_arm_minidump = {
	.ka_probe = _arm_minidump_probe,
	.ka_initvtop = _arm_minidump_initvtop,
	.ka_freevtop = _arm_minidump_freevtop,
	.ka_kvatop = _arm_minidump_kvatop,
	.ka_native = _arm_native,
};

KVM_ARCH(kvm_arm_minidump);
