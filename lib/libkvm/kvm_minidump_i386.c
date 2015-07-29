/*-
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

/*
 * i386 machine dependent routines for kvm and minidumps.
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/fnv_hash.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <kvm.h>

#include "../../sys/i386/include/minidump.h"

#include <limits.h>

#include "kvm_private.h"
#include "kvm_i386.h"

#define	i386_round_page(x)	roundup2((kvaddr_t)(x), I386_PAGE_SIZE)

struct hpte {
	struct hpte *next;
	uint64_t pa;
	int64_t off;
};

#define HPT_SIZE 1024

struct vmstate {
	struct minidumphdr hdr;
	void *hpt_head[HPT_SIZE];
	uint32_t *bitmap;
	void *ptemap;
};

static void
hpt_insert(kvm_t *kd, uint64_t pa, int64_t off)
{
	struct hpte *hpte;
	uint32_t fnv = FNV1_32_INIT;

	fnv = fnv_32_buf(&pa, sizeof(pa), fnv);
	fnv &= (HPT_SIZE - 1);
	hpte = malloc(sizeof(*hpte));
	hpte->pa = pa;
	hpte->off = off;
	hpte->next = kd->vmst->hpt_head[fnv];
	kd->vmst->hpt_head[fnv] = hpte;
}

static int64_t
hpt_find(kvm_t *kd, uint64_t pa)
{
	struct hpte *hpte;
	uint32_t fnv = FNV1_32_INIT;

	fnv = fnv_32_buf(&pa, sizeof(pa), fnv);
	fnv &= (HPT_SIZE - 1);
	for (hpte = kd->vmst->hpt_head[fnv]; hpte != NULL; hpte = hpte->next) {
		if (pa == hpte->pa)
			return (hpte->off);
	}
	return (-1);
}

static int
inithash(kvm_t *kd, uint32_t *base, int len, off_t off)
{
	uint64_t idx;
	uint32_t bit, bits;
	uint64_t pa;

	for (idx = 0; idx < len / sizeof(*base); idx++) {
		bits = le32toh(base[idx]);
		while (bits) {
			/* XXX: Don't really have an ffs32(). */
			bit = ffs(bits) - 1;
			bits &= ~(1ul << bit);
			pa = (idx * sizeof(*base) * NBBY + bit) * I386_PAGE_SIZE;
			hpt_insert(kd, pa, off);
			off += I386_PAGE_SIZE;
		}
	}
	return (off);
}

static int
_i386_minidump_probe(kvm_t *kd)
{

	return (_i386_probe(kd, 1));
}

static void
_i386_minidump_freevtop(kvm_t *kd)
{
	struct vmstate *vm = kd->vmst;

	if (vm->bitmap)
		free(vm->bitmap);
	if (vm->ptemap)
		free(vm->ptemap);
	free(vm);
	kd->vmst = NULL;
}

static int
_i386_minidump_initvtop(kvm_t *kd)
{
	struct vmstate *vmst;
	off_t off;

	vmst = _kvm_malloc(kd, sizeof(*vmst));
	if (vmst == 0) {
		_kvm_err(kd, kd->program, "cannot allocate vm");
		return (-1);
	}
	kd->vmst = vmst;
	if (pread(kd->pmfd, &vmst->hdr, sizeof(vmst->hdr), 0) !=
	    sizeof(vmst->hdr)) {
		_kvm_err(kd, kd->program, "cannot read dump header");
		return (-1);
	}
	vmst->hdr.version = le32toh(vmst->hdr.version);
	vmst->hdr.msgbufsize = le32toh(vmst->hdr.msgbufsize);
	vmst->hdr.bitmapsize = le32toh(vmst->hdr.bitmapsize);
	vmst->hdr.ptesize = le32toh(vmst->hdr.ptesize);
	vmst->hdr.kernbase = le32toh(vmst->hdr.kernbase);
	vmst->hdr.paemode = le32toh(vmst->hdr.paemode);
	if (strncmp(MINIDUMP_MAGIC, vmst->hdr.magic, sizeof(vmst->hdr.magic)) != 0) {
		_kvm_err(kd, kd->program, "not a minidump for this platform");
		return (-1);
	}
	if (vmst->hdr.version != MINIDUMP_VERSION) {
		_kvm_err(kd, kd->program, "wrong minidump version. expected %d got %d",
		    MINIDUMP_VERSION, vmst->hdr.version);
		return (-1);
	}

	/* Skip header and msgbuf */
	off = I386_PAGE_SIZE + i386_round_page(vmst->hdr.msgbufsize);

	vmst->bitmap = _kvm_malloc(kd, vmst->hdr.bitmapsize);
	if (vmst->bitmap == NULL) {
		_kvm_err(kd, kd->program, "cannot allocate %d bytes for bitmap", vmst->hdr.bitmapsize);
		return (-1);
	}
	if (pread(kd->pmfd, vmst->bitmap, vmst->hdr.bitmapsize, off) !=
	    (ssize_t)vmst->hdr.bitmapsize) {
		_kvm_err(kd, kd->program, "cannot read %d bytes for page bitmap", vmst->hdr.bitmapsize);
		return (-1);
	}
	off += i386_round_page(vmst->hdr.bitmapsize);

	vmst->ptemap = _kvm_malloc(kd, vmst->hdr.ptesize);
	if (vmst->ptemap == NULL) {
		_kvm_err(kd, kd->program, "cannot allocate %d bytes for ptemap", vmst->hdr.ptesize);
		return (-1);
	}
	if (pread(kd->pmfd, vmst->ptemap, vmst->hdr.ptesize, off) !=
	    (ssize_t)vmst->hdr.ptesize) {
		_kvm_err(kd, kd->program, "cannot read %d bytes for ptemap", vmst->hdr.ptesize);
		return (-1);
	}
	off += vmst->hdr.ptesize;

	/* build physical address hash table for sparse pages */
	inithash(kd, vmst->bitmap, vmst->hdr.bitmapsize, off);

	return (0);
}

static int
_i386_minidump_vatop_pae(kvm_t *kd, kvaddr_t va, off_t *pa)
{
	struct vmstate *vm;
	i386_physaddr_pae_t offset;
	i386_pte_pae_t pte;
	int pteindex;
	i386_physaddr_pae_t a;
	off_t ofs;
	i386_pte_pae_t *ptemap;

	vm = kd->vmst;
	ptemap = vm->ptemap;
	offset = va & I386_PAGE_MASK;

	if (va >= vm->hdr.kernbase) {
		pteindex = (va - vm->hdr.kernbase) >> I386_PAGE_SHIFT;
		pte = le64toh(ptemap[pteindex]);
		if ((pte & I386_PG_V) == 0) {
			_kvm_err(kd, kd->program, "_kvm_vatop: pte not valid");
			goto invalid;
		}
		a = pte & I386_PG_FRAME_PAE;
		ofs = hpt_find(kd, a);
		if (ofs == -1) {
			_kvm_err(kd, kd->program, "_kvm_vatop: physical address 0x%jx not in minidump", (uintmax_t)a);
			goto invalid;
		}
		*pa = ofs + offset;
		return (I386_PAGE_SIZE - offset);
	} else {
		_kvm_err(kd, kd->program, "_kvm_vatop: virtual address 0x%jx not minidumped", (uintmax_t)va);
		goto invalid;
	}

invalid:
	_kvm_err(kd, 0, "invalid address (0x%jx)", (uintmax_t)va);
	return (0);
}

static int
_i386_minidump_vatop(kvm_t *kd, kvaddr_t va, off_t *pa)
{
	struct vmstate *vm;
	i386_physaddr_t offset;
	i386_pte_t pte;
	int pteindex;
	i386_physaddr_t a;
	off_t ofs;
	i386_pte_t *ptemap;

	vm = kd->vmst;
	ptemap = vm->ptemap;
	offset = va & I386_PAGE_MASK;

	if (va >= vm->hdr.kernbase) {
		pteindex = (va - vm->hdr.kernbase) >> I386_PAGE_SHIFT;
		pte = le32toh(ptemap[pteindex]);
		if ((pte & I386_PG_V) == 0) {
			_kvm_err(kd, kd->program, "_kvm_vatop: pte not valid");
			goto invalid;
		}
		a = pte & I386_PG_FRAME;
		ofs = hpt_find(kd, a);
		if (ofs == -1) {
			_kvm_err(kd, kd->program, "_kvm_vatop: physical address 0x%jx not in minidump", (uintmax_t)a);
			goto invalid;
		}
		*pa = ofs + offset;
		return (I386_PAGE_SIZE - offset);
	} else {
		_kvm_err(kd, kd->program, "_kvm_vatop: virtual address 0x%jx not minidumped", (uintmax_t)va);
		goto invalid;
	}

invalid:
	_kvm_err(kd, 0, "invalid address (0x%jx)", (uintmax_t)va);
	return (0);
}

static int
_i386_minidump_kvatop(kvm_t *kd, kvaddr_t va, off_t *pa)
{

	if (ISALIVE(kd)) {
		_kvm_err(kd, 0, "kvm_kvatop called in live kernel!");
		return (0);
	}
	if (kd->vmst->hdr.paemode)
		return (_i386_minidump_vatop_pae(kd, va, pa));
	else
		return (_i386_minidump_vatop(kd, va, pa));
}

struct kvm_arch kvm_i386_minidump = {
	.ka_probe = _i386_minidump_probe,
	.ka_initvtop = _i386_minidump_initvtop,
	.ka_freevtop = _i386_minidump_freevtop,
	.ka_kvatop = _i386_minidump_kvatop,
#ifdef __i386__
	.ka_native = 1,
#endif
};

KVM_ARCH(kvm_i386_minidump);
