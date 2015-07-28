/*-
 * Copyright (c) 1989, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software developed by the Computer Systems
 * Engineering group at Lawrence Berkeley Laboratory under DARPA contract
 * BG 91-66 and contributed to Berkeley.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
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

#if defined(LIBC_SCCS) && !defined(lint)
#if 0
static char sccsid[] = "@(#)kvm_hp300.c	8.1 (Berkeley) 6/4/93";
#endif
#endif /* LIBC_SCCS and not lint */

/*
 * i386 machine dependent routines for kvm.  Hopefully, the forthcoming
 * vm code will one day obsolete this module.
 */

#include <sys/param.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <nlist.h>
#include <gelf.h>
#include <kvm.h>

#include <limits.h>

#include "kvm_private.h"

typedef uint32_t	i386_physaddr_t;
typedef uint32_t	i386_pte_t;
typedef uint64_t	i386_physaddr_pae_t;
typedef	uint64_t	i386_pte_pae_t;

#define	I386_PAGE_SHIFT	12
#define	I386_PAGE_SIZE	(1<<I386_PAGE_SHIFT)
#define	I386_PAGE_MASK	(I386_PAGE_SIZE-1)
#define	I386_PDRSHIFT	22
#define	I386_NPTEPG	(I386_PAGE_SIZE/sizeof(i386_pte_t))
#define	I386_NBPDR	(1<<I386_PDRSHIFT)
#define	I386_PDRSHIFT_PAE	21
#define	I386_NPTEPG_PAE	(I386_PAGE_SIZE/sizeof(i386_pte_pae_t))
#define	I386_NBPDR_PAE	(1<<PDRSHIFT_PAE)

#ifdef __i386__
_Static_assert(PAGE_SHIFT == I386_PAGE_SHIFT, "PAGE_SHIFT mismatch");
_Static_assert(PAGE_SIZE == I386_PAGE_SIZE, "PAGE_SIZE mismatch");
_Static_assert(PAGE_MASK == I386_PAGE_MASK, "PAGE_MASK mismatch");
_Static_assert(PDRSHIFT == I386_PDRSHIFT, "PDRSHIFT mismatch");
#endif

struct vmstate {
	void		*PTD;
	int		pae;
	size_t		phnum;
	GElf_Phdr	*phdr;
};

/*
 * Read the ELF header and save a copy of the program headers.
 */
static int
_i386_maphdrs(kvm_t *kd)
{
	struct vmstate *vm = kd->vmst;
	GElf_Ehdr ehdr;
	Elf *elf;
	int i;

	elf = elf_begin(kd->pmfd, ELF_C_READ, NULL);
	if (elf == NULL) {
		_kvm_err(kd, kd->program, "%s", elf_errmsg());
		return (-1);
	}
	if (elf_kind(elf) != ELF_K_ELF) {
		_kvm_err(kd, kd->program, "invalid core");
		goto bad;
	}
	if (gelf_getehdr(elf, &ehdr) == NULL) {
		_kvm_err(kd, kd->program, "%s", elf_errmsg());
		goto bad;
	}
	if (ehdr.e_ident[EI_CLASS] != ELFCLASS32 || ehdr.e_machine != EM_386) {
		_kvm_err(kd, kd->program, "invalid core");
		goto bad;
	}

	if (elf_getphdrnum(elf, &vm->phnum) == -1) {
		_kvm_err(kd, kd->program, "%s", elf_errmsg());
		goto bad;
	}

	vm->phdr = calloc(vm->phnum, sizeof(*vm->phdr));
	if (vm->phdr == NULL) {
		_kvm_err(kd, kd->program, "failed to allocate phdrs");
		goto bad;
	}

	for (i = 0; i < vm->phnum; i++) {
		if (gelf_getphdr(elf, i, &vm->phdr[i]) == NULL) {
			_kvm_err(kd, kd->program, "%s", elf_errmsg());
			goto bad;
		}
	}
	elf_end(elf);
	return (0);

bad:
	elf_end(elf);
	return (-1);
}

/*
 * Translate a physical memory address to a file-offset in the crash-dump.
 */
static size_t
_kvm_pa2off(kvm_t *kd, uint64_t pa, off_t *ofs)
{
	struct vmstate *vm = kd->vmst;
	GElf_Phdr *p;
	int n;

	if (kd->rawdump) {
		*ofs = pa;
		return (I386_PAGE_SIZE - ((size_t)pa & I386_PAGE_MASK));
	}

	p = vm->phdr;
	n = vm->phnum;
	while (n && (pa < p->p_paddr || pa >= p->p_paddr + p->p_memsz))
		p++, n--;
	if (n == 0)
		return (0);
	*ofs = (pa - p->p_paddr) + p->p_offset;
	return (I386_PAGE_SIZE - ((size_t)pa & I386_PAGE_MASK));
}

static void
_i386_freevtop(kvm_t *kd)
{
	struct vmstate *vm = kd->vmst;

	if (vm->PTD)
		free(vm->PTD);
	free(vm->phdr);
	free(vm);
	kd->vmst = NULL;
}

static int
_i386_probe(kvm_t *kd)
{
	Elf *elf;
	GElf_Ehdr ehdr;
	char minihdr[8];

	/* First check the kernel to ensure it is an i386 image. */
	elf = elf_begin(kd->nlfd, ELF_C_READ, NULL);
	if (elf == NULL)
		return (0);
	if (elf_kind(elf) != ELF_K_ELF)
		goto bad;
	if (gelf_getehdr(elf, &ehdr) == NULL)
		goto bad;
	if (ehdr.e_ident[EI_CLASS] != ELFCLASS32)
		goto bad;
	if (ehdr.e_machine != EM_386)
		goto bad;
	elf_end(elf);

	/* Now, check to see if this is a minidump. */
	if (!kd->rawdump && pread(kd->pmfd, &minihdr, 8, 0) == 8 &&
	    memcmp(&minihdr, "minidump", 8) == 0)
		return (0);

	return (1);
bad:
	elf_end(elf);
	return (0);
}

static int
_i386_initvtop(kvm_t *kd)
{
	struct nlist nl[2];
	u_long pa;
	u_long kernbase;
	char		*PTD;
	Elf_Ehdr	*ehdr;
	size_t		hdrsz;
	int		i;

	kd->vmst = (struct vmstate *)_kvm_malloc(kd, sizeof(struct vmstate));
	if (kd->vmst == NULL) {
		_kvm_err(kd, kd->program, "cannot allocate vm");
		return (-1);
	}
	kd->vmst->PTD = 0;

	if (kd->rawdump == 0) {
		if (_kvm_maphdrs(kd) == -1)
			return (-1);
	}

	nl[0].n_name = "kernbase";
	nl[1].n_name = 0;

	if (kvm_nlist(kd, nl) != 0)
		kernbase = KERNBASE;	/* for old kernels */
	else
		kernbase = nl[0].n_value;

	nl[0].n_name = "IdlePDPT";
	nl[1].n_name = 0;

	if (kvm_nlist(kd, nl) == 0) {
		uint64_t pa64;

		if (kvm_read(kd, (nl[0].n_value - kernbase), &pa,
		    sizeof(pa)) != sizeof(pa)) {
			_kvm_err(kd, kd->program, "cannot read IdlePDPT");
			return (-1);
		}
		PTD = _kvm_malloc(kd, 4 * I386_PAGE_SIZE);
		for (i = 0; i < 4; i++) {
			if (kvm_read(kd, pa + (i * sizeof(pa64)), &pa64,
			    sizeof(pa64)) != sizeof(pa64)) {
				_kvm_err(kd, kd->program, "Cannot read PDPT");
				free(PTD);
				return (-1);
			}
			if (kvm_read(kd, pa64 & PG_FRAME_PAE,
			    PTD + (i * I386_PAGE_SIZE), I386_PAGE_SIZE) != (I386_PAGE_SIZE)) {
				_kvm_err(kd, kd->program, "cannot read PDPT");
				free(PTD);
				return (-1);
			}
		}
		kd->vmst->PTD = PTD;
		kd->vmst->pae = 1;
	} else {
		nl[0].n_name = "IdlePTD";
		nl[1].n_name = 0;

		if (kvm_nlist(kd, nl) != 0) {
			_kvm_err(kd, kd->program, "bad namelist");
			return (-1);
		}
		if (kvm_read(kd, (nl[0].n_value - kernbase), &pa,
		    sizeof(pa)) != sizeof(pa)) {
			_kvm_err(kd, kd->program, "cannot read IdlePTD");
			return (-1);
		}
		PTD = _kvm_malloc(kd, I386_PAGE_SIZE);
		if (kvm_read(kd, pa, PTD, I386_PAGE_SIZE) != I386_PAGE_SIZE) {
			_kvm_err(kd, kd->program, "cannot read PTD");
			return (-1);
		}
		kd->vmst->PTD = PTD;
		kd->vmst->pae = 0;
	}
	return (0);
}

static int
_i386_vatop(kvm_t *kd, u_long va, off_t *pa)
{
	struct vmstate *vm;
	u_long offset;
	u_long pte_pa;
	u_long pde_pa;
	pd_entry_t pde;
	pt_entry_t pte;
	u_long pdeindex;
	u_long pteindex;
	size_t s;
	u_long a;
	off_t ofs;
	uint32_t *PTD;

	vm = kd->vmst;
	PTD = (uint32_t *)vm->PTD;
	offset = va & (I386_PAGE_SIZE - 1);

	/*
	 * If we are initializing (kernel page table descriptor pointer
	 * not yet set) then return pa == va to avoid infinite recursion.
	 */
	if (PTD == 0) {
		s = _kvm_pa2off(kd, va, pa);
		if (s == 0) {
			_kvm_err(kd, kd->program,
			    "_kvm_vatop: bootstrap data not in dump");
			goto invalid;
		} else
			return (I386_PAGE_SIZE - offset);
	}

	pdeindex = va >> PDRSHIFT;
	pde = PTD[pdeindex];
	if (((u_long)pde & PG_V) == 0) {
		_kvm_err(kd, kd->program, "_kvm_vatop: pde not valid");
		goto invalid;
	}

	if ((u_long)pde & PG_PS) {
	      /*
	       * No second-level page table; ptd describes one 4MB page.
	       * (We assume that the kernel wouldn't set PG_PS without enabling
	       * it cr0).
	       */
#define	I386_PAGE4M_MASK	(NBPDR - 1)
#define	PG_FRAME4M	(~I386_PAGE4M_MASK)
		pde_pa = ((u_long)pde & PG_FRAME4M) + (va & I386_PAGE4M_MASK);
		s = _kvm_pa2off(kd, pde_pa, &ofs);
		if (s == 0) {
			_kvm_err(kd, kd->program,
			    "_kvm_vatop: 4MB page address not in dump");
			goto invalid;
		}
		*pa = ofs;
		return (NBPDR - (va & I386_PAGE4M_MASK));
	}

	pteindex = (va >> I386_PAGE_SHIFT) & (NPTEPG-1);
	pte_pa = ((u_long)pde & PG_FRAME) + (pteindex * sizeof(pde));

	s = _kvm_pa2off(kd, pte_pa, &ofs);
	if (s < sizeof pte) {
		_kvm_err(kd, kd->program, "_kvm_vatop: pdpe_pa not found");
		goto invalid;
	}

	/* XXX This has to be a physical address read, kvm_read is virtual */
	if (lseek(kd->pmfd, ofs, 0) == -1) {
		_kvm_syserr(kd, kd->program, "_kvm_vatop: lseek");
		goto invalid;
	}
	if (read(kd->pmfd, &pte, sizeof pte) != sizeof pte) {
		_kvm_syserr(kd, kd->program, "_kvm_vatop: read");
		goto invalid;
	}
	if (((u_long)pte & PG_V) == 0) {
		_kvm_err(kd, kd->program, "_kvm_kvatop: pte not valid");
		goto invalid;
	}

	a = ((u_long)pte & PG_FRAME) + offset;
	s =_kvm_pa2off(kd, a, pa);
	if (s == 0) {
		_kvm_err(kd, kd->program, "_kvm_vatop: address not in dump");
		goto invalid;
	} else
		return (I386_PAGE_SIZE - offset);

invalid:
	_kvm_err(kd, 0, "invalid address (0x%lx)", va);
	return (0);
}

static int
_i386_vatop_pae(kvm_t *kd, u_long va, off_t *pa)
{
	struct vmstate *vm;
	uint64_t offset;
	uint64_t pte_pa;
	uint64_t pde_pa;
	uint64_t pde;
	uint64_t pte;
	u_long pdeindex;
	u_long pteindex;
	size_t s;
	uint64_t a;
	off_t ofs;
	uint64_t *PTD;

	vm = kd->vmst;
	PTD = (uint64_t *)vm->PTD;
	offset = va & (I386_PAGE_SIZE - 1);

	/*
	 * If we are initializing (kernel page table descriptor pointer
	 * not yet set) then return pa == va to avoid infinite recursion.
	 */
	if (PTD == 0) {
		s = _kvm_pa2off(kd, va, pa);
		if (s == 0) {
			_kvm_err(kd, kd->program,
			    "_kvm_vatop_pae: bootstrap data not in dump");
			goto invalid;
		} else
			return (I386_PAGE_SIZE - offset);
	}

	pdeindex = va >> PDRSHIFT_PAE;
	pde = PTD[pdeindex];
	if (((u_long)pde & PG_V) == 0) {
		_kvm_err(kd, kd->program, "_kvm_kvatop_pae: pde not valid");
		goto invalid;
	}

	if ((u_long)pde & PG_PS) {
	      /*
	       * No second-level page table; ptd describes one 2MB page.
	       * (We assume that the kernel wouldn't set PG_PS without enabling
	       * it cr0).
	       */
#define	I386_PAGE2M_MASK	(NBPDR_PAE - 1)
#define	PG_FRAME2M	(~I386_PAGE2M_MASK)
		pde_pa = ((u_long)pde & PG_FRAME2M) + (va & I386_PAGE2M_MASK);
		s = _kvm_pa2off(kd, pde_pa, &ofs);
		if (s == 0) {
			_kvm_err(kd, kd->program,
			    "_kvm_vatop: 2MB page address not in dump");
			goto invalid;
		}
		*pa = ofs;
		return (NBPDR_PAE - (va & I386_PAGE2M_MASK));
	}

	pteindex = (va >> I386_PAGE_SHIFT) & (NPTEPG_PAE-1);
	pte_pa = ((uint64_t)pde & PG_FRAME_PAE) + (pteindex * sizeof(pde));

	s = _kvm_pa2off(kd, pte_pa, &ofs);
	if (s < sizeof pte) {
		_kvm_err(kd, kd->program, "_kvm_vatop_pae: pdpe_pa not found");
		goto invalid;
	}

	/* XXX This has to be a physical address read, kvm_read is virtual */
	if (lseek(kd->pmfd, ofs, 0) == -1) {
		_kvm_syserr(kd, kd->program, "_kvm_vatop_pae: lseek");
		goto invalid;
	}
	if (read(kd->pmfd, &pte, sizeof pte) != sizeof pte) {
		_kvm_syserr(kd, kd->program, "_kvm_vatop_pae: read");
		goto invalid;
	}
	if (((uint64_t)pte & PG_V) == 0) {
		_kvm_err(kd, kd->program, "_kvm_vatop_pae: pte not valid");
		goto invalid;
	}

	a = ((uint64_t)pte & PG_FRAME_PAE) + offset;
	s =_kvm_pa2off(kd, a, pa);
	if (s == 0) {
		_kvm_err(kd, kd->program,
		    "_kvm_vatop_pae: address not in dump");
		goto invalid;
	} else
		return (I386_PAGE_SIZE - offset);

invalid:
	_kvm_err(kd, 0, "invalid address (0x%lx)", va);
	return (0);
}

int
_i386_kvatop(kvm_t *kd, u_long va, off_t *pa)
{

	if (ISALIVE(kd)) {
		_kvm_err(kd, 0, "vatop called in live kernel!");
		return (0);
	}
	if (kd->vmst->pae)
		return (_i386_vatop_pae(kd, va, pa));
	else
		return (_i386_vatop(kd, va, pa));
}

struct kvm_arch kvm_i386 = {
	.ka_probe = _i386_probe,
	.ka_initvtop = _i386_initvtop,
	.ka_freevtop = _i386_freevtop,
	.ka_kvatop = _i386_kvatop,
#ifdef __i386__
	.ka_native = 1,
#endif
};

KVM_ARCH(kvm_i386);
