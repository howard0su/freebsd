/*-
 * XXX: Copyright
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/usr.sbin/pciconf/slot.c 256592 2013-08-26 15:41:29Z gnn $");

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/pciio.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pciconf.h"

#if defined(__i386__) || defined(__amd64__)

#include <machine/pc/bios.h>

#define	BIOS_BASE	0xf0000
#define	BIOS_LEN	0x10000

#include <machine/pc/bios.h>

static struct PIR_table *pir_table;
static int pir_opened, pir_count;

static int
valid_table(void *buf)
{
	struct PIR_header *ph;
	char *p, *pend, sum;

	ph = buf;

	/* Require version 1.0. */
	if (ph->ph_version != 0x0100)
		return (0);

	/* Table size must be > 32 and a multiple of 16. */
	if (ph->ph_length <= 32 || ph->ph_length % 16 != 0)
		return (0);

	/* Verify checksum. */
	sum = 0;
	p = buf;
	pend = p + ph->ph_length;
	while (p < pend)
		sum += *p++;

	return (sum == 0);
}

static int
find_table(const char *sig, char *base)
{
	char *p;

	for (p = base; p < base + BIOS_LEN; p += 16) {
		if (strncmp(p, sig, 4) == 0 && valid_table(p)) {
			pir_table = (struct PIR_table *)p;
			pir_count = (pir_table->pt_header.ph_length -
			    sizeof(struct PIR_header)) / 
			    sizeof(struct PIR_entry);
			return (1);
		}
	}

	return (0);
}

static void
pir_open(void)
{
	char *p;
	int fd;

	fd = open("/dev/mem", O_RDONLY);
	if (fd < 0)
		err(1, "open(/dev/mem)");

	/* Map the BIOS. */
	p = mmap(NULL, BIOS_LEN, PROT_READ, MAP_SHARED, fd, BIOS_BASE);
	if (p == MAP_FAILED)
		err(1, "mmap(/dev/mem)");

	/* Look for $PIR and then _PIR. */
	if (!find_table("$PIR", p))
		find_table("_PIR", p);

	close(fd);
	pir_opened = 1;
}

void
list_slot(struct pci_conf *p)
{
	struct PIR_entry *pe;
	int i;

	/* $PIR only works for domain 0. */
	if (p->pc_sel.pc_domain != 0)
		return;

	if (!pir_opened)
		pir_open();

	if (pir_table == NULL)
		return;

	/* Find a matching entry. */
	for (i = 0, pe = pir_table->pt_entry; i < pir_count; i++, pe++) {
		if (pe->pe_bus == p->pc_sel.pc_bus &&
		    pe->pe_device == p->pc_sel.pc_dev) {
			if (pe->pe_slot != 0)
				printf("    slot       = %u\n", pe->pe_slot);
			return;
		}
	}
}

#else /* __i386__ || __amd64__ */

void
list_slot(struct pci_conf *p)
{
}

#endif /* __i386__ || __amd64__ */
