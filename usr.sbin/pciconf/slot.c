/*-
 * XXX: Copyright
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/usr.sbin/pciconf/slot.c 256592 2013-08-26 15:41:29Z gnn $");

#include <sys/types.h>
#include <sys/pciio.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include "pathnames.h"
#include "pciconf.h"

void
list_slot(struct pci_conf *p)
{
#if defined(__i386__) || defined(__amd64__)
	int slot;

	slot = bios_slot(p);
	if (slot >= 0)
		printf("    slot       = %d\n", slot);
#endif /* __i386__ || __amd64__ */
}

void
list_slots(void)
{
#if defined(__i386__) || defined(__amd64__)
	int fd;

	fd = open(_PATH_DEVPCI, O_RDWR, 0);
	if (fd < 0)
		err(1, "%s", _PATH_DEVPCI);
	if (bios_list_slots(fd))
		return;
#endif
	fprintf(stderr, "Unable to determine slot information\n");
	exit(1);
}
