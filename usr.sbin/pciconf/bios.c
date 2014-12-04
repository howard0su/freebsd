/*-
 * XXX: Copyright
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/pciio.h>
#include <sys/mman.h>
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include <dev/pci/pcireg.h>
#include <machine/pc/bios.h>

#include "pciconf.h"

#define	BIOS_START	0xe0000
#define	BIOS_SIZE	0x20000

static int mem_fd = -1;

/*
 * Locate a signature within a BIOS region.
 */ 
static void *
bios_sigsearch(uint32_t start, const char *sig, int siglen, int paralen,
    int sigofs, int (*validate)(void *))
{
	static char *bios_base, *bios_end;
	char *p;

	if (mem_fd < 0) {
		mem_fd = open("/dev/mem", O_RDONLY);
		if (mem_fd < 0)
			err(1, "open(/dev/mem)");
	
		/* Map the BIOS. */
		bios_base = mmap(NULL, BIOS_SIZE, PROT_READ, MAP_SHARED, mem_fd,
		    BIOS_START);
		if (bios_base == MAP_FAILED)
			err(1, "mmap(/dev/mem)");
		bios_end = bios_base + BIOS_SIZE;
	}

	if (start < BIOS_START)
		return (NULL);
	for (p = bios_base + start - BIOS_START;
	     (p + sigofs + siglen) < bios_end; p += paralen) {
		if (bcmp(p + sigofs, sig, siglen) == 0 && validate(p))
			return (p);
	}
	return (NULL);
}

static void *
bios_map(uint32_t start, size_t length)
{
	void *p;

	p = mmap(NULL, length, PROT_READ, MAP_SHARED, mem_fd, start);
	if (p == MAP_FAILED)
		err(1, "mmap(/dev/mem)");
	return (p);
}

/* $PIR support */

#define	PIR_BASE	0xf0000

static struct PIR_table *pir_table;
static int pir_opened, pir_count;

static int
valid_pir(void *buf)
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

static void
pir_open(void)
{

	/* Look for $PIR and then _PIR. */
	pir_table = bios_sigsearch(PIR_BASE, "$PIR", 4, 16, 0, valid_pir);
	if (pir_table == NULL)
		pir_table = bios_sigsearch(PIR_BASE, "$PIR", 4, 16, 0,
		    valid_pir);
	if (pir_table != NULL)
		pir_count = (pir_table->pt_header.ph_length -
		    sizeof(struct PIR_header)) / 
		    sizeof(struct PIR_entry);

	pir_opened = 1;
}

static int
pir_slot(struct pci_conf *p)
{
	struct PIR_entry *pe;
	int i;

	/* $PIR only works for domain 0. */
	if (p->pc_sel.pc_domain != 0)
		return (-2);

	if (!pir_opened)
		pir_open();

	if (pir_table == NULL)
		return (-2);

	/* Find a matching entry. */
	for (i = 0, pe = pir_table->pt_entry; i < pir_count; i++, pe++) {
		if (pe->pe_bus == p->pc_sel.pc_bus &&
		    pe->pe_device == p->pc_sel.pc_dev) {
			if (pe->pe_slot != 0)
				return (pe->pe_slot);
			return (-1);
		}
	}
	return (-1);
}

static int
pir_find_slot(struct pcisel *pc, int slot)
{
	struct PIR_entry *pe;
	int i;

	if (slot == 0)
		return (0);

	if (!pir_opened)
		pir_open();

	if (pir_table == NULL)
		return (0);

	/* Find a matching entry. */
	for (i = 0, pe = pir_table->pt_entry; i < pir_count; i++, pe++) {
		/* Ignore entries for bus 0 device 0. */
		if (pe->pe_bus == 0 && pe->pe_device == 0)
			continue;
		if (pe->pe_slot == slot) {
			pc->pc_domain = 0;
			pc->pc_bus = pe->pe_bus;
			pc->pc_dev = pe->pe_device;
			pc->pc_func = 0;
			return (1);
		}
	}
	return (0);
}

/* SMBIOS parsing code */

struct system_slot {
	uint8_t		type;
	uint8_t		length;
	uint16_t	handle;
	uint8_t		slot_designation;
	uint8_t		slot_type;
	uint8_t		slot_data_bus_width;
	uint8_t		current_usage;
	uint8_t		slot_length;
	uint16_t	slot_id;
	uint8_t		slot_characteristics1;
	uint8_t		slot_characteristics2;
	uint16_t	segment_group_number;
	uint8_t		bus_number;
	uint8_t		device_function_number;
} __packed;

static struct smbios_eps *smbios_eps;
static struct smbios_structure_header *smbios_table, *smbios_table_end;
static int smbios_opened, smbios_slots_valid;

static int
valid_eps(void *buf)
{
	struct smbios_eps *e;
	uint8_t *ptr;
	uint8_t cksum;
	int i;

	e = buf;
	ptr = buf;
	cksum = 0;
	for (i = 0; i < e->length; i++) {
		cksum += ptr[i];
	}

	return (cksum == 0);
}

static void
smbios_walk_table(void (*callback)(struct smbios_structure_header *, void *),
    void *arg)
{
	struct smbios_structure_header *s;
	char *p;
	int i;

	for (s = smbios_table, i = 0; s < smbios_table_end &&
	     i < smbios_eps->number_structures; i++) {
		callback(s, arg);

		/*
		 * Look for a double-nul after the end of the
		 * formatted area of this structure.
		 */
		p = (char *)s + s->length;
		while (!(p[0] == 0 && p[1] == 0))
			p++;

		/*
		 * Skip over the double-nul to the start of the next
		 * structure.
		 */
		p += 2;
		s = (struct smbios_structure_header *)p;
	}
}

static int
smbios_system_slot_is_pci(struct smbios_structure_header *s)
{
	struct system_slot *slot;

	if (s->type != 9 || s->length < 0xc)
		return (0);
	slot = (struct system_slot *)s;
	switch (slot->slot_type) {
	case 0x06:	/* PCI */
	case 0x0e:	/* PCI 66Mhz */
	case 0x0f:	/* AGP */
	case 0x10:	/* AGP 2X */
	case 0x11:	/* AGP 4X */
	case 0x12:	/* PCI-X */
	case 0x13:	/* AGP 8X */
	case 0xa5:	/* PCI-e */
	case 0xa6:	/* PCI-e x1 */
	case 0xa7:	/* PCI-e x2 */
	case 0xa8:	/* PCI-e x4 */
	case 0xa9:	/* PCI-e x8 */
	case 0xaa:	/* PCI-e x16 */
	case 0xab:	/* PCI-e Gen 2 */
	case 0xac:	/* PCI-e Gen 2 x1 */
	case 0xad:	/* PCI-e Gen 2 x2 */
	case 0xae:	/* PCI-e Gen 2 x4 */
	case 0xaf:	/* PCI-e Gen 2 x8 */
	case 0xb0:	/* PCI-e Gen 2 x16 */
	case 0xb1:	/* PCI-e Gen 3 */
	case 0xb2:	/* PCI-e Gen 3 x1 */
	case 0xb3:	/* PCI-e Gen 3 x2 */
	case 0xb4:	/* PCI-e Gen 3 x4 */
	case 0xb5:	/* PCI-e Gen 3 x8 */
	case 0xb6:	/* PCI-e Gen 3 x16 */
		return (1);
	default:
		return (0);
	}
}

/*
 * Don't trust the slot mapping if all slots have a
 * domain/bus/dev/func of all zeroes.
 */
static void
smbios_check(struct smbios_structure_header *s, void *arg)
{
	struct system_slot *slot;

	if (!smbios_system_slot_is_pci(s) ||
	    s->length < sizeof(struct system_slot))
		return;
	slot = (struct system_slot *)s;
	if (slot->segment_group_number != 0 || slot->bus_number != 0 ||
	    slot->device_function_number != 0)
		smbios_slots_valid = 1;
}

static void
smbios_open(void)
{

	smbios_eps = bios_sigsearch(SMBIOS_START, SMBIOS_SIG, SMBIOS_LEN,
	    SMBIOS_STEP, SMBIOS_OFF, valid_eps);
	if (smbios_eps != NULL) {
		smbios_table = bios_map(smbios_eps->structure_table_address,
		    smbios_eps->structure_table_length);
		smbios_table_end = (struct smbios_structure_header *)
		    ((char *)smbios_table + smbios_eps->structure_table_length);
	}

	smbios_walk_table(smbios_check, NULL);
	smbios_opened = 1;
}

struct smbios_slot_data {
	struct pci_conf *p;
	int slot;
};

static void
smbios_slot_helper(struct smbios_structure_header *s, void *arg)
{
	struct smbios_slot_data *data;
	struct system_slot *slot;

	if (!smbios_system_slot_is_pci(s))
		return;
	assert(s->length >= sizeof(struct system_slot));
	data = arg;
	slot = (struct system_slot *)s;
	if (slot->segment_group_number == data->p->pc_sel.pc_domain &&
	    slot->bus_number == data->p->pc_sel.pc_bus &&
	    slot->device_function_number >> 3 == data->p->pc_sel.pc_dev)
		data->slot = slot->slot_id;
}

int
smbios_slot(struct pci_conf *p)
{
	struct smbios_slot_data data;

	if (!smbios_opened)
		smbios_open();

	if (!smbios_slots_valid)
		return (-1);

	data.p = p;
	data.slot = -1;
	smbios_walk_table(smbios_slot_helper, &data);
	return (data.slot);
}

struct smbios_list_slots_data {
	int fd;
	int count;
	int maxlen;
};

static const char *
smbios_describe_slot(struct system_slot *slot)
{
	static char buf[16];
	int gen, len, log_width, phys_width, subtype;

	switch (slot->slot_type) {
	case 0x06:	/* PCI */
	case 0x0e:	/* PCI 66Mhz */
		return ("PCI");
	case 0x0f:	/* AGP */
		return ("AGP");
	case 0x10:	/* AGP 2X */
		return ("AGP 2X");
	case 0x11:	/* AGP 4X */
		return ("AGP 4X");
	case 0x12:	/* PCI-X */
		return ("PCI-X");
	case 0x13:	/* AGP 8X */
		return ("AGP 8X");
	}

	/* PCI-express */
	switch (slot->slot_type) {
	case 0xa5:	/* PCI-e */
	case 0xa6:	/* PCI-e x1 */
	case 0xa7:	/* PCI-e x2 */
	case 0xa8:	/* PCI-e x4 */
	case 0xa9:	/* PCI-e x8 */
	case 0xaa:	/* PCI-e x16 */
		subtype = slot->slot_type - 0xa5;
		gen = 0;
		break;
	case 0xab:	/* PCI-e Gen 2 */
	case 0xac:	/* PCI-e Gen 2 x1 */
	case 0xad:	/* PCI-e Gen 2 x2 */
	case 0xae:	/* PCI-e Gen 2 x4 */
	case 0xaf:	/* PCI-e Gen 2 x8 */
	case 0xb0:	/* PCI-e Gen 2 x16 */
		subtype = slot->slot_type - 0xab;
		gen = 2;
		break;
	case 0xb1:	/* PCI-e Gen 3 */
	case 0xb2:	/* PCI-e Gen 3 x1 */
	case 0xb3:	/* PCI-e Gen 3 x2 */
	case 0xb4:	/* PCI-e Gen 3 x4 */
	case 0xb5:	/* PCI-e Gen 3 x8 */
	case 0xb6:	/* PCI-e Gen 3 x16 */
		subtype = slot->slot_type - 0xb1;
		gen = 3;
		break;
	}
	switch (slot->slot_data_bus_width) {
	case 0x8:
		log_width = 1;
		break;
	case 0x9:
		log_width = 2;
		break;
	case 0xa:
		log_width = 4;
		break;
	case 0xb:
		log_width = 8;
		break;
	case 0xd:
		log_width = 16;
		break;
	default:
		log_width = 0;
		break;
	}
	switch (subtype) {
	case 0:
		phys_width = log_width;
		break;
	default:
		phys_width = 1 << (subtype - 1);
		break;
	}
	len = snprintf(buf, sizeof(buf), "PCIE");
	if (gen != 0)
		len += snprintf(buf + len, sizeof(buf) - len, "%d", gen);
	if (log_width != 0)
		len += snprintf(buf + len, sizeof(buf) - len, " x%d",
		    log_width);
	else
		len += snprintf(buf + len, sizeof(buf) - len, " x??");
	if (log_width != phys_width)
		len += snprintf(buf + len, sizeof(buf) - len, "/x%d",
		    phys_width);
	return (buf);
}

static void
smbios_count_slots(struct smbios_structure_header *s, void *arg)
{
	struct smbios_list_slots_data *data;
	struct system_slot *slot;
	int len;

	if (!smbios_system_slot_is_pci(s))
		return;
	data = arg;
	slot = (struct system_slot *)s;
	data->count++;
	len = snprintf(NULL, 0, "Slot %d (%s):", slot->slot_id,
	    smbios_describe_slot(slot));
	if (len > data->maxlen)
		data->maxlen = len;
}

static int
pcie_link_width(struct pci_conf *p, int fd)
{
	uint16_t flags;
	uint8_t ptr;

	ptr = pci_find_cap(fd, p, PCIY_EXPRESS);
	if (ptr == 0)
		return (0);

	flags = read_config(fd, &p->pc_sel, ptr + PCIR_EXPRESS_LINK_STA, 2);
	return ((flags & PCIM_LINK_STA_WIDTH) >> 4);
}

static void
smbios_list_devices(struct pcisel *pc, int fd)
{
	struct pci_match_conf match;
	struct pci_conf confs[PCI_FUNCMAX + 1];
	struct pci_conf_io conf_io;
	int i, link_width, matches;

	memset(&match, 0, sizeof(match));
	memset(&conf_io, 0, sizeof(conf_io));
	match.pc_sel = *pc;
	match.flags = PCI_GETCONF_MATCH_DOMAIN | PCI_GETCONF_MATCH_BUS |
	    PCI_GETCONF_MATCH_DEV;
	conf_io.pat_buf_len = sizeof(match);
	conf_io.num_patterns = 1;
	conf_io.patterns = &match;
	conf_io.match_buf_len = sizeof(confs);
	conf_io.matches = confs;
	if (ioctl(fd, PCIOCGETCONF, &conf_io) < 0)
		err(1, "ioctl(PCIOCGETCONF)");
	if (conf_io.status != PCI_GETCONF_LAST_DEVICE &&
	    conf_io.status != PCI_GETCONF_MORE_DEVS) {
		printf(" error\n");
		return;
	}
	if (conf_io.num_matches == 0) {
		printf(" empty\n");
		return;
	}

	/* See if any attached devices are in the list and print them out. */
	matches = 0;
	link_width = 0;
	for (i = 0; i < conf_io.num_matches; i++) {
		if (link_width == 0)
			link_width = pcie_link_width(&confs[i], fd);
		if (confs[i].pd_name[0] == '\0')
			continue;
		printf(" %s%d", confs[i].pd_name, confs[i].pd_unit);
		matches++;
	}

	/*
	 * No attached devices.  It is too hard to come up with noneX names,
	 * so resort to printing out selectors instead.
	 */
	if (matches == 0) {
		for (i = 0; i < conf_io.num_matches; i++) {
			printf(" pci%d:%d:%d:%d", confs[i].pc_sel.pc_domain,
			    confs[i].pc_sel.pc_bus, confs[i].pc_sel.pc_dev,
			    confs[i].pc_sel.pc_func);
		}
	}

	if (link_width != 0)
		printf(" (x%d)", link_width);
	printf("\n");
}

static void
smbios_list_slots_helper(struct smbios_structure_header *s, void *arg)
{
	struct smbios_list_slots_data *data;
	struct system_slot *slot;
	struct pcisel pc;
	int found, len;

	/*
	 * This ignores slot_current_usage as it has been found to be
	 * incorrect on some systems.  Instead, if no devices match
	 * the address found in $PIR or the slot is not found in $PIR,
	 * assume the slot is empty.
	 */
	if (!smbios_system_slot_is_pci(s))
		return;
	data = arg;
	slot = (struct system_slot *)s;
	len = printf("Slot %d (%s):", slot->slot_id,
	    smbios_describe_slot(slot));
	for (; len < data->maxlen; len++)
		putchar(' ');
	if (pir_find_slot(&pc, slot->slot_id))
		smbios_list_devices(&pc, data->fd);
	else
		printf(" empty\n");
}

int
smbios_list_slots(int fd)
{
	struct smbios_list_slots_data data;

	if (!smbios_opened)
		smbios_open();

	data.fd = fd;
	data.count = 0;
	data.maxlen = 0;
	smbios_walk_table(smbios_count_slots, &data);
	if (data.count != 0)
		smbios_walk_table(smbios_list_slots_helper, &data);
	return (data.count != 0);
}

int
bios_slot(struct pci_conf *p)
{
	int slot;

	/* Prefer $PIR if it exists. */
	slot = pir_slot(p);
	if (slot == -2)
		slot = smbios_slot(p);
	return (slot);
}

int
bios_list_slots(int fd)
{

	return (smbios_list_slots(fd));
}

