/*-
 * Copyright (c) 2015 Chelsio Communications, Inc.
 * All rights reserved.
 * Written by: John Baldwin <jhb@FreeBSD.org>
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

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <dev/pci/pcivar.h>

struct t5iov_softc {
	device_t sc_dev;
};

static int
t5iov_probe(device_t dev)
{

	return (ENXIO);
}

static int
t5iov_attach(device_t dev)
{
	struct t5iov_softc *sc;

	sc = device_get_softc(dev);
	sc->sc_dev = dev;
	return (ENXIO);
}

static int
t5iov_detach(device_t dev)
{

	return (ENXIO);
}

static int
t5iov_init_iov(device_t dev, uint16_t num_vfs, const struct nvlist *config)
{

	return (ENXIO);
}

static void
t5iov_uninit_iov(device_t dev)
{
}

static int
t5iov_add_vf(device_t dev, uint16_t vfnum, const struct nvlist *config)
{

	return (ENXIO);
}


static device_method_t t5iov_methods[] = {
	DEVMETHOD(device_probe,		t5iov_probe),
	DEVMETHOD(device_attach,	t5iov_attach),
	DEVMETHOD(device_detach,	t5iov_detach),

	DEVMETHOD(pci_init_iov,		t5iov_init_iov),
	DEVMETHOD(pci_uninit_iov,	t5iov_uninit_iov),
	DEVMETHOD(pci_add_vf,		t5iov_add_vf),

	DEVMETHOD_END
};

static driver_t t5iov_driver = {
	"t5iov",
	t5iov_methods,
	sizeof(struct t5iov_softc)
};

static devclass_t t5iov_devclass;

DRIVER_MODULE(t5iov, pci, t5iov_driver, t5iov_devclass, 0, 0);
MODULE_VERSION(t5iov, 1);

