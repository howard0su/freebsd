/*-
 * Copyright (c) 2014 John Baldwin <jhb@FreeBSD.org>
 * All rights reserved.
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

#include <sys/types.h>
#include <sys/bus.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

static int
devctl_request(u_long cmd, struct devreq *req)
{
	static int devctl2_fd = -1;

	if (devctl2_fd == -1) {
		devctl2_fd = open("/dev/devctl2", O_RDONLY);
		if (devctl2_fd == -1)
			return (-1);
	}
	return (ioctl(devctl2_fd, cmd, &req));
}

static int
devctl_simple_request(u_long cmd, const char *name)
{
	struct devreq req;

	memset(&req, 0, sizeof(req));
	if (strlcpy(req.dr_name, name, sizeof(req.dr_name)) >=
	    sizeof(req.dr_name)) {
		errno = EINVAL;
		return (-1);
	}
	return (devctl_request(cmd, &req));
}

int
devctl_attach(const char *name)
{

	return (devctl_simple_request(DEV_ATTACH, name));
}

int
devctl_detach(const char *name)
{

	return (devctl_simple_request(DEV_DETACH, name));
}

int
devctl_enable(const char *name)
{

	return (devctl_simple_request(DEV_ENABLE, name));
}

int
devctl_disable(const char *name)
{

	return (devctl_simple_request(DEV_DISABLE, name));
}

int
devctl_suspend(const char *name)
{

	return (devctl_simple_request(DEV_SUSPEND, name));
}

int
devctl_resume(const char *name)
{

	return (devctl_simple_request(DEV_RESUME, name));
}
