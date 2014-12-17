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

#include <devctl.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

static void
usage(void)
{
	fprintf(stderr, "%s\n%s\n%s\n%s\n%s\n%s\n",
	    "usage: devctl attach device",
	    "       devctl detach device",
	    "       devctl disable device",
	    "       devctl enable device",
	    "       devctl suspend device",
	    "       devctl resume device");
	exit(1);
}

int
main(int argc, char *argv[])
{

	if (argc != 3)
		usage();
	if (strcasecmp(argv[1], "attach") == 0) {
		if (devctl_attach(argv[2]) < 0)
			err(1, "Failed to attach %s", argv[2]);
	} else if (strcasecmp(argv[1], "detach") == 0) {
		if (devctl_detach(argv[2]) < 0)
			err(1, "Failed to detach %s", argv[2]);
	} else if (strcasecmp(argv[1], "disable") == 0) {
		if (devctl_disable(argv[2]) < 0)
			err(1, "Failed to disable %s", argv[2]);
	} else if (strcasecmp(argv[1], "enable") == 0) {
		if (devctl_enable(argv[2]) < 0)
			err(1, "Failed to enable %s", argv[2]);
	} else if (strcasecmp(argv[1], "suspend") == 0) {
		if (devctl_suspend(argv[2]) < 0)
			err(1, "Failed to suspend %s", argv[2]);
	} else if (strcasecmp(argv[1], "resume") == 0) {
		if (devctl_resume(argv[2]) < 0)
			err(1, "Failed to resume %s", argv[2]);
	} else
		usage();
	return (0);
}
