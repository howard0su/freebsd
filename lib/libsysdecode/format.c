/*-
 * Copyright (c) 2015 John H. Baldwin <jhb@FreeBSD.org>
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

#include <errno.h>
#include <sysdecode.h>

#include "local.h"

enum sysdecode_int_format _sd_int_format;
enum sysdecode_flags_format _sd_flags_format;

enum sysdecode_flags_format
sysdecode_get_flags_format(void)
{

	return (_sd_flags_format);
}

enum sysdecode_int_format
sysdecode_get_int_format(void)
{

	return (_sd_int_format);
}

int
sysdecode_set_flags_format(enum sysdecode_flags_format format)
{

	switch (format) {
	case KDUMP:
	case TRUSS:
		_sd_flags_format = format;
		return (0);
	}
	return (EINVAL);
}

int
sysdecode_set_int_format(enum sysdecode_int_format format)
{

	switch (format) {
	case DECIMAL:
	case HEXADECIMAL:
		_sd_int_format = format;
		return (0);
	}
	return (EINVAL);
}
