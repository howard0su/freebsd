/*-
 * Copyright (c) 2014 Chelsio Communications, Inc.
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

/*
 * A simple test program for TCP TOE DDP.  This functions like a simple
 * telnet client accepting line buffered input and sending it to a remote
 * echo server.  It expects to get the same output back before accepting
 * the next line of input.  Uses blocking I/O and TCP_NODELAY.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <err.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

static void
usage(void)
{

	fprintf(stderr, "Usage: ddp <host> [port]\n");
	exit(1);
}

static int
opensock(const char *host, const char *port)
{
	struct addrinfo hints, *res, *res0;
	int error, optval, s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(host, port, &hints, &res0);
	if (error)
		errx(1, "%s", gai_strerror(error));
	s = -1;
	for (res = res0; res != NULL; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s < 0)
			continue;
		if (connect(s, res->ai_addrlen, res->ai_addrlen) < 0) {
			close(s);
			s = -1;
			continue;
		}
		break;
	}
	if (s < 0)
		err(1, "Failed to connect");
	freeaddrinfo(res0);

	/* Set TCP_NODELAY */
	optval = 1;
	if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval))
	    < 0)
		err(1, "setsockopt(TCP_NODELAY)");
	return (s);
}

void
read_plain(int s, const char *data, size_t len)
{
	static char *buf;
	static size_t buflen;
	size_t nread;

	if (buflen < len) {
		buf = realloc(buf, len);
		buflen = malloc_usable_size(buf);
	}

	nread = read(s, buf, buflen);
	if (nread < 0)
		err(1, "socket read");
	if (nread == 0)
		errx(1, "socket EOF");
	if ((size_t)nread != len)
		errx(1, "short read: %zd vs %zu", nread, len);
	if (memcmp(data, buf, len) != 0)
		errx(1, "data mismatch");
}

int
main(int ac, char **av)
{
	char *line;
	size_t linecap, linelen;
	ssize_t nwritten;
	int s;

	if (ac < 2 || ac > 3)
		usage();
	s = opensock(av[1], ac == 3 ? av[2] : "echo");

	line = NULL;
	linecap = 0;
	for (;;) {
		linelen = getline(&line, &linecap, stdin);
		if (linelen < 0)
			err(1, "getline");
		if (linelen == 0)
			break;
		nwritten = write(s, line, linelen);
		if (nwritten < 0)
			err(1, "socket write");
		if ((size_t)nwritten != linelen)
			errx(1, "short write: %zd of %zu", nwritten, linelen);
		read_plain();
	}
	close(s);
	return (0);
}
