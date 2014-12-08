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

#define _WITH_GETLINE
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <err.h>
#include <malloc_np.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
		if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
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

static void
check_for_toe(int s)
{
	struct tcp_info info;
	socklen_t len;

	len = sizeof(info);
	if (getsockopt(s, IPPROTO_TCP, TCP_INFO, &info, &len) < 0)
		err(1, "getsockopt(TCP_INFO)");
	if (info.tcpi_options & TCPI_OPT_TOE)
		printf("Using TOE\n");
}

static char *ddp_buf;

static void
setup_static_ddp(int s)
{
	socklen_t len;
	int optval;

	optval = 1;
	len = sizeof(optval);
	if (setsockopt(s, IPPROTO_TCP, TCP_DDP_STATIC, &optval, len) < 0)
		err(1, "Failed to enable static DDP");
	if (getsockopt(s, IPPROTO_TCP, TCP_DDP_STATIC, &optval, &len) < 0)
		err(1, "getsockopt(TCP_DDP_STATIC");
	if (optval == 0)
		errx(1, "Static DDP doesn't claim to be enabled");
	len = sizeof(ddp_buf);
	if (getsockopt(s, IPPROTO_TCP, TCP_DDP_MAP, &ddp_buf, &len) < 0)
		err(1, "Failed to map static DDP buffer");
}

static void
read_ddp(int s, const char *data, size_t len)
{
	struct tcp_ddp_read tdr;
	socklen_t olen;

	olen = sizeof(tdr);
	if (getsockopt(s, IPPROTO_TCP, TCP_DDP_READ, &tdr, &olen) < 0)
		err(1, "Failed to read from static DDP buffer");
	if (tdr.length != len)
		errx(1, "short DDP read: %zu vs %zu", tdr.length, len);
	if (memcmp(ddp_buf + tdr.offset, data, len) != 0)
		errx(1, "DDP data mismatch");
	printf("Received DDP data matched\n");
}

static void
read_plain(int s, const char *data, size_t len)
{
	static char *buf;
	static size_t buflen;
	ssize_t nread;

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
	printf("Received data matched\n");
}

int
main(int ac, char **av)
{
	char *line;
	size_t linecap;
	ssize_t linelen, nwritten;
	bool static_ddp;
	int ch, s;

	static_ddp = false;
	while ((ch = getopt(ac, av, "D")) != -1)
		switch (ch) {
		case 'D':
			static_ddp = true;
			break;
		default:
			usage();
		}
	ac -= optind;
	av += optind;

	if (ac < 1 || ac > 2)
		usage();
	s = opensock(av[0], ac == 2 ? av[1] : "echo");
	check_for_toe(s);
	if (static_ddp)
		setup_static_ddp(s);

	line = NULL;
	linecap = 0;
	for (;;) {
		linelen = getline(&line, &linecap, stdin);
		if (linelen < 0) {
			if (feof(stdin))
				break;
			errx(1, "stdin returned an error");
		}
		if (linelen == 0)
			errx(1, "zero-length line");
		nwritten = write(s, line, linelen);
		if (nwritten < 0)
			err(1, "socket write");
		if (nwritten != linelen)
			errx(1, "short write: %zd of %zd", nwritten, linelen);
		if (static_ddp)
			read_ddp(s, line, linelen);
		else
			read_plain(s, line, linelen);
	}
	close(s);
	return (0);
}
