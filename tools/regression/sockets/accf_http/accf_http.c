/*-
 * Copyright (c) 2009 Advanced Computing Technologies LLC
 * Written by: John H. Baldwin <jhb@FreeBSD.org>
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

/*
 * A regression test to verify that accf_http does not mark a socket
 * connected until it has received a full HTTP request.
 */

static int test = 1;

static void
ok(const char *descr)
{

	printf("ok %d - %s\n", test, descr);
	test++;
}

static void
fail(const char *descr, char *fmt, ...)
{
	va_list ap;

	printf("not ok %d - %s", test, descr);
	test++;
	if (fmt) {
		va_start(ap, fmt);
		printf(" # ");
		vprintf(fmt, ap);
		va_end(ap);
	}
	printf("\n");
	exit(1);
}

#define	fail_err(descr)		fail((descr), "%s", strerror(errno))

/* Returns true if 'cso' is connected to 'lso'. */
static int
socket_ready(int lso, struct sockaddr_in *csin)
{
	struct sockaddr_in sin;
	struct pollfd p;
	socklen_t len;
	int ret, s;

	for (;;) {
		/*
		 * Do a non-blocking poll() to see if there is a ready
		 * socket.
		 */
		p.fd = lso;
		p.events = POLLIN;
		ret = poll(&p, 1, 0);
		if (ret < 0)
			fail_err("poll");
		if (ret == 0)
			return (0);

		/* Accept the socket that is ready. */
		len = sizeof(sin);
		s = accept(lso, (struct sockaddr *)&sin, &len);
		if (s < 0)
			fail_err("accept");
		if (len != sizeof(sin))
			fail("accept", "bad sockaddr length %d", (int)len);
		close(s);

		/* Ignore sockets that are not 'sin'. */
		if (sin.sin_family != csin->sin_family ||
		    sin.sin_port != csin->sin_port ||
		    sin.sin_addr.s_addr != csin->sin_addr.s_addr) {
			continue;
		}

		/* We've got our own socket. */
		return (1);
	}
}

/*
 * Run a test for a given HTTP request.  The request is sent to the
 * listener in three parts.  The socket should not be ready until the
 * full request has been received.
 */
static void
test_request(int lso, struct sockaddr_in *remote, const char *request)
{
	struct sockaddr_in sin;
	socklen_t len;
	int cso, reqlen;

	/* Create the client socket. */
	cso = socket(PF_INET, SOCK_STREAM, 0);
	if (cso < 0)
		fail_err("socket");
	ok("socket");

	/* Connect to our listening socket. */
	if (connect(cso, (struct sockaddr *)remote, sizeof(*remote)) < 0)
		fail_err("connect");
	ok("connect");

	/* Fetch our client socket's local name. */
	len = sizeof(sin);
	if (getsockname(cso, (struct sockaddr *)&sin, &len) < 0)
		fail_err("getsockname");
	ok("getsockname");

	/* Give it some time. */
	usleep(100);

	/* See if our socket is ready yet. */
	if (socket_ready(lso, &sin))
		fail("accept", "socket ready too soon");
	ok("accept");

	/* Write the first half of the request. */
	reqlen = strlen(request) / 2;
	write(cso, request, reqlen);
	request += reqlen;
	usleep(250 * 1000);
	
	/* See if our socket is ready yet. */
	if (socket_ready(lso, &sin))
		fail("accept", "socket ready too soon");
	ok("accept");

	/* Write all but the last byte. */
	reqlen = strlen(request) - 1;
	write(cso, request, reqlen);
	request += reqlen;
	usleep(250 * 1000);
	
	/* See if our socket is ready yet. */
	if (socket_ready(lso, &sin))
		fail("accept", "socket ready too soon");
	ok("accept");

	/* Write the final byte to make the socket ready. */
	write(cso, request, 1);
	usleep(250 * 1000);

	/* Our socket should be ready now. */
	if (!socket_ready(lso, &sin))
		fail("accept", "socket is not ready");
	ok("accept");

	close(cso);
}

int
main(int ac, char **av)
{
	struct accept_filter_arg afa;
	struct sockaddr_in sin;
	int lso;

	printf("1..39\n");

	/* Create a socket. */
	lso = socket(PF_INET, SOCK_STREAM, 0);
	if (lso < 0)
		fail_err("socket");
	ok("socket");

	/* Bind to an address. */
	bzero(&sin, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(8080);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(lso, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		fail_err("bind");
	ok("bind");

	/* Enable listening for connections. */
	if (listen(lso, -1) < 0)
		fail_err("listen");
	ok("listen");

	/* Attach the accept filter. */
	bzero(&afa, sizeof(afa));
	strcpy(afa.af_name, "httpready");
	if (setsockopt(lso, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa)) < 0)
		fail_err("setsockopt(SO_ACCEPTFILTER)");
	ok("setsockopt(SO_ACCEPTFILTER)");

	/*
	 * Simple HTTP/0.9 request.  Note that we omit the trailing
	 * '\n' in this case since soparsehttpvers() will bail at the
	 * first CR or LF it sees.
	 */
	test_request(lso, &sin, "GET /\r");

	/* Simple HTTP/1.0 request. */
	test_request(lso, &sin, "GET / HTTP/1.0\r\n\r\n");

	/* Simple HEAD request. */
	test_request(lso, &sin, "HEAD / HTTP/1.0\r\n\r\n");

	/* Complex GET request. */
	test_request(lso, &sin, "GET / HTTP/1.0\r\n"
	    "User-Agent: accf_http/1.0\r\n\r\n");

	/* Complex HEAD request. */
	test_request(lso, &sin, "HEAD / HTTP/1.0\r\n"
	    "User-Agent: accf_http/1.0\r\n\r\n");

	close(lso);
	return (0);
}

