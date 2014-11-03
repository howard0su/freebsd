/*-
 * XXX: License
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
 * A regression test to verify that accf_dns does not mark a socket
 * connected until it has received a full DNS request.
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

int
main(int ac, char **av)
{
	struct accept_filter_arg afa;
	struct sockaddr_in sin;
	uint16_t dns_len;
	socklen_t len;
	int lso, cso;

	printf("1..11\n");

	/* Create a socket. */
	lso = socket(PF_INET, SOCK_STREAM, 0);
	if (lso < 0)
		fail_err("socket");
	ok("socket");

	/* Bind to an address. */
	bzero(&sin, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(8053);
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
	strcpy(afa.af_name, "dnsready");
	if (setsockopt(lso, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa)) < 0)
		fail_err("setsockopt(SO_ACCEPTFILTER)");
	ok("setsockopt(SO_ACCEPTFILTER)");

	/* Create the client socket. */
	cso = socket(PF_INET, SOCK_STREAM, 0);
	if (cso < 0)
		fail_err("socket");
	ok("socket");

	/* Connect to our listening socket. */
	if (connect(cso, (struct sockaddr *)&sin, sizeof(sin)) < 0)
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

	/* Scribble a partial request.  First the 16-bit length. */
	dns_len = htons(16);
	write(cso, &dns_len, sizeof(dns_len));
	usleep(250 * 1000);
	
	/* See if our socket is ready yet. */
	if (socket_ready(lso, &sin))
		fail("accept", "socket ready too soon");
	ok("accept");

	/* Write part of the DNS request payload. */
	write(cso, "01234657", 8);
	usleep(250 * 1000);
	
	/* See if our socket is ready yet. */
	if (socket_ready(lso, &sin))
		fail("accept", "socket ready too soon");
	ok("accept");

	/* Write the rest of the DNS request to make the socket ready. */
	write(cso, "89abcdef", 8);
	usleep(250 * 1000);

	/* Our socket should be ready now. */
	if (!socket_ready(lso, &sin))
		fail("accept", "socket is not ready");
	ok("accept");

	close(cso);
	close(lso);
	return (0);
}

