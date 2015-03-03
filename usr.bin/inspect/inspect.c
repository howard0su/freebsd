/*-
 * Toggle the inspection flags on a given process or execute a process
 * with a given set of inspection flags.
 */

#include <sys/types.h>
#include <sys/inspect.h>
#include <sys/sysctl.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void
usage(void)
{
	fprintf(stderr, "%s\n%s\n",
"usage: inspect [-c | -t flags] [-p pid]",
"       inspect [-t flags] command");
	exit(1);
}

static int
inspection_present(void)
{
	int mib[2];
	size_t len;

	len = 2;
	return (sysctlnametomib("inspect.me", mib, &len) == 0);
}

static int
parseflags(const char *options)
{
	int flags;

	flags = 0;
	while (*options != '\0') {
		switch (*options) {
		case 's':
			flags |= INSPECT_SLEEPS;
			break;
		case 'l':
			flags |= INSPECT_LOCKS;
			break;
		case 'p':
			flags |= INSPECT_PREEMPTIONS;
			break;
		default:
			errx(1, "Unknown flag '%c'", *options);
		}
		options++;
	}
	return (flags);
}

static void
set_inspect_flags(pid_t pid, int flags)
{
	int mib[3];
	size_t len;

	len = 2;
	if (sysctlnametomib("inspect.proc", mib, &len) < 0)
		err(1, "sysctl('inspect.proc')");
	mib[2] = pid;
	if (sysctl(mib, 3, NULL, NULL, &flags, sizeof(flags)) < 0)
		err(1, "Failed to set trace flags on pid %ld", (long)pid);
}

int
main(int ac, char **av)
{
	pid_t pid;
	int ch, cflag, flags;

	if (!inspection_present())
		errx(1, "Kernel does not include inspection support");

	cflag = 0;
	pid = -1;
	flags = 0;
	while ((ch = getopt(ac, av, "cp:t:")) != -1)
		switch (ch) {
		case 'c':
			cflag = 1;
			break;
		case 'p':
			pid = atoi(optarg);
			break;
		case 't':
			flags = parseflags(optarg);
			break;
		default:
			usage();
		}
	av += optind;
	ac -= optind;

	if (((pid != -1 || cflag) && *av != NULL) ||
	    (pid == -1 && *av == NULL) || cflag != (flags == 0))
		usage();

	if (pid != -1) {
		if (cflag)
			set_inspect_flags(pid, 0);
		else
			set_inspect_flags(pid, flags);
		return (0);
	}

	set_inspect_flags(getpid(), flags);
	execvp(av[0], &av[0]);
	err(1, "exec of '%s' failed", av[0]);
}
