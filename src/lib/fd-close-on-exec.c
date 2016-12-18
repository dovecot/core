/* Copyright (c) 2002-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "fd-close-on-exec.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/un.h>

void fd_close_on_exec(int fd, bool set)
{
	int flags;

	flags = fcntl(fd, F_GETFD, 0);
	if (flags < 0)
		i_fatal("fcntl(F_GETFD, %d) failed: %m", fd);

	flags = set ? (flags | FD_CLOEXEC) : (flags & ~FD_CLOEXEC);
	if (fcntl(fd, F_SETFD, flags) < 0)
		i_fatal("fcntl(F_SETFD, %d) failed: %m", fd);
}

void fd_debug_verify_leaks(int first_fd, int last_fd)
{
	struct ip_addr addr, raddr;
	in_port_t port, rport;
	struct stat st;
	int old_errno;
	bool leaks = FALSE;

	for (int fd = first_fd; fd <= last_fd; ++fd) {
		if (fcntl(fd, F_GETFD, 0) == -1 && errno == EBADF)
			continue;

		old_errno = errno;

		if (net_getsockname(fd, &addr, &port) == 0) {
			if (addr.family == AF_UNIX) {
				struct sockaddr_un sa;

				socklen_t socklen = sizeof(sa);

				if (getsockname(fd, (void *)&sa,
						&socklen) < 0)
					sa.sun_path[0] = '\0';

				i_error("Leaked UNIX socket fd %d: %s",
					fd, sa.sun_path);
				leaks = TRUE;
				continue;
			}

			if (net_getpeername(fd, &raddr, &rport) < 0) {
				i_zero(&raddr);
				rport = 0;
			}
			i_error("Leaked socket fd %d: %s:%u -> %s:%u",
				fd, net_ip2addr(&addr), port,
				net_ip2addr(&raddr), rport);
			leaks = TRUE;
			continue;
		}

		if (fstat(fd, &st) == 0) {
#ifdef __APPLE__
			/* OSX workaround: gettimeofday() calls shm_open()
			   internally and the fd won't get closed on exec.
			   We'll just skip all ino/dev=0 files and hope they
			   weren't anything else. */
			if (st.st_ino == 0 && st.st_dev == 0)
				continue;
#endif
#ifdef HAVE_SYS_SYSMACROS_H
			i_error("Leaked file fd %d: dev %s.%s inode %s",
				fd, dec2str(major(st.st_dev)),
				dec2str(minor(st.st_dev)), dec2str(st.st_ino));
			leaks = TRUE;
			continue;
#else
			i_error("Leaked file fd %d: dev %s inode %s",
				fd, dec2str(st.st_dev),
				dec2str(st.st_ino));
			leaks = TRUE;
			continue;
#endif
		}

		i_error("Leaked unknown fd %d (errno = %s)",
			fd, strerror(old_errno));
		leaks = TRUE;
		continue;
	}
	if (leaks)
		i_fatal("fd leak found");
}
