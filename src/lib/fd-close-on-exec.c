/*
    Copyright (c) 2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "lib.h"
#include "network.h"
#include "fd-close-on-exec.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/un.h>

void fd_close_on_exec(int fd, int set)
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
	struct ip_addr addr;
	unsigned int port;
	struct stat st;

	while (first_fd < last_fd) {
		if (fcntl(first_fd, F_GETFD, 0) != -1 || errno != EBADF) {
			int old_errno = errno;

			if (net_getsockname(first_fd, &addr, &port) == 0) {
				if (addr.family == AF_UNIX) {
					struct sockaddr_un sa;
					socklen_t socklen = sizeof(sa);

					if (getsockname(first_fd,
							(struct sockaddr *) &sa,
							&socklen) < 0)
						sa.sun_path[0] = '\0';

					i_panic("Leaked UNIX socket fd %d: %s",
						first_fd, sa.sun_path);
				}

				i_panic("Leaked socket fd %d: %s:%u",
					first_fd, net_ip2host(&addr), port);
			}

			if (fstat(first_fd, &st) == 0) {
#ifdef HAVE_SYS_SYSMACROS_H
				i_panic("Leaked file fd %d: dev %s.%s inode %s", first_fd,
					dec2str(major(st.st_dev)),
					dec2str(minor(st.st_dev)),
					dec2str(st.st_ino));
#else
				i_panic("Leaked file fd %d: dev %s inode %s",
					first_fd, dec2str(st.st_dev),
					dec2str(st.st_ino));
#endif
			}

			i_panic("Leaked unknown fd %d (errno = %s)",
				first_fd, strerror(old_errno));
		}
		first_fd++;
	}
}
