/*
 fdpass.c - File descriptor passing between processes via UNIX sockets

 This isn't fully portable, but pretty much all UNIXes nowadays should
 support this. If you're having runtime problems, check the end of fd_read()
 and play with the if condition.

 If this file doesn't compile at all, you should check if this is supported
 in your system at all. It may require some extra #define to enable it.
 If not, you're pretty much out of luck. Cygwin didn't last I checked.

    Copyright (c) 2002-2003 Timo Sirainen

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

#define _XPG4_2

#ifndef _AIX
#  define _XOPEN_SOURCE_EXTENDED /* for Tru64, breaks AIX */
#endif

#include "lib.h"
#include "fdpass.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

#ifndef CMSG_SPACE
#  define CMSG_ALIGN(len) \
	(((len) + sizeof(size_t) - 1) & ~(sizeof(size_t) - 1))
#  define CMSG_SPACE(len) \
	(CMSG_ALIGN(len) + CMSG_ALIGN(sizeof(struct cmsghdr)))
#  define CMSG_LEN(len) \
	(CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#endif

ssize_t fd_send(int handle, int send_fd, const void *data, size_t size)
{
        struct msghdr msg;
        struct iovec iov;
        struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))];

	/* at least one byte is required to be sent with fd passing */
	i_assert(size > 0 && size < SSIZE_T_MAX);

	memset(&msg, 0, sizeof (struct msghdr));

        iov.iov_base = (void *) data;
        iov.iov_len = size;

        msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (send_fd != -1) {
		/* set the control and controllen before CMSG_FIRSTHDR() */
		msg.msg_control = buf;
		msg.msg_controllen = sizeof(buf);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		*((int *) CMSG_DATA(cmsg)) = send_fd;

		/* set the real length we want to use. it's different than
		   sizeof(buf) in 64bit systems. */
		msg.msg_controllen = cmsg->cmsg_len;
	}

	return sendmsg(handle, &msg, 0);
}

ssize_t fd_read(int handle, void *data, size_t size, int *fd)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	ssize_t ret;
	char buf[CMSG_SPACE(sizeof(int))];

	i_assert(size > 0 && size < SSIZE_T_MAX);

	memset(&msg, 0, sizeof (struct msghdr));

	iov.iov_base = data;
	iov.iov_len = size;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	memset(buf, 0, sizeof(buf));
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	ret = recvmsg(handle, &msg, 0);
	if (ret <= 0) {
		*fd = -1;
		return ret;
	}

	/* at least one byte transferred - we should have the fd now.
	   do extra checks to make sure it really is an fd that is being
	   transferred to avoid potential DoS conditions. some systems don't
	   set all these values correctly however:

	   Linux 2.0.x - cmsg_len, cmsg_level, cmsg_type are not set
	   Tru64 - msg_controllen isn't set */
	cmsg = CMSG_FIRSTHDR(&msg);
	if (
#ifndef __osf__
	    msg.msg_controllen < CMSG_SPACE(sizeof(int)) ||
#endif
	    cmsg == NULL || cmsg->cmsg_len < CMSG_LEN(sizeof(int)) ||
	    cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
		*fd = -1;
	else
		*fd = *((int *) CMSG_DATA(cmsg));
	return ret;
}
