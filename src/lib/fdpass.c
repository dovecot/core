/* Copyright (c) 2002-2003 Timo Sirainen */

/*
   fdpass.c - File descriptor passing between processes via UNIX sockets

   This isn't fully portable, but pretty much all UNIXes nowadays should
   support this. If you're having runtime problems, check the end of fd_read()
   and play with the if condition.

   If this file doesn't compile at all, you should check if this is supported
   in your system at all. It may require some extra #define to enable it.
   If not, you're pretty much out of luck. Cygwin didn't last I checked.
*/

#define _XPG4_2

#if defined(irix) || defined (__irix__) || defined(sgi) || defined (__sgi__)
#  define _XOPEN_SOURCE 4 /* for IRIX */
#endif


#if !defined(_AIX) && !defined(_XOPEN_SOURCE_EXTENDED)
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

#ifdef SCM_RIGHTS

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

#ifdef __osf__
#  define CHECK_MSG(msg) TRUE /* Tru64 */
#else
#  define CHECK_MSG(msg) (msg).msg_controllen >= CMSG_SPACE(sizeof(int))
#endif

#ifdef LINUX20
/* Linux 2.0.x doesn't set any cmsg fields. Note that this might make some
   attacks possible so don't do it unless you really have to. */
#  define CHECK_CMSG(cmsg) ((cmsg) != NULL)
#else
#  define CHECK_CMSG(cmsg) \
	((cmsg) != NULL && \
	 (size_t)(cmsg)->cmsg_len >= (size_t)CMSG_LEN(sizeof(int)) && \
	 (cmsg)->cmsg_level == SOL_SOCKET && (cmsg)->cmsg_type == SCM_RIGHTS)
#endif

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
	   set all these values correctly however so CHECK_MSG() and
	   CHECK_CMSG() are somewhat system dependent */
	cmsg = CMSG_FIRSTHDR(&msg);
	if (!CHECK_MSG(msg) || !CHECK_CMSG(cmsg))
		*fd = -1;
	else
		*fd = *((int *) CMSG_DATA(cmsg));
	return ret;
}

#else
#  ifdef __GNUC__
#    warning SCM_RIGHTS not supported, privilege separation not possible
#  endif
ssize_t fd_send(int handle __attr_unused__, int send_fd __attr_unused__,
		const void *data __attr_unused__, size_t size __attr_unused__)
{
	errno = ENOSYS;
	return -1;
}

ssize_t fd_read(int handle __attr_unused__, void *data __attr_unused__,
		size_t size __attr_unused__, int *fd __attr_unused__)
{
	errno = ENOSYS;
	return -1;
}
#endif
