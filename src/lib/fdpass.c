/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

/*
   fdpass.c - File descriptor passing between processes via UNIX sockets

   This isn't fully portable, but pretty much all UNIXes nowadays should
   support this. If you're having runtime problems with fd_read(), check the
   end of fd_read() and play with the if condition. If you're having problems
   with fd_send(), try defining BUGGY_CMSG_MACROS.

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

#ifdef HAVE_CONFIG_H
#  include "lib.h"
#else
#  define i_assert(x)
#endif

#include <string.h>
#include <limits.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

#include "fdpass.h"

#ifndef HAVE_CONFIG_H
struct const_iovec {
	const void *iov_base;
	size_t iov_len;
};
#endif

/* RFC 2292 defines CMSG_*() macros, but some operating systems don't have them
   so we'll define our own if they don't exist.

   CMSG_LEN(data) is used to calculate size of sizeof(struct cmsghdr) +
   sizeof(data) and padding between them.

   CMSG_SPACE(data) also calculates the padding needed after the data, in case
   multiple objects are sent.

   cmsghdr contains cmsg_len field and two integers. cmsg_len is sometimes
   defined as sockaddr_t and sometimes size_t, so it can be either 32bit or
   64bit. This padding is added by compiler in sizeof(struct cmsghdr).

   Padding required by CMSG_DATA() can vary. Usually it wants size_t or 32bit.
   With Solaris it's in _CMSG_DATA_ALIGNMENT (32bit), we assume others want
   size_t.

   We don't really need CMSG_SPACE() to be exactly correct, because currently
   we send only one object at a time. But anyway I'm trying to keep that
   correct in case it's sometimes needed..
*/

#ifdef BUGGY_CMSG_MACROS
/* Some OSes have broken CMSG macros in 64bit systems. The macros use 64bit
   alignment while kernel uses 32bit alignment. */
#  undef CMSG_SPACE
#  undef CMSG_LEN
#  undef CMSG_DATA
#  define CMSG_DATA(cmsg) ((char *)((cmsg) + 1))
#  define _CMSG_DATA_ALIGNMENT 4
#  define _CMSG_HDR_ALIGNMENT 4
#endif

#ifndef CMSG_SPACE
#  define MY_ALIGN(len, align) \
	(((len) + align - 1) & ~(align - 1))

/* Alignment between cmsghdr and data */
#  ifndef _CMSG_DATA_ALIGNMENT
#    define _CMSG_DATA_ALIGNMENT sizeof(size_t)
#  endif
/* Alignment between data and next cmsghdr */
#  ifndef _CMSG_HDR_ALIGNMENT
#    define _CMSG_HDR_ALIGNMENT sizeof(size_t)
#  endif

#  define CMSG_SPACE(len) \
	(MY_ALIGN(sizeof(struct cmsghdr), _CMSG_DATA_ALIGNMENT) + \
	 MY_ALIGN(len, _CMSG_HDR_ALIGNMENT))
#  define CMSG_LEN(len) \
	(MY_ALIGN(sizeof(struct cmsghdr), _CMSG_DATA_ALIGNMENT) + (len))
#endif

#ifdef SCM_RIGHTS

ssize_t fd_send(int handle, int send_fd, const void *data, size_t size)
{
        struct msghdr msg;
        struct const_iovec iov;
        struct cmsghdr *cmsg;
	char buf[CMSG_SPACE(sizeof(int))];

	/* at least one byte is required to be sent with fd passing */
	i_assert(size > 0 && size < INT_MAX);

	memset(&msg, 0, sizeof(struct msghdr));

        iov.iov_base = data;
        iov.iov_len = size;

        msg.msg_iov = (void *)&iov;
	msg.msg_iovlen = 1;

	if (send_fd != -1) {
		/* set the control and controllen before CMSG_FIRSTHDR(). */
		memset(buf, 0, sizeof(buf));
		msg.msg_control = buf;
		msg.msg_controllen = sizeof(buf);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &send_fd, sizeof(send_fd));

		/* set the real length we want to use. Do it after all is
		   set just in case CMSG macros required the extra padding
		   in the end. */
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

	i_assert(size > 0 && size < INT_MAX);

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
		memcpy(fd, CMSG_DATA(cmsg), sizeof(*fd));
	return ret;
}

#else
#  ifdef __GNUC__
#    warning SCM_RIGHTS not supported, privilege separation not possible
#  endif
ssize_t fd_send(int handle ATTR_UNUSED, int send_fd ATTR_UNUSED,
		const void *data ATTR_UNUSED, size_t size ATTR_UNUSED)
{
	errno = ENOSYS;
	return -1;
}

ssize_t fd_read(int handle ATTR_UNUSED, void *data ATTR_UNUSED,
		size_t size ATTR_UNUSED, int *fd ATTR_UNUSED)
{
	errno = ENOSYS;
	return -1;
}
#endif
