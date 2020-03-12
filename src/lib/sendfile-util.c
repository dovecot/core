/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

/* kludge a bit to remove _FILE_OFFSET_BITS definition from config.h.
   It's required to be able to include sys/sendfile.h with Linux. */
#include "config.h"
#undef HAVE_CONFIG_H

#ifdef HAVE_LINUX_SENDFILE
#  undef _FILE_OFFSET_BITS
#endif

#include "lib.h"
#include "sendfile-util.h"

#ifdef HAVE_LINUX_SENDFILE

#include <sys/sendfile.h>

ssize_t safe_sendfile(int out_fd, int in_fd, uoff_t *offset, size_t count)
{
	/* REMEMBER: uoff_t and off_t may not be of same size. */
	off_t safe_offset;
	ssize_t ret;

	i_assert(count > 0);

	/* make sure given offset fits into off_t */
	if (sizeof(off_t) * CHAR_BIT == 32) {
		/* 32bit off_t */
		if (*offset >= 2147483647L) {
			errno = EINVAL;
			return -1;
		}
		if (count > 2147483647L - *offset)
			count = 2147483647L - *offset;
	} else {
		/* they're most likely the same size. if not, fix this
		   code later */
		i_assert(sizeof(off_t) == sizeof(uoff_t));

		if (*offset >= OFF_T_MAX) {
			errno = EINVAL;
			return -1;
		}
		if (count > OFF_T_MAX - *offset)
			count = OFF_T_MAX - *offset;
	}

	safe_offset = (off_t)*offset;
	ret = sendfile(out_fd, in_fd, &safe_offset, count);
	/* ret=0 : trying to read past EOF */
	*offset = (uoff_t)safe_offset;
	return ret;
}

#elif defined(HAVE_FREEBSD_SENDFILE)

#include <sys/socket.h>
#include <sys/uio.h>

ssize_t safe_sendfile(int out_fd, int in_fd, uoff_t *offset, size_t count)
{
	struct sf_hdtr hdtr;
	off_t sbytes;
	int ret;

	/* if count=0 is passed to sendfile(), it sends everything
	   from in_fd until EOF. We don't want that. */
	i_assert(count > 0);
	i_assert(count <= SSIZE_T_MAX);

	i_zero(&hdtr);
	ret = sendfile(in_fd, out_fd, *offset, count, &hdtr, &sbytes, 0);

	*offset += sbytes;

	if (ret == 0 || (ret < 0 && errno == EAGAIN && sbytes > 0))
		return (ssize_t)sbytes;
	else {
		if (errno == ENOTSOCK) {
			/* out_fd wasn't a socket. behave as if sendfile()
			   wasn't supported at all. */
			errno = EINVAL;
		}
		return -1;
	}
}

#elif defined (HAVE_SOLARIS_SENDFILE)

#include <sys/sendfile.h>
#include "net.h"

ssize_t safe_sendfile(int out_fd, int in_fd, uoff_t *offset, size_t count)
{
	ssize_t ret;
	off_t s_offset;

	i_assert(count > 0);
	i_assert(count <= SSIZE_T_MAX);

	/* NOTE: if outfd is not a socket, some Solaris versions will
	   kernel panic */

	s_offset = (off_t)*offset;
	ret = sendfile(out_fd, in_fd, &s_offset, count);

	if (ret < 0) {
		/* if remote is gone, EPIPE is returned */
		if (errno == EINVAL) {
			/* most likely trying to read past EOF */
			ret = 0;
		} else if (errno == EAFNOSUPPORT || errno == EOPNOTSUPP) {
			/* not supported, return Linux-like EINVAL so caller
			   sees only consistent errnos. */
			errno = EINVAL;
		} else if (s_offset != (off_t)*offset) {
			/* some data was sent, return it */
			i_assert(s_offset > (off_t)*offset);
			ret = s_offset - (off_t)*offset;
		}
	}
	*offset = (uoff_t)s_offset;
	i_assert(ret < 0 || (size_t)ret <= count);
	return ret;
}

#else
ssize_t safe_sendfile(int out_fd ATTR_UNUSED, int in_fd ATTR_UNUSED,
		      uoff_t *offset ATTR_UNUSED,
		      size_t count ATTR_UNUSED)
{
	errno = EINVAL;
	return -1;
}

#endif
