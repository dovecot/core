/* kludge a bit to remove _FILE_OFFSET_BITS definition from config.h.
   It's required to be able to include sys/sendfile.h with Linux. */
#include "../../config.h"
#undef HAVE_CONFIG_H
#undef _FILE_OFFSET_BITS

#include "lib.h"
#include "sendfile-util.h"

#ifdef HAVE_SYS_SENDFILE_H

#include <sys/sendfile.h>

ssize_t safe_sendfile(int out_fd, int in_fd, uoff_t *offset, size_t count)
{
	/* REMEBER: uoff_t and off_t may not be of same size. */
	off_t safe_offset;
	ssize_t ret;

	/* make sure given offset fits into off_t */
	if (sizeof(off_t) * CHAR_BIT == 32) {
		/* 32bit off_t */
		if (*offset > 2147483647L) {
			errno = EINVAL;
			return -1;
		}
	} else {
		/* they're most likely the same size. if not, fix this
		   code later */
		i_assert(sizeof(off_t) == sizeof(uoff_t));

		if (*offset > OFF_T_MAX) {
			errno = EINVAL;
			return -1;
		}
	}

	safe_offset = (off_t)*offset;
	ret = sendfile(out_fd, in_fd, &safe_offset, count);
	*offset = (uoff_t)safe_offset;

	return ret;
}

#else
ssize_t safe_sendfile(int out_fd __attr_unused__, int in_fd __attr_unused__,
		      uoff_t *offset __attr_unused__,
		      size_t count __attr_unused__)
{
	errno = EINVAL;
	return -1;
}
#endif
