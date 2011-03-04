/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "hex-binary.h"
#include "randgen.h"
#include "hostpid.h"
#include "eacces-error.h"
#include "safe-mkstemp.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static int
safe_mkstemp_full(string_t *prefix, mode_t mode, uid_t uid, gid_t gid,
		  const char *gid_origin)
{
	size_t prefix_len;
	struct stat st;
	unsigned char randbuf[8];
	mode_t old_umask;
	int fd;

	prefix_len = str_len(prefix);
	for (;;) {
		do {
			random_fill_weak(randbuf, sizeof(randbuf));
			str_truncate(prefix, prefix_len);
			str_append(prefix,
				   binary_to_hex(randbuf, sizeof(randbuf)));
		} while (lstat(str_c(prefix), &st) == 0);

		if (errno != ENOENT) {
			i_error("stat(%s) failed: %m", str_c(prefix));
			str_truncate(prefix, prefix_len);
			return -1;
		}

		old_umask = umask(0666 ^ mode);
		fd = open(str_c(prefix), O_RDWR | O_EXCL | O_CREAT, 0666);
		umask(old_umask);
		if (fd != -1)
			break;

		if (errno != EEXIST) {
			if (errno != ENOENT && errno != EACCES)
				i_error("open(%s) failed: %m", str_c(prefix));
			str_truncate(prefix, prefix_len);
			return -1;
		}
	}
	if (uid == (uid_t)-1 && gid == (gid_t)-1)
		return fd;

	if (fchown(fd, uid, gid) < 0) {
		if (errno == EPERM) {
			i_error("%s", eperm_error_get_chgrp("fchown",
					str_c(prefix), gid, gid_origin));
		} else {
			i_error("fchown(%s, %ld, %ld) failed: %m",
				str_c(prefix),
				uid == (uid_t)-1 ? -1L : (long)uid,
				gid == (gid_t)-1 ? -1L : (long)gid);
		}
		(void)close(fd);
		(void)unlink(str_c(prefix));
		return -1;
	}
	return fd;
}

int safe_mkstemp(string_t *prefix, mode_t mode, uid_t uid, gid_t gid)
{
	return safe_mkstemp_full(prefix, mode, uid, gid, NULL);
}

int safe_mkstemp_group(string_t *prefix, mode_t mode,
		       gid_t gid, const char *gid_origin)
{
	return safe_mkstemp_full(prefix, mode, (uid_t)-1, gid, gid_origin);
}

int safe_mkstemp_hostpid(string_t *prefix, mode_t mode, uid_t uid, gid_t gid)
{
	str_printfa(prefix, "%s.%s.", my_hostname, my_pid);
	return safe_mkstemp(prefix, mode, uid, gid);
}

int safe_mkstemp_hostpid_group(string_t *prefix, mode_t mode,
			       gid_t gid, const char *gid_origin)
{
	str_printfa(prefix, "%s.%s.", my_hostname, my_pid);
	return safe_mkstemp_group(prefix, mode, gid, gid_origin);
}
