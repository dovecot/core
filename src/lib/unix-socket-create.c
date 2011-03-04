/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "network.h"
#include "unix-socket-create.h"

#include <unistd.h>
#include <sys/stat.h>

int unix_socket_create(const char *path, int mode,
		       uid_t uid, gid_t gid, int backlog)
{
	mode_t old_umask;
	int fd;

	old_umask = umask(0777 ^ mode);
	fd = net_listen_unix_unlink_stale(path, backlog);
	umask(old_umask);

	if (fd < 0) {
		i_error("net_listen_unix(%s) failed: %m", path);
		return -1;
	}

	if (uid != (uid_t)-1 || gid != (gid_t)-1) {
		/* set correct permissions */
		if (chown(path, uid, gid) < 0) {
			i_error("chown(%s, %s, %s) failed: %m",
				path, dec2str(uid), dec2str(gid));
			return -1;
		}
	}
	return fd;
}

