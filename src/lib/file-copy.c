/* Copyright (c) 2006 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "file-copy.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static int file_copy_to_tmp(const char *srcpath, const char *tmppath,
			    bool try_hardlink)
{
	struct istream *input;
	struct ostream *output;
	struct stat st;
	mode_t old_umask;
	int fd_in, fd_out;
	off_t ret;

	if (try_hardlink) {
		/* see if hardlinking works */
		if (link(srcpath, tmppath) == 0)
			return 1;
		if (errno == EEXIST) {
			if (unlink(tmppath) < 0 && errno != ENOENT) {
				i_error("unlink(%s) failed: %m", tmppath);
				return -1;
			}
			if (link(srcpath, tmppath) == 0)
				return 1;
		}
		if (errno == ENOENT)
			return 0;
		if (!ECANTLINK(errno)) {
			i_error("link(%s, %s) failed: %m", srcpath, tmppath);
			return -1;
		}

		/* fallback to manual copying */
	}

	fd_in = open(srcpath, O_RDONLY);
	if (fd_in == -1) {
		if (errno == ENOENT)
			return 0;
		i_error("open(%s) failed: %m", srcpath);
		return -1;
	}

	if (fstat(fd_in, &st) < 0) {
		i_error("fstat(%s) failed: %m", srcpath);
		(void)close(fd_in);
		return -1;
	}

	old_umask = umask(0);
	fd_out = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode);
	umask(old_umask);
	if (fd_out == -1) {
		i_error("open(%s, O_CREAT) failed: %m", tmppath);
		(void)close(fd_in);
		return -1;
	}

	/* try to change the group, don't really care if it fails */
	(void)fchown(fd_out, (uid_t)-1, st.st_gid);

	input = i_stream_create_file(fd_in, 0, FALSE);
	output = o_stream_create_fd_file(fd_out, 0, FALSE);

	while ((ret = o_stream_send_istream(output, input)) > 0) ;

	i_stream_destroy(&input);
	o_stream_destroy(&output);

	if (close(fd_in) < 0) {
		i_error("close(%s) failed: %m", srcpath);
		ret = -1;
	}
	if (close(fd_out) < 0) {
		i_error("close(%s) failed: %m", tmppath);
		ret = -1;
	}
	return ret < 0 ? -1 : 1;
}

int file_copy(const char *srcpath, const char *destpath, bool try_hardlink)
{
	const char *tmppath;
	int ret;

	t_push();
	tmppath = t_strconcat(destpath, ".tmp", NULL);

	ret = file_copy_to_tmp(srcpath, tmppath, try_hardlink);
	if (ret > 0) {
		if (rename(tmppath, destpath) < 0) {
			i_error("rename(%s, %s) failed: %m", tmppath, destpath);
			ret = -1;
		}
	}
	if (ret < 0)
		(void)unlink(tmppath);

	t_pop();
	return ret;
}
