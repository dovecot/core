/* Copyright (c) 2006 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "file-copy.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int file_copy(const char *srcpath, const char *destpath, bool try_hardlink)
{
	const char *tmppath;
	struct istream *input;
	struct ostream *output;
	int fd_in, fd_out;
	off_t ret;

	if (try_hardlink) {
		/* see if hardlinking works */
		if (link(srcpath, destpath) == 0 || errno == EEXIST)
			return 1;
		if (errno == ENOENT)
			return 0;
		if (!ECANTLINK(errno)) {
			i_error("link(%s, %s) failed: %m", srcpath, destpath);
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

	t_push();
	tmppath = t_strconcat(destpath, ".tmp", NULL);
	fd_out = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd_out == -1) {
		i_error("open(%s, O_CREAT) failed: %m", tmppath);
		(void)close(fd_in);
		t_pop();
		return -1;
	}
	input = i_stream_create_file(fd_in, default_pool, 0, FALSE);
	output = o_stream_create_file(fd_out, default_pool, 0, FALSE);

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
	if (ret == 0) {
		if (rename(tmppath, destpath) < 0) {
			i_error("rename(%s, %s) failed: %m", tmppath, destpath);
			ret = -1;
		}
	}
	if (ret < 0)
		(void)unlink(tmppath);
	t_pop();
	return ret < 0 ? -1 : 1;
}
