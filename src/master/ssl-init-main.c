/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "lib-signals.h"
#include "file-lock.h"
#include "randgen.h"
#include "ssl-init.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef HAVE_SSL
static int generate_parameters_file(const char *fname)
{
	const char *temp_fname;
	struct file_lock *lock;
	mode_t old_mask;
	int fd, ret;

	temp_fname = t_strconcat(fname, ".tmp", NULL);

	old_mask = umask(0);
	fd = open(temp_fname, O_WRONLY | O_CREAT, 0644);
	umask(old_mask);

	if (fd == -1) {
		i_fatal("Can't create temporary SSL parameters file %s: %m",
			temp_fname);
	}

	/* If multiple dovecot instances are running, only one of them needs
	   to regenerate this file. */
	ret = file_try_lock(fd, temp_fname, F_WRLCK,
			    FILE_LOCK_METHOD_FCNTL, &lock);
	if (ret < 0)
		i_fatal("file_try_lock(%s) failed: %m", temp_fname);
	if (ret == 0) {
		/* someone else is writing this */
		return -1;
	}
	if (ftruncate(fd, 0) < 0)
		i_fatal("ftruncate(%s) failed: %m", temp_fname);

	_ssl_generate_parameters(fd, temp_fname);

	if (rename(temp_fname, fname) < 0)
		i_fatal("rename(%s, %s) failed: %m", temp_fname, fname);
	if (close(fd) < 0)
		i_fatal("close(%s) failed: %m", temp_fname);
	file_lock_free(&lock);

	i_info("SSL parameters regeneration completed");
	return 0;
}
#else
static int generate_parameters_file(const char *fname ATTR_UNUSED)
{
	i_fatal("Dovecot built without SSL support");
	return -1;
}
#endif

int main(int argc, char *argv[])
{
	int ret = 0;

	lib_init();
	i_set_failure_internal();

	if (argc < 2)
		i_fatal("Usage: ssl-build-param <path>");

	random_init();
	if (generate_parameters_file(argv[1]) < 0)
		ret = 1;

	random_deinit();
	lib_deinit();
	return ret;
}
