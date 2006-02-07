/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "lib-signals.h"
#include "randgen.h"
#include "ssl-init.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef HAVE_SSL
static void generate_parameters_file(const char *fname)
{
	const char *temp_fname;
	mode_t old_mask;
	int fd;

	temp_fname = t_strconcat(fname, ".tmp", NULL);
	(void)unlink(temp_fname);

	old_mask = umask(0);
	fd = open(temp_fname, O_WRONLY | O_CREAT | O_EXCL, 0644);
	umask(old_mask);

	if (fd == -1) {
		i_fatal("Can't create temporary SSL parameters file %s: %m",
			temp_fname);
	}

	_ssl_generate_parameters(fd, temp_fname);

	if (close(fd) < 0)
		i_fatal("close(%s) failed: %m", temp_fname);

	if (rename(temp_fname, fname) < 0)
		i_fatal("rename(%s, %s) failed: %m", temp_fname, fname);

	i_info("SSL parameters regeneration completed");
}
#else
static void generate_parameters_file(const char *fname __attr_unused__)
{
	i_fatal("Dovecot built without SSL support");
}
#endif

int main(int argc, char *argv[])
{
	lib_init();
	i_set_failure_internal();

	if (argc < 2)
		i_fatal("Usage: ssl-build-param <path>");

	random_init();
	generate_parameters_file(argv[1]);

	random_deinit();
	lib_deinit();
	return 0;
}
