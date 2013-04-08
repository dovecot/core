/* Copyright (c) 2002-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "restrict-process-size.h"

#include <unistd.h>

void restrict_process_size(rlim_t bytes)
{
	struct rlimit rlim;

	rlim.rlim_max = rlim.rlim_cur = bytes;
	if (setrlimit(RLIMIT_DATA, &rlim) < 0) {
		i_fatal("setrlimit(RLIMIT_DATA, %llu): %m",
			(unsigned long long)bytes);
	}

#ifdef HAVE_RLIMIT_AS
	if (setrlimit(RLIMIT_AS, &rlim) < 0) {
		i_fatal("setrlimit(RLIMIT_AS, %llu): %m",
			(unsigned long long)bytes);
	}
#endif
}

void restrict_process_count(rlim_t count ATTR_UNUSED)
{
#ifdef HAVE_RLIMIT_NPROC
	struct rlimit rlim;

	rlim.rlim_max = rlim.rlim_cur = count;
	if (setrlimit(RLIMIT_NPROC, &rlim) < 0) {
		i_error("setrlimit(RLIMIT_NPROC, %llu): %m",
			(unsigned long long)count);
	}
#endif
}

void restrict_fd_limit(rlim_t count)
{
#ifdef HAVE_SETRLIMIT
	struct rlimit rlim;

	rlim.rlim_cur = rlim.rlim_max = count;
	if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
		i_error("setrlimit(RLIMIT_NOFILE, %llu): %m",
			(unsigned long long)count);
	}
#endif
}

int restrict_get_process_size(rlim_t *limit_r)
{
	struct rlimit rlim;

#ifdef HAVE_RLIMIT_AS
	if (getrlimit(RLIMIT_AS, &rlim) < 0) {
		i_error("getrlimit(RLIMIT_AS): %m");
		return -1;
	}
#else
	if (getrlimit(RLIMIT_DATA, &rlim) < 0) {
		i_error("getrlimit(RLIMIT_DATA): %m");
		return -1;
	}
#endif
	*limit_r = rlim.rlim_cur;
	return 0;
}

int restrict_get_core_limit(rlim_t *limit_r)
{
#ifdef HAVE_RLIMIT_CORE
	struct rlimit rlim;

	if (getrlimit(RLIMIT_CORE, &rlim) < 0) {
		i_error("getrlimit(RLIMIT_CORE) failed: %m");
		return -1;
	}
	*limit_r = rlim.rlim_cur;
	return 0;
#else
	return -1;
#endif
}

int restrict_get_process_limit(rlim_t *limit_r)
{
#ifdef HAVE_RLIMIT_NPROC
	struct rlimit rlim;

	if (getrlimit(RLIMIT_NPROC, &rlim) < 0) {
		i_error("getrlimit(RLIMIT_NPROC) failed: %m");
		return -1;
	}
	*limit_r = rlim.rlim_cur;
	return 0;
#else
	return -1;
#endif
}

int restrict_get_fd_limit(rlim_t *limit_r)
{
	struct rlimit rlim;

	if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
		i_error("getrlimit(RLIMIT_NOFILE) failed: %m");
		return -1;
	}
	*limit_r = rlim.rlim_cur;
	return 0;
}
