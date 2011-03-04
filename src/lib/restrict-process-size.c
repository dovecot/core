/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "restrict-process-size.h"

#include <unistd.h>

void restrict_process_size(unsigned int size ATTR_UNUSED,
			   unsigned int max_processes ATTR_UNUSED)
{
#ifdef HAVE_SETRLIMIT
	struct rlimit rlim;

#ifdef HAVE_RLIMIT_NPROC
	if (max_processes < INT_MAX) {
		rlim.rlim_max = rlim.rlim_cur = max_processes;
		if (setrlimit(RLIMIT_NPROC, &rlim) < 0)
			i_fatal("setrlimit(RLIMIT_NPROC, %u): %m", size);
	}
#endif

	if (size > 0 && size < INT_MAX/1024/1024) {
		rlim.rlim_max = rlim.rlim_cur = size*1024*1024;

		if (setrlimit(RLIMIT_DATA, &rlim) < 0)
			i_fatal("setrlimit(RLIMIT_DATA, %u): %m", size);

#ifdef HAVE_RLIMIT_AS
		if (setrlimit(RLIMIT_AS, &rlim) < 0)
			i_fatal("setrlimit(RLIMIT_AS, %u): %m", size);
#endif
	}
#else
	if (size != 0) {
		i_warning("Can't restrict process size: "
			  "setrlimit() not supported by system. "
			  "Set the limit to 0 to hide this warning.");
	}
#endif
}

void restrict_fd_limit(unsigned int count)
{
#ifdef HAVE_SETRLIMIT
	struct rlimit rlim;

	rlim.rlim_cur = rlim.rlim_max = count;
	if (setrlimit(RLIMIT_NOFILE, &rlim) < 0)
		i_error("setrlimit(RLIMIT_NOFILE, %u): %m", count);
#endif
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
