/*
    Copyright (c) 2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "lib.h"
#include "restrict-process-size.h"

#include <unistd.h>
#include <sys/time.h>
#ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
#endif

void restrict_process_size(unsigned int size __attr_unused__,
			   unsigned int max_processes __attr_unused__)
{
#ifdef HAVE_SETRLIMIT
	struct rlimit rlim;

#ifdef HAVE_RLIMIT_NPROC
	rlim.rlim_max = rlim.rlim_cur =
		max_processes < INT_MAX ? max_processes : RLIM_INFINITY;
	if (setrlimit(RLIMIT_NPROC, &rlim) < 0)
		i_fatal("setrlimit(RLIMIT_NPROC, %u): %m", size);
#endif

	rlim.rlim_max = rlim.rlim_cur =
		size > 0 && size < INT_MAX/1024/1024 ?
		size*1024*1024 : RLIM_INFINITY;

	if (setrlimit(RLIMIT_DATA, &rlim) < 0)
		i_fatal("setrlimit(RLIMIT_DATA, %u): %m", size);

#ifdef HAVE_RLIMIT_AS
	if (setrlimit(RLIMIT_AS, &rlim) < 0)
		i_fatal("setrlimit(RLIMIT_AS, %u): %m", size);
#endif
#else
	if (size != 0) {
		i_warning("Can't restrict process size: "
			  "setrlimit() not supported by system. "
			  "Set the limit to 0 to hide this warning.");
	}
#endif
}
