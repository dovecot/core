#ifndef RESTRICT_PROCESS_SIZE_H
#define RESTRICT_PROCESS_SIZE_H

#include <sys/time.h>
#ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
#endif

/* Restrict max. process size. The size is in megabytes, setting it to
   (unsigned int)-1 sets it unlimited. */
void restrict_process_size(unsigned int size, unsigned int max_processes);
/* Set fd limit to count. */
void restrict_fd_limit(unsigned int count);

/* Get the core dump size limit. Returns 0 if ok, -1 if lookup failed. */
int restrict_get_core_limit(rlim_t *limit_r);

#endif
