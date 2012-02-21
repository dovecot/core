#ifndef RESTRICT_PROCESS_SIZE_H
#define RESTRICT_PROCESS_SIZE_H

#include <sys/time.h>
#ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
#endif

/* Restrict max. process size. */
void restrict_process_size(rlim_t bytes);
/* Restrict max. number of processes. */
void restrict_process_count(rlim_t count);
/* Set fd limit to count. */
void restrict_fd_limit(rlim_t count);

/* Get the core dump size limit. Returns 0 if ok, -1 if lookup failed. */
int restrict_get_core_limit(rlim_t *limit_r);
/* Get the process VSZ size limit. Returns 0 if ok, -1 if lookup failed. */
int restrict_get_process_size(rlim_t *limit_r);
/* Get the process count limit. Returns 0 if ok, -1 if lookup failed. */
int restrict_get_process_limit(rlim_t *limit_r);
/* Get the fd limit. Returns 0 if ok, -1 if lookup failed. */
int restrict_get_fd_limit(rlim_t *limit_r);

#endif
