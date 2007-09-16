#ifndef RESTRICT_PROCESS_SIZE_H
#define RESTRICT_PROCESS_SIZE_H

/* Restrict max. process size. The size is in megabytes, setting it to
   (unsigned int)-1 sets it unlimited. */
void restrict_process_size(unsigned int size, unsigned int max_processes);
/* Set fd limit to count. */
void restrict_fd_limit(unsigned int count);

#endif
