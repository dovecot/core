#ifndef SERVICE_LOG_H
#define SERVICE_LOG_H

#include "dup2-array.h"

int services_log_init(struct service_list *service_list);
void services_log_deinit(struct service_list *service_list);

void services_log_dup2(ARRAY_TYPE(dup2) *dups,
		       struct service_list *service_list,
		       unsigned int first_fd, unsigned int *fd_count);

#endif
