#ifndef ADMIN_CLIENT_POOL_H
#define ADMIN_CLIENT_POOL_H

#include "admin-client.h"

struct admin_client_pool *
admin_client_pool_init(const char *base_dir, unsigned int max_connections);
void admin_client_pool_deinit(struct admin_client_pool **pool);

void admin_client_pool_send_cmd(struct admin_client_pool *pool,
				const char *service, pid_t pid, const char *cmd,
				admin_client_callback_t *callback,
				void *context);

#endif
