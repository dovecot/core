#ifndef ANVIL_CONNECTION_H
#define ANVIL_CONNECTION_H

enum anvil_connection_type {
	ANVIL_CONNECTION_TYPE_ADMIN,
	ANVIL_CONNECTION_TYPE_SHARED_FIFO,
	ANVIL_CONNECTION_TYPE_AUTH_PENALTY,
	ANVIL_CONNECTION_TYPE_CONNECT_LIMIT,
};

/* Error is set and reply=NULL on internal errors. */
typedef void
anvil_connection_cmd_callback_t(const char *reply, const char *error,
				void *context);

void anvil_connection_create(int fd, enum anvil_connection_type type,
			     bool fifo);

/* Find an existing anvil connection from the specified process. */
struct anvil_connection *anvil_connection_find(const char *service, pid_t pid);

void anvil_connection_send_cmd(struct anvil_connection *conn,
			       const char *cmdline,
			       anvil_connection_cmd_callback_t *callback,
			       void *context);

void anvil_get_global_counts(unsigned int *connection_count_r,
			     unsigned int *kicks_pending_count_r,
			     unsigned int *cmd_counter_r,
			     unsigned int *connect_dump_counter_r);

void anvil_connections_init(const char *base_dir,
			    unsigned int max_kick_connections);
void anvil_connections_deinit(void);

#endif
