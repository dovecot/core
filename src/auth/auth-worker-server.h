#ifndef AUTH_WORKER_SERVER_H
#define AUTH_WORKER_SERVER_H

#define AUTH_MASTER_NAME "auth-master"
#define AUTH_WORKER_NAME "auth-worker"
#define AUTH_WORKER_PROTOCOL_MAJOR_VERSION 1
#define AUTH_WORKER_PROTOCOL_MINOR_VERSION 0
#define AUTH_WORKER_MAX_LINE_LENGTH 8192

struct master_service_connection;
struct auth_worker_command;

struct auth_worker_server *
auth_worker_server_create(struct auth *auth,
			  const struct master_service_connection *master_conn);
bool auth_worker_auth_request_new(struct auth_worker_command *cmd, unsigned int id,
				  const char *const *args, struct auth_request **request_r);

bool auth_worker_has_connections(void);
void auth_worker_server_send_error(void);
void auth_worker_server_send_success(void);
void auth_worker_server_send_shutdown(void);

void auth_worker_connections_destroy_all(void);

/* Stop master service after this many requests. 0 is unlimited. */
void auth_worker_set_max_service_count(unsigned int count);

#endif
