#ifndef AUTH_WORKER_CLIENT_H
#define AUTH_WORKER_CLIENT_H

#define AUTH_WORKER_PROTOCOL_MAJOR_VERSION 1
#define AUTH_WORKER_PROTOCOL_MINOR_VERSION 0
#define AUTH_WORKER_MAX_LINE_LENGTH 8192

struct master_service_connection;
struct auth_worker_command;

struct auth_worker_client *
auth_worker_client_create(struct auth *auth,
			  const struct master_service_connection *master_conn);
bool auth_worker_auth_request_new(struct auth_worker_command *cmd, unsigned int id,
				  const char *const *args, struct auth_request **request_r);

bool auth_worker_has_client(void);
void auth_worker_client_send_error(void);
void auth_worker_client_send_success(void);
void auth_worker_client_send_shutdown(void);

void auth_worker_connections_destroy_all(void);

#endif
