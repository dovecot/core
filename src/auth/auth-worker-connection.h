#ifndef AUTH_WORKER_CONNECTION_H
#define AUTH_WORKER_CONNECTION_H

struct auth_request;
struct auth_stream_reply;
struct auth_worker_connection;

typedef bool auth_worker_callback_t(struct auth_worker_connection *conn,
				    const char *const *args, void *context);

void auth_worker_call(pool_t pool, const char *username, const char *data,
		      auth_worker_callback_t *callback, void *context);
void auth_worker_connection_resume_input(struct auth_worker_connection *conn);

void auth_worker_connection_init(void);
void auth_worker_connection_deinit(void);

#endif
