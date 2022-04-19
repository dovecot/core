#ifndef AUTH_WORKER_SERVER_H
#define AUTH_WORKER_SERVER_H

struct auth_request;
struct auth_stream_reply;
struct auth_worker_connection;

typedef bool auth_worker_callback_t(struct auth_worker_connection *conn,
				    const char *reply, void *context);

struct auth_worker_connection * ATTR_NOWARN_UNUSED_RESULT
auth_worker_call(pool_t pool, const char *username, const char *data,
		 auth_worker_callback_t *callback, void *context);
void auth_worker_server_resume_input(struct auth_worker_connection *conn);

void auth_worker_server_init(void);
void auth_worker_server_deinit(void);

#endif
