#ifndef AUTH_WORKER_SERVER_H
#define AUTH_WORKER_SERVER_H

struct auth_request;
struct auth_stream_reply;

typedef void auth_worker_callback_t(struct auth_request *request,
				    const char *reply);

void auth_worker_call(struct auth_request *auth_request,
		      struct auth_stream_reply *data,
		      auth_worker_callback_t *callback);

void auth_worker_server_init(struct auth *auth);
void auth_worker_server_deinit(void);

#endif
