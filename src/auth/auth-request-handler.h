#ifndef AUTH_REQUEST_HANDLER_H
#define AUTH_REQUEST_HANDLER_H

struct auth_request;
struct auth_client_connection;
struct auth_master_connection;
struct auth_stream_reply;

enum auth_client_result {
	AUTH_CLIENT_RESULT_CONTINUE = 1,
	AUTH_CLIENT_RESULT_SUCCESS,
	AUTH_CLIENT_RESULT_FAILURE
};

typedef void
auth_client_request_callback_t(const char *reply, struct auth_client_connection *conn);
typedef void
auth_master_request_callback_t(const char *reply, struct auth_master_connection *conn);

typedef void
auth_request_handler_reply_callback_t(struct auth_request *request,
				      enum auth_client_result result,
				      const void *auth_reply,
				      size_t reply_size);
typedef void
auth_request_handler_reply_continue_callback_t(struct auth_request *request,
					       const void *reply,
					       size_t reply_size);


struct auth_request_handler *
auth_request_handler_create(bool token_auth, auth_client_request_callback_t *callback,
			    struct auth_client_connection *conn,
			    auth_master_request_callback_t *master_callback);

void auth_request_handler_destroy(struct auth_request_handler **handler);
void auth_request_handler_unref(struct auth_request_handler **handler);
void auth_request_handler_abort_requests(struct auth_request_handler *handler);

void auth_request_handler_set(struct auth_request_handler *handler,
			      unsigned int connect_uid,
			      unsigned int client_pid);

bool auth_request_handler_auth_begin(struct auth_request_handler *handler,
				     const char *args);
bool auth_request_handler_auth_continue(struct auth_request_handler *handler,
					const char *args);
void auth_request_handler_reply(struct auth_request *request,
				enum auth_client_result result,
				const void *reply, size_t reply_size);
void auth_request_handler_reply_continue(struct auth_request *request,
					 const void *reply, size_t reply_size);
unsigned int
auth_request_handler_get_request_count(struct auth_request_handler *handler);
bool auth_request_handler_master_request(struct auth_request_handler *handler,
					 struct auth_master_connection *master,
					 unsigned int id, unsigned int client_id,
					 const char *const *params);
void auth_request_handler_cancel_request(struct auth_request_handler *handler,
					 unsigned int client_id);

void auth_request_handler_flush_failures(bool flush_all);

void auth_request_handler_init(void);
void auth_request_handler_deinit(void);

#endif
