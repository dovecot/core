#ifndef AUTH_REQUEST_HANDLER_PRIVATE_H
#define AUTH_REQUEST_HANDLER_PRIVATE_H

struct auth_request;
struct auth_client_connection;

struct auth_request_handler {
	int refcount;
	pool_t pool;
	HASH_TABLE(void *, struct auth_request *) requests;

        unsigned int connect_uid, client_pid;

	auth_client_request_callback_t *callback;
	struct auth_client_connection *conn;

	auth_master_request_callback_t *master_callback;
	auth_request_handler_reply_callback_t *reply_callback;
	auth_request_handler_reply_continue_callback_t *reply_continue_callback;
	verify_plain_continue_callback_t *verify_plain_continue_callback;

	bool destroyed:1;
	bool token_auth:1;
};


#endif
