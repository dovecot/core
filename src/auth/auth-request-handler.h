#ifndef AUTH_REQUEST_HANDLER_H
#define AUTH_REQUEST_HANDLER_H

struct auth_request;
struct auth_master_connection;
struct auth_stream_reply;

typedef void
auth_request_callback_t(struct auth_stream_reply *reply, void *context);

struct auth_request_handler *
auth_request_handler_create(auth_request_callback_t *callback, void *context,
			    auth_request_callback_t *master_callback);
#ifdef CONTEXT_TYPE_SAFETY
#  define auth_request_handler_create(callback, context, master_callback)\
	({(void)(1 ? 0 : callback((struct auth_stream_reply *)NULL, context)); \
	  auth_request_handler_create( \
		(auth_request_callback_t *)callback, context, \
		master_callback); })
#else
#  define auth_request_handler_create(callback, context, master_callback)\
	  auth_request_handler_create( \
		(auth_request_callback_t *)callback, context, \
		master_callback)
#endif
void auth_request_handler_unref(struct auth_request_handler **handler);

void auth_request_handler_set(struct auth_request_handler *handler,
			      unsigned int connect_uid,
			      unsigned int client_pid);

bool auth_request_handler_auth_begin(struct auth_request_handler *handler,
				     const char *args);
bool auth_request_handler_auth_continue(struct auth_request_handler *handler,
					const char *args);
void auth_request_handler_master_request(struct auth_request_handler *handler,
					 struct auth_master_connection *master,
					 unsigned int id,
					 unsigned int client_id);

void auth_request_handler_flush_failures(bool flush_all);

void auth_request_handler_init(void);
void auth_request_handler_deinit(void);

#endif
