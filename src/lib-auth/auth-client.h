#ifndef __AUTH_CLIENT_H
#define __AUTH_CLIENT_H

#include "../auth/auth-client-interface.h"

struct auth_client;
struct auth_request;

/* reply is NULL if auth connection died */
typedef void auth_request_callback_t(struct auth_request *request,
				     struct auth_client_request_reply *reply,
				     const unsigned char *data, void *context);

typedef void auth_connect_notify_callback_t(struct auth_client *client,
					    int connected, void *context);

/* Create new authentication client. */
struct auth_client *auth_client_new(unsigned int client_pid);
void auth_client_free(struct auth_client *client);

int auth_client_is_connected(struct auth_client *client);
void auth_client_set_connect_notify(struct auth_client *client,
				    auth_connect_notify_callback_t *callback,
				    void *context);
enum auth_mech auth_client_get_available_mechs(struct auth_client *client);

void auth_client_connect_missing_servers(struct auth_client *client);

/* Create a new authentication request. callback is called whenever something
   happens for the request. */
struct auth_request *
auth_client_request_new(struct auth_client *client,
			enum auth_mech mech, enum auth_protocol protocol,
			enum auth_client_request_new_flags flags,
			auth_request_callback_t *callback, void *context,
			const char **error_r);

/* Continue authentication. Call when
   reply->result == AUTH_CLIENT_REQUEST_CONTINUE */
void auth_client_request_continue(struct auth_request *request,
				  const unsigned char *data, size_t data_size);

/* Abort ongoing authentication request. */
void auth_client_request_abort(struct auth_request *request);

/* Return ID of this request. */
unsigned int auth_client_request_get_id(struct auth_request *request);

/* Return the PID of the server that handled this request. */
unsigned int auth_client_request_get_server_pid(struct auth_request *request);

#endif
