#ifndef __AUTH_CLIENT_H
#define __AUTH_CLIENT_H

#include "network.h"
#include "../auth/auth-client-interface.h"

struct auth_client;
struct auth_request;

struct auth_mech_desc {
	char *name;
	unsigned int plaintext:1;
	unsigned int advertise:1;
};

struct auth_request_info {
	const char *mech;
	const char *protocol;
	enum auth_client_request_new_flags flags;

	struct ip_addr local_ip, remote_ip;

	const unsigned char *initial_resp_data;
	size_t initial_resp_size;
};

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
const struct auth_mech_desc *
auth_client_get_available_mechs(struct auth_client *client,
				unsigned int *mech_count);
const struct auth_mech_desc *
auth_client_find_mech(struct auth_client *client, const char *name);

/* Create a new authentication request. callback is called whenever something
   happens for the request. */
struct auth_request *
auth_client_request_new(struct auth_client *client,
			const struct auth_request_info *request_info,
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

/* -- Using lib-auth with external I/O loop -- */

typedef void *input_func_add_t(int fd, void (*cb)(void *), void *context);
typedef void *input_func_remove_t(void *io);

struct auth_client *auth_client_new_external(unsigned int client_pid,
					     const char *socket_paths,
					     input_func_add_t *add_func,
					     input_func_remove_t *remove_func);
/* Call every few seconds. */
void auth_client_connect_missing_servers(struct auth_client *client);

#endif
