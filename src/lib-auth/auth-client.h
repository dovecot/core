#ifndef AUTH_CLIENT_H
#define AUTH_CLIENT_H

#include "network.h"
#include "auth-client-interface.h"

struct auth_client;
struct auth_client_request;

enum auth_request_flags {
	AUTH_REQUEST_FLAG_SECURED		= 0x01,
	AUTH_REQUEST_FLAG_VALID_CLIENT_CERT	= 0x02,
	/* Skip penalty checks for this request */
	AUTH_REQUEST_FLAG_NO_PENALTY		= 0x04
};

enum auth_request_status {
	AUTH_REQUEST_STATUS_FAIL = -1,
	AUTH_REQUEST_STATUS_CONTINUE,
	AUTH_REQUEST_STATUS_OK
};

struct auth_mech_desc {
	char *name;
        enum mech_security_flags flags;
};

struct auth_connect_id {
	unsigned int server_pid;
	unsigned int connect_uid;
};

struct auth_request_info {
	const char *mech;
	const char *service;
	const char *cert_username;
	enum auth_request_flags flags;

	struct ip_addr local_ip, remote_ip;
	unsigned int local_port, remote_port;

	const char *initial_resp_base64;
};

typedef void auth_request_callback_t(struct auth_client_request *request,
				     enum auth_request_status status,
				     const char *data_base64,
				     const char *const *args, void *context);

typedef void auth_connect_notify_callback_t(struct auth_client *client,
					    bool connected, void *context);

/* Create new authentication client. */
struct auth_client *
auth_client_init(const char *auth_socket_path, unsigned int client_pid,
		 bool debug);
void auth_client_deinit(struct auth_client **client);

void auth_client_connect(struct auth_client *client);
void auth_client_disconnect(struct auth_client *client);
bool auth_client_is_connected(struct auth_client *client);
bool auth_client_is_disconnected(struct auth_client *client);
void auth_client_set_connect_notify(struct auth_client *client,
				    auth_connect_notify_callback_t *callback,
				    void *context);
const struct auth_mech_desc *
auth_client_get_available_mechs(struct auth_client *client,
				unsigned int *mech_count);
const struct auth_mech_desc *
auth_client_find_mech(struct auth_client *client, const char *name);

/* Return current connection's identifiers. */
void auth_client_get_connect_id(struct auth_client *client,
				unsigned int *server_pid_r,
				unsigned int *connect_uid_r);

/* Create a new authentication request. callback is called whenever something
   happens for the request. */
struct auth_client_request *
auth_client_request_new(struct auth_client *client,
			const struct auth_request_info *request_info,
			auth_request_callback_t *callback, void *context);
/* Continue authentication. Call when
   reply->result == AUTH_CLIENT_REQUEST_CONTINUE */
void auth_client_request_continue(struct auth_client_request *request,
				  const char *data_base64);
/* Abort ongoing authentication request. */
void auth_client_request_abort(struct auth_client_request **request);
/* Return ID of this request. */
unsigned int auth_client_request_get_id(struct auth_client_request *request);
/* Return the PID of the server that handled this request. */
unsigned int
auth_client_request_get_server_pid(struct auth_client_request *request);
/* Return cookie of the server that handled this request. */
const char *auth_client_request_get_cookie(struct auth_client_request *request);

/* Tell auth process to drop specified request from memory */
void auth_client_send_cancel(struct auth_client *client, unsigned int id);

#endif
