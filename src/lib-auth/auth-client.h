#ifndef AUTH_CLIENT_H
#define AUTH_CLIENT_H

#include "network.h"
#include "auth-client-interface.h"

struct auth_client;
struct auth_request;

enum auth_request_flags {
	AUTH_REQUEST_FLAG_SECURED		= 0x01,
	AUTH_REQUEST_FLAG_VALID_CLIENT_CERT	= 0x02
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

typedef void auth_request_callback_t(struct auth_request *request, int status,
				     const char *data_base64,
				     const char *const *args, void *context);

typedef void auth_connect_notify_callback_t(struct auth_client *client,
					    bool connected, void *context);

/* Create new authentication client. */
struct auth_client *auth_client_new(unsigned int client_pid);
void auth_client_free(struct auth_client **client);

/* Destroy all connections and reconnect. */
void auth_client_reconnect(struct auth_client *client);

bool auth_client_is_connected(struct auth_client *client);
void auth_client_set_connect_notify(struct auth_client *client,
				    auth_connect_notify_callback_t *callback,
				    void *context);
const struct auth_mech_desc *
auth_client_get_available_mechs(struct auth_client *client,
				unsigned int *mech_count);
const struct auth_mech_desc *
auth_client_find_mech(struct auth_client *client, const char *name);

/* Reserve connection for specific mechanism. The id can be given to
   auth_client_request_new() to force it to use the same connection, or fail.
   This is currently useful only for APOP authentication. Returns TRUE if
   successfull. */
bool auth_client_reserve_connection(struct auth_client *client,
				    const char *mech,
				    struct auth_connect_id *id_r);

/* Create a new authentication request. callback is called whenever something
   happens for the request. id can be NULL. */
struct auth_request *
auth_client_request_new(struct auth_client *client, struct auth_connect_id *id,
			const struct auth_request_info *request_info,
			auth_request_callback_t *callback, void *context,
			const char **error_r);
/* Continue authentication. Call when
   reply->result == AUTH_CLIENT_REQUEST_CONTINUE */
void auth_client_request_continue(struct auth_request *request,
				  const char *data_base64);

/* Abort ongoing authentication request. */
void auth_client_request_abort(struct auth_request *request);

/* Return ID of this request. */
unsigned int auth_client_request_get_id(struct auth_request *request);

/* Return the PID of the server that handled this request. */
unsigned int auth_client_request_get_server_pid(struct auth_request *request);

void auth_client_connect_missing_servers(struct auth_client *client);

#endif
