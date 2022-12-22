#ifndef SASL_SERVER_H
#define SASL_SERVER_H

struct auth_request_info;
struct client;

enum sasl_server_reply {
	SASL_SERVER_REPLY_SUCCESS,
	SASL_SERVER_REPLY_AUTH_FAILED,
	SASL_SERVER_REPLY_AUTH_ABORTED,
	SASL_SERVER_REPLY_MASTER_FAILED,
	SASL_SERVER_REPLY_CONTINUE
};

enum sasl_server_auth_flags {
	/* Allow the use of private mechanism */
	SASL_SERVER_AUTH_FLAG_PRIVATE = BIT(0),
	/* Signal to the post-login service that this is an implicit login,
	   meaning that no command success reply is expected. */
	SASL_SERVER_AUTH_FLAG_IMPLICIT = BIT(1),
};

typedef void sasl_server_callback_t(struct client *client,
				    enum sasl_server_reply reply,
				    const char *data, const char *const *args);

const struct auth_mech_desc *
sasl_server_get_advertised_mechs(struct client *client, unsigned int *count_r);
const struct auth_mech_desc *
sasl_server_find_available_mech(struct client *client, const char *name);

int sasl_server_auth_request_info_fill(struct client *client,
				       struct auth_request_info *info_r,
				       const char **client_error_r);

void sasl_server_auth_begin(struct client *client, const char *mech_name,
			    enum sasl_server_auth_flags flags,
			    const char *initial_resp_base64,
			    sasl_server_callback_t *callback);
void sasl_server_auth_failed(struct client *client, const char *reason,
	const char *code) ATTR_NULL(3);
/* Called when client asks for SASL authentication to be aborted by sending
   "*" line. */
void sasl_server_auth_abort(struct client *client);

#endif
