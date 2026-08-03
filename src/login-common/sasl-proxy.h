#ifndef SASL_PROXY_H
#define SASL_PROXY_H

struct auth_request_info;
struct client;

enum sasl_proxy_reply {
	SASL_PROXY_REPLY_SUCCESS,
	SASL_PROXY_REPLY_AUTH_FAILED,
	SASL_PROXY_REPLY_AUTH_ABORTED,
	SASL_PROXY_REPLY_MASTER_FAILED,
	SASL_PROXY_REPLY_MASTER_FAILED_LIMIT,
	SASL_PROXY_REPLY_CONTINUE
};

enum sasl_proxy_auth_flags {
	/* Allow the use of private mechanism */
	SASL_PROXY_AUTH_FLAG_PRIVATE = BIT(0),
	/* Signal to the post-login service that this is an implicit login,
	   meaning that no command success reply is expected. */
	SASL_PROXY_AUTH_FLAG_IMPLICIT = BIT(1),
};

typedef void sasl_proxy_callback_t(struct client *client,
				   enum sasl_proxy_reply reply,
				   const char *data, const char *const *args);

const struct auth_mech_desc *
sasl_proxy_get_advertised_mechs(struct client *client, unsigned int *count_r);
const struct auth_mech_desc *
sasl_proxy_find_available_mech(struct client *client, const char *name);

int sasl_proxy_auth_request_info_fill(struct client *client,
				      struct auth_request_info *info_r,
				      const char **client_error_r);

void sasl_proxy_auth_begin(struct client *client, const char *mech_name,
			   enum sasl_proxy_auth_flags flags,
			   const char *initial_resp_base64,
			   sasl_proxy_callback_t *callback);
void sasl_proxy_auth_continue(struct client *client, const char *response);
void sasl_proxy_auth_failed(struct client *client, const char *reason,
	const char *code) ATTR_NULL(3);
/* Called when client asks for SASL authentication to be aborted by sending
   "*" line. */
void sasl_proxy_auth_abort(struct client *client, const char *reason);

#endif
