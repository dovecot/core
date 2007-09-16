#ifndef SASL_SERVER_H
#define SASL_SERVER_H

enum sasl_server_reply {
	SASL_SERVER_REPLY_SUCCESS,
	SASL_SERVER_REPLY_AUTH_FAILED,
	SASL_SERVER_REPLY_CLIENT_ERROR,
	SASL_SERVER_REPLY_MASTER_FAILED,
	SASL_SERVER_REPLY_CONTINUE
};

typedef void sasl_server_callback_t(struct client *client,
				    enum sasl_server_reply reply,
				    const char *data, const char *const *args);

void sasl_server_auth_begin(struct client *client,
			    const char *service, const char *mech_name,
			    const char *initial_resp_base64,
			    sasl_server_callback_t *callback);
void sasl_server_auth_failed(struct client *client, const char *reason);
void sasl_server_auth_client_error(struct client *client, const char *reason);

#endif
