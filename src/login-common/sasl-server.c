/* Copyright (C) 2002-2004 Timo Sirainen */

#include "common.h"
#include "base64.h"
#include "buffer.h"
#include "str-sanitize.h"
#include "auth-client.h"
#include "ssl-proxy.h"
#include "client-common.h"
#include "master.h"

/* Used only for string sanitization while verbose_auth is set. */
#define MAX_MECH_NAME 64

static enum auth_client_request_new_flags
client_get_auth_flags(struct client *client)
{
        enum auth_client_request_new_flags auth_flags = 0;

	if (client->proxy != NULL &&
	    ssl_proxy_has_valid_client_cert(client->proxy))
		auth_flags |= AUTH_CLIENT_FLAG_SSL_VALID_CLIENT_CERT;
	if (client->tls)
		auth_flags |= AUTH_CLIENT_FLAG_SSL_ENABLED;
	return auth_flags;
}

static void master_callback(struct client *client, int success)
{
	client->authenticating = FALSE;
	i_free(client->auth_mech_name);
	client->auth_mech_name = NULL;

	client->sasl_callback(client, success ? SASL_SERVER_REPLY_SUCCESS :
			      SASL_SERVER_REPLY_MASTER_FAILED, NULL);
}

static const char *auth_client_get_str(struct auth_client_request_reply *reply,
				       const unsigned char *data, size_t idx)
{
	size_t stop;

	if (idx >= reply->data_size || idx >= reply->reply_idx)
		return NULL;

	stop = reply->reply_idx < reply->data_size ?
		reply->reply_idx-1 : reply->data_size;

	return t_strndup(data + idx, stop);
}

static void authenticate_callback(struct auth_request *request,
				  struct auth_client_request_reply *reply,
				  const unsigned char *data, void *context)
{
	struct client *client = context;
	buffer_t *buf;
	const char *user, *error;

	if (!client->authenticating) {
		/* client aborted */
		i_assert(reply == NULL);
		return;
	}

	if (reply == NULL) {
		/* failed */
		client->auth_request = NULL;
		sasl_server_auth_cancel(client, "Authentication process died.");
		return;
	}

	switch (reply->result) {
	case AUTH_CLIENT_RESULT_CONTINUE:
		if (client->auth_request != NULL) {
			i_assert(client->auth_request == request);
		} else {
			i_assert(client->auth_request == NULL);

			client->auth_request = request;
		}

		t_push();
		buf = buffer_create_dynamic(pool_datastack_create(),
				MAX_BASE64_ENCODED_SIZE(reply->data_size));
		base64_encode(data, reply->data_size, buf);
		buffer_append_c(buf, '\0');

		client->sasl_callback(client, SASL_SERVER_REPLY_CONTINUE,
				      buf->data);
		t_pop();
		break;
	case AUTH_CLIENT_RESULT_SUCCESS:
		client->auth_request = NULL;

		user = auth_client_get_str(reply, data, reply->username_idx);
		i_free(client->virtual_user);
		client->virtual_user = i_strdup(user);

		master_request_login(client, master_callback,
				auth_client_request_get_server_pid(request),
				auth_client_request_get_id(request));
		break;
	case AUTH_CLIENT_RESULT_FAILURE:
		client->auth_request = NULL;

		/* see if we have error message */
		if (reply->data_size > 0 && data[reply->data_size-1] == '\0') {
			error = t_strconcat("Authentication failed: ",
					    (const char *)data, NULL);
		} else {
			error = NULL;
		}
		sasl_server_auth_cancel(client, error);
		break;
	}
}

void sasl_server_auth_begin(struct client *client,
			    const char *protocol, const char *mech_name,
			    const unsigned char *initial_resp,
			    size_t initial_resp_size,
			    sasl_server_callback_t *callback)
{
	struct auth_request_info info;
	const struct auth_mech_desc *mech;
	const char *error;

	client->authenticating = TRUE;
	client->auth_mech_name = i_strdup(mech_name);
	client->sasl_callback = callback;

	mech = auth_client_find_mech(auth_client, mech_name);
	if (mech == NULL) {
		sasl_server_auth_cancel(client, 
			"Unsupported authentication mechanism.");
		return;
	}

	if (!client->secured && mech->plaintext && disable_plaintext_auth) {
		sasl_server_auth_cancel(client,
					"Plaintext authentication disabled.");
		return;
	}

	memset(&info, 0, sizeof(info));
	info.mech = mech->name;
	info.protocol = protocol;
	info.flags = client_get_auth_flags(client);
	info.local_ip = client->local_ip;
	info.remote_ip = client->ip;
	info.initial_resp_data = initial_resp;
	info.initial_resp_size = initial_resp_size;

	client->auth_request =
		auth_client_request_new(auth_client, NULL, &info,
					authenticate_callback, client, &error);
	if (client->auth_request == NULL) {
		sasl_server_auth_cancel(client,
			 t_strconcat("Authentication failed: ", error, NULL));
	}
}

void sasl_server_auth_cancel(struct client *client, const char *reason)
{
	if (verbose_auth && reason != NULL) {
		client_syslog(client, "Authenticate %s failed: %s",
			      str_sanitize(client->auth_mech_name,
					   MAX_MECH_NAME), reason);
	}

	client->authenticating = FALSE;
	i_free(client->auth_mech_name);
	client->auth_mech_name = NULL;

	if (client->auth_request != NULL) {
		auth_client_request_abort(client->auth_request);
		client->auth_request = NULL;
	}

	client->sasl_callback(client, SASL_SERVER_REPLY_AUTH_FAILED, reason);
}
