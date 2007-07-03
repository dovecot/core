/* Copyright (C) 2002-2004 Timo Sirainen */

#include "common.h"
#include "base64.h"
#include "buffer.h"
#include "str-sanitize.h"
#include "auth-client.h"
#include "ssl-proxy.h"
#include "client-common.h"
#include "master.h"

static enum auth_request_flags
client_get_auth_flags(struct client *client)
{
        enum auth_request_flags auth_flags = 0;

	if (client->proxy != NULL &&
	    ssl_proxy_has_valid_client_cert(client->proxy))
		auth_flags |= AUTH_REQUEST_FLAG_VALID_CLIENT_CERT;
	if (client->secured)
		auth_flags |= AUTH_REQUEST_FLAG_SECURED;
	return auth_flags;
}

static void
call_client_callback(struct client *client, enum sasl_server_reply reply,
		     const char *data, const char *const *args)
{
	sasl_server_callback_t *sasl_callback;

	i_assert(reply != SASL_SERVER_REPLY_CONTINUE);

	sasl_callback = client->sasl_callback;
	client->sasl_callback = NULL;

	sasl_callback(client, reply, data, args);
	/* NOTE: client may be destroyed now */
}

static void
master_callback(struct client *client, enum master_login_status status)
{
	enum sasl_server_reply reply = SASL_SERVER_REPLY_MASTER_FAILED;
	const char *data = NULL;

	client->authenticating = FALSE;
	switch (status) {
	case MASTER_LOGIN_STATUS_OK:
		reply = SASL_SERVER_REPLY_SUCCESS;
		break;
	case MASTER_LOGIN_STATUS_INTERNAL_ERROR:
		break;
	case MASTER_LOGIN_STATUS_MAX_CONNECTIONS:
		data = "Maximum number of connections exceeded";
		break;
	}
	call_client_callback(client, reply, data, NULL);
}

static void authenticate_callback(struct auth_request *request, int status,
				  const char *data_base64,
				  const char *const *args, void *context)
{
	struct client *client = context;
	unsigned int i;
	bool nologin;

	if (!client->authenticating) {
		/* client aborted */
		i_assert(status < 0);
		return;
	}

	i_assert(client->auth_request == request);
	client->waiting_auth_reply = FALSE;

	switch (status) {
	case 0:
		/* continue */
		client->sasl_callback(client, SASL_SERVER_REPLY_CONTINUE,
				      data_base64, NULL);
		break;
	case 1:
		client->auth_request = NULL;

		nologin = FALSE;
		for (i = 0; args[i] != NULL; i++) {
			if (strncmp(args[i], "user=", 5) == 0) {
				i_free(client->virtual_user);
				client->virtual_user = i_strdup(args[i] + 5);
			}
			if (strcmp(args[i], "nologin") == 0 ||
			    strcmp(args[i], "proxy") == 0) {
				/* user can't login */
				nologin = TRUE;
			}
		}

		if (nologin) {
			client->authenticating = FALSE;
			call_client_callback(client, SASL_SERVER_REPLY_SUCCESS,
					     NULL, args);
		} else {
			master_request_login(client, master_callback,
				auth_client_request_get_server_pid(request),
				auth_client_request_get_id(request));
		}
		break;
	case -1:
		client->auth_request = NULL;

		if (args != NULL) {
			/* parse our username if it's there */
			for (i = 0; args[i] != NULL; i++) {
				if (strncmp(args[i], "user=", 5) == 0) {
					i_free(client->virtual_user);
					client->virtual_user =
						i_strdup(args[i] + 5);
				}
			}
		}

		client->authenticating = FALSE;
		call_client_callback(client, SASL_SERVER_REPLY_AUTH_FAILED,
				     NULL, args);
		break;
	}
}

void sasl_server_auth_begin(struct client *client,
			    const char *service, const char *mech_name,
			    const char *initial_resp_base64,
			    sasl_server_callback_t *callback)
{
	struct auth_request_info info;
	const struct auth_mech_desc *mech;
	const char *error;

	client->authenticating = TRUE;
	i_free(client->auth_mech_name);
	client->auth_mech_name = str_ucase(i_strdup(mech_name));
	client->sasl_callback = callback;

	mech = auth_client_find_mech(auth_client, mech_name);
	if (mech == NULL) {
		sasl_server_auth_client_error(client,
			"Unsupported authentication mechanism.");
		return;
	}

	if (!client->secured && disable_plaintext_auth &&
	    (mech->flags & MECH_SEC_PLAINTEXT) != 0) {
		sasl_server_auth_client_error(client,
			"Plaintext authentication disabled.");
		return;
	}

	memset(&info, 0, sizeof(info));
	info.mech = mech->name;
	info.service = service;
	info.cert_username = client->proxy == NULL ? NULL :
		ssl_proxy_get_peer_name(client->proxy);
	info.flags = client_get_auth_flags(client);
	info.local_ip = client->local_ip;
	info.remote_ip = client->ip;
	info.local_port = client->local_port;
	info.remote_port = client->remote_port;
	info.initial_resp_base64 = initial_resp_base64;

	client->auth_request =
		auth_client_request_new(auth_client, NULL, &info,
					authenticate_callback, client, &error);
	if (client->auth_request == NULL) {
		sasl_server_auth_failed(client,
			 t_strconcat("Authentication failed: ", error, NULL));
	}
}

static void sasl_server_auth_cancel(struct client *client, const char *reason,
				    enum sasl_server_reply reply)
{
	i_assert(client->authenticating);

	if (verbose_auth && reason != NULL) {
		const char *auth_name =
			str_sanitize(client->auth_mech_name, MAX_MECH_NAME);
		client_syslog(client,
			t_strdup_printf("Authenticate %s failed: %s",
					auth_name, reason));
	}

	client->authenticating = FALSE;
	client->waiting_auth_reply = FALSE;

	if (client->auth_request != NULL) {
		auth_client_request_abort(client->auth_request);
		client->auth_request = NULL;
	}

	call_client_callback(client, reply, reason, NULL);
}

void sasl_server_auth_failed(struct client *client, const char *reason)
{
	sasl_server_auth_cancel(client, reason, SASL_SERVER_REPLY_AUTH_FAILED);
}

void sasl_server_auth_client_error(struct client *client, const char *reason)
{
	sasl_server_auth_cancel(client, reason, SASL_SERVER_REPLY_CLIENT_ERROR);
}
