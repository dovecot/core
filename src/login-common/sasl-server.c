/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "base64.h"
#include "buffer.h"
#include "istream.h"
#include "write-full.h"
#include "strescape.h"
#include "str-sanitize.h"
#include "auth-client.h"
#include "ssl-proxy.h"
#include "master-interface.h"
#include "master-auth.h"
#include "client-common.h"

#include <stdlib.h>
#include <unistd.h>

#define ERR_TOO_MANY_USERIP_CONNECTIONS \
	"Maximum number of connections from user+IP exceeded " \
	"(mail_max_userip_connections)"

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
master_auth_callback(const struct master_auth_reply *reply, void *context)
{
	struct client *client = context;
	enum sasl_server_reply sasl_reply = SASL_SERVER_REPLY_MASTER_FAILED;
	const char *data = NULL;

	client->master_tag = 0;
	client->authenticating = FALSE;
	switch (reply->status) {
	case MASTER_AUTH_STATUS_OK:
		sasl_reply = SASL_SERVER_REPLY_SUCCESS;
		break;
	case MASTER_AUTH_STATUS_INTERNAL_ERROR:
		break;
	}
	client->mail_pid = reply->mail_pid;
	call_client_callback(client, sasl_reply, data, NULL);
}

static void
master_send_request(struct client *client, struct auth_request *request)
{
	struct master_auth_request req;
	const unsigned char *data;
	size_t size;
	buffer_t *buf;

	memset(&req, 0, sizeof(req));
	req.auth_pid = auth_client_request_get_server_pid(request);
	req.auth_id = auth_client_request_get_id(request);
	req.local_ip = client->local_ip;
	req.remote_ip = client->ip;

	buf = buffer_create_dynamic(pool_datastack_create(), 256);
	if (client->auth_command_tag != NULL) {
		buffer_append(buf, client->auth_command_tag,
			      strlen(client->auth_command_tag)+1);
	}

	data = i_stream_get_data(client->input, &size);
	buffer_append(buf, data, size);
	req.data_size = buf->used;

	client->master_tag =
		master_auth_request(service, client->fd, &req, buf->data,
				    master_auth_callback, client);
}

static bool anvil_has_too_many_connections(struct client *client)
{
	const char *ident;
	char buf[64];
	ssize_t ret;

	if (client->virtual_user == NULL)
		return FALSE;
	if (client->set->mail_max_userip_connections == 0)
		return FALSE;

	ident = t_strconcat("LOOKUP\t", net_ip2addr(&client->ip), "/",
			    str_tabescape(client->virtual_user), "/",
			    login_protocol, "\n", NULL);
	if (write_full(anvil_fd, ident, strlen(ident)) < 0)
		i_fatal("write(anvil) failed: %m");
	ret = read(anvil_fd, buf, sizeof(buf)-1);
	if (ret < 0)
		i_fatal("read(anvil) failed: %m");
	else if (ret == 0)
		i_fatal("read(anvil) failed: EOF");
	if (buf[ret-1] != '\n')
		i_fatal("anvil lookup failed: Invalid input in reply");
	buf[ret-1] = '\0';

	return strtoul(buf, NULL, 10) >=
		client->set->mail_max_userip_connections;
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
		} else if (anvil_has_too_many_connections(client)) {
			client->authenticating = FALSE;
			call_client_callback(client,
					SASL_SERVER_REPLY_MASTER_FAILED,
					ERR_TOO_MANY_USERIP_CONNECTIONS, NULL);
		} else {
			master_send_request(client, request);
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

	client->auth_attempts++;
	client->authenticating = TRUE;
	i_free(client->auth_mech_name);
	client->auth_mech_name = str_ucase(i_strdup(mech_name));
	client->sasl_callback = callback;

	mech = auth_client_find_mech(auth_client, mech_name);
	if (mech == NULL) {
		sasl_server_auth_failed(client,
			"Unsupported authentication mechanism.");
		return;
	}

	if (!client->secured && client->set->disable_plaintext_auth &&
	    (mech->flags & MECH_SEC_PLAINTEXT) != 0) {
		sasl_server_auth_failed(client,
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

	if (client->set->verbose_auth && reason != NULL) {
		const char *auth_name =
			str_sanitize(client->auth_mech_name, MAX_MECH_NAME);
		client_syslog(client,
			t_strdup_printf("Authenticate %s failed: %s",
					auth_name, reason));
	}

	client->authenticating = FALSE;
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
