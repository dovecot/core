/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "str.h"
#include "base64.h"
#include "buffer.h"
#include "hex-binary.h"
#include "ioloop.h"
#include "istream.h"
#include "write-full.h"
#include "strescape.h"
#include "str-sanitize.h"
#include "anvil-client.h"
#include "auth-client.h"
#include "iostream-ssl.h"
#include "master-service.h"
#include "master-service-ssl-settings.h"
#include "master-interface.h"
#include "master-auth.h"
#include "client-common.h"

#include <unistd.h>

#define ERR_TOO_MANY_USERIP_CONNECTIONS \
	"Maximum number of connections from user+IP exceeded " \
	"(mail_max_userip_connections=%u)"

struct anvil_request {
	struct client *client;
	unsigned int auth_pid, auth_id;
	unsigned char cookie[MASTER_AUTH_COOKIE_SIZE];
};

static bool
sasl_server_filter_mech(struct client *client, struct auth_mech_desc *mech)
{
	if (client->v.sasl_filter_mech != NULL &&
	    !client->v.sasl_filter_mech(client, mech))
		return FALSE;
	return TRUE;
}

const struct auth_mech_desc *
sasl_server_get_advertised_mechs(struct client *client, unsigned int *count_r)
{
	const struct auth_mech_desc *mech;
	struct auth_mech_desc *ret_mech;
	unsigned int i, j, count;

	mech = auth_client_get_available_mechs(auth_client, &count);
	if (count == 0 || (!client->secured &&
			   strcmp(client->ssl_set->ssl, "required") == 0)) {
		*count_r = 0;
		return NULL;
	}

	ret_mech = t_new(struct auth_mech_desc, count);
	for (i = j = 0; i < count; i++) {
		struct auth_mech_desc fmech = mech[i];

		if (!sasl_server_filter_mech(client, &fmech))
			continue;

		/* a) transport is secured
		   b) auth mechanism isn't plaintext
		   c) we allow insecure authentication
		*/
		if ((fmech.flags & MECH_SEC_PRIVATE) == 0 &&
		    (client->secured || !client->set->disable_plaintext_auth ||
		     (fmech.flags & MECH_SEC_PLAINTEXT) == 0))
			ret_mech[j++] = fmech;
	}
	*count_r = j;
	return ret_mech;
}

const struct auth_mech_desc *
sasl_server_find_available_mech(struct client *client, const char *name)
{
	const struct auth_mech_desc *mech;
	struct auth_mech_desc fmech;

	mech = auth_client_find_mech(auth_client, name);
	if (mech == NULL)
		return NULL;

	fmech = *mech;
	if (!sasl_server_filter_mech(client, &fmech))
		return NULL;
	if (memcmp(&fmech, mech, sizeof(fmech)) != 0) {
		struct auth_mech_desc *nmech = t_new(struct auth_mech_desc, 1);

		*nmech = fmech;
		mech = nmech;
	}
	return mech;
}

static enum auth_request_flags
client_get_auth_flags(struct client *client)
{
        enum auth_request_flags auth_flags = 0;

	if (client->ssl_iostream != NULL &&
	    ssl_iostream_has_valid_client_cert(client->ssl_iostream))
		auth_flags |= AUTH_REQUEST_FLAG_VALID_CLIENT_CERT;
	if (client->tls || client->proxied_ssl)
		auth_flags |= AUTH_REQUEST_FLAG_TRANSPORT_SECURITY_TLS;
	if (client->secured)
		auth_flags |= AUTH_REQUEST_FLAG_SECURED;
	if (login_binary->sasl_support_final_reply)
		auth_flags |= AUTH_REQUEST_FLAG_SUPPORT_FINAL_RESP;
	return auth_flags;
}

static void ATTR_NULL(3, 4)
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
	if (reply != NULL) {
		switch (reply->status) {
		case MASTER_AUTH_STATUS_OK:
			sasl_reply = SASL_SERVER_REPLY_SUCCESS;
			break;
		case MASTER_AUTH_STATUS_INTERNAL_ERROR:
			sasl_reply = SASL_SERVER_REPLY_MASTER_FAILED;
			break;
		}
		client->mail_pid = reply->mail_pid;
	} else {
		auth_client_send_cancel(auth_client, client->master_auth_id);
	}
	call_client_callback(client, sasl_reply, data, NULL);
}

static int master_send_request(struct anvil_request *anvil_request)
{
	struct client *client = anvil_request->client;
	struct master_auth_request_params params;
	struct master_auth_request req;
	const unsigned char *data;
	size_t size;
	buffer_t *buf;
	const char *session_id = client_get_session_id(client);
	int fd;
	bool close_fd;

	if (client_get_plaintext_fd(client, &fd, &close_fd) < 0)
		return -1;

	i_zero(&req);
	req.auth_pid = anvil_request->auth_pid;
	req.auth_id = anvil_request->auth_id;
	req.local_ip = client->local_ip;
	req.remote_ip = client->ip;
	req.local_port = client->local_port;
	req.remote_port = client->remote_port;
	req.client_pid = getpid();
	if (client->ssl_iostream != NULL &&
	    ssl_iostream_get_compression(client->ssl_iostream) != NULL)
		req.flags |= MAIL_AUTH_REQUEST_FLAG_TLS_COMPRESSION;
	if (client->secured)
		req.flags |= MAIL_AUTH_REQUEST_FLAG_CONN_SECURED;
	if (client->ssl_secured)
		req.flags |= MAIL_AUTH_REQUEST_FLAG_CONN_SSL_SECURED;
	memcpy(req.cookie, anvil_request->cookie, sizeof(req.cookie));

	buf = t_buffer_create(256);
	/* session ID */
	buffer_append(buf, session_id, strlen(session_id)+1);
	/* protocol specific data (e.g. IMAP tag) */
	buffer_append(buf, client->master_data_prefix,
		      client->master_data_prefix_len);
	/* buffered client input */
	data = i_stream_get_data(client->input, &size);
	buffer_append(buf, data, size);
	req.data_size = buf->used;

	client->auth_finished = ioloop_time;
	client->master_auth_id = req.auth_id;

	i_zero(&params);
	params.client_fd = fd;
	params.socket_path = client->postlogin_socket_path;
	params.request = req;
	params.data = buf->data;
	master_auth_request_full(master_auth, &params, master_auth_callback,
				 client, &client->master_tag);
	if (close_fd)
		i_close_fd(&fd);
	return 0;
}

static void ATTR_NULL(1)
anvil_lookup_callback(const char *reply, void *context)
{
	struct anvil_request *req = context;
	struct client *client = req->client;
	const struct login_settings *set = client->set;
	const char *errmsg;
	unsigned int conn_count;
	int ret;

	conn_count = 0;
	if (reply != NULL && str_to_uint(reply, &conn_count) < 0)
		i_fatal("Received invalid reply from anvil: %s", reply);

	/* reply=NULL if we didn't need to do anvil lookup,
	   or if the anvil lookup failed. allow failed anvil lookups in. */
	if (reply == NULL || conn_count < set->mail_max_userip_connections) {
		ret = master_send_request(req);
		errmsg = NULL; /* client will see internal error */
	} else {
		ret = -1;
		errmsg = t_strdup_printf(ERR_TOO_MANY_USERIP_CONNECTIONS,
					 set->mail_max_userip_connections);
	}
	if (ret < 0) {
		client->authenticating = FALSE;
		auth_client_send_cancel(auth_client, req->auth_id);
		call_client_callback(client, SASL_SERVER_REPLY_MASTER_FAILED,
				     errmsg, NULL);
	}
	i_free(req);
}

static void
anvil_check_too_many_connections(struct client *client,
				 struct auth_client_request *request)
{
	struct anvil_request *req;
	const char *query, *cookie;
	buffer_t buf;

	req = i_new(struct anvil_request, 1);
	req->client = client;
	req->auth_pid = auth_client_request_get_server_pid(request);
	req->auth_id = auth_client_request_get_id(request);

	buffer_create_from_data(&buf, req->cookie, sizeof(req->cookie));
	cookie = auth_client_request_get_cookie(request);
	if (strlen(cookie) == MASTER_AUTH_COOKIE_SIZE*2)
		(void)hex_to_binary(cookie, &buf);

	if (client->virtual_user == NULL ||
	    client->set->mail_max_userip_connections == 0) {
		anvil_lookup_callback(NULL, req);
		return;
	}

	query = t_strconcat("LOOKUP\t", login_binary->protocol, "/",
			    net_ip2addr(&client->ip), "/",
			    str_tabescape(client->virtual_user), NULL);
	anvil_client_query(anvil, query, anvil_lookup_callback, req);
}

static void
authenticate_callback(struct auth_client_request *request,
		      enum auth_request_status status, const char *data_base64,
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
	client->auth_waiting = FALSE;

	i_assert(client->auth_request == request);
	switch (status) {
	case AUTH_REQUEST_STATUS_CONTINUE:
		/* continue */
		client->sasl_callback(client, SASL_SERVER_REPLY_CONTINUE,
				      data_base64, NULL);
		break;
	case AUTH_REQUEST_STATUS_OK:
		client->auth_request = NULL;
		client->auth_successes++;
		client->auth_passdb_args = p_strarray_dup(client->pool, args);
		client->postlogin_socket_path = NULL;

		nologin = FALSE;
		for (i = 0; args[i] != NULL; i++) {
			if (str_begins(args[i], "user=")) {
				i_free(client->virtual_user);
				i_free_and_null(client->virtual_user_orig);
				i_free_and_null(client->virtual_auth_user);
				client->virtual_user = i_strdup(args[i] + 5);
			} else if (str_begins(args[i], "original_user=")) {
				i_free(client->virtual_user_orig);
				client->virtual_user_orig = i_strdup(args[i] + 14);
			} else if (str_begins(args[i], "auth_user=")) {
				i_free(client->virtual_auth_user);
				client->virtual_auth_user =
					i_strdup(args[i] + 10);
			} else if (str_begins(args[i], "postlogin_socket=")) {
				client->postlogin_socket_path =
					p_strdup(client->pool, args[i] + 17);
			} else if (strcmp(args[i], "nologin") == 0 ||
				   strcmp(args[i], "proxy") == 0) {
				/* user can't login */
				nologin = TRUE;
			} else if (strcmp(args[i], "anonymous") == 0 ) {
				client->auth_anonymous = TRUE;
			} else if (str_begins(args[i], "resp=") &&
				   login_binary->sasl_support_final_reply) {
				client->sasl_final_resp =
					p_strdup(client->pool, args[i] + 5);
			}
		}

		if (nologin) {
			client->authenticating = FALSE;
			call_client_callback(client, SASL_SERVER_REPLY_SUCCESS,
					     NULL, args);
		} else {
			anvil_check_too_many_connections(client, request);
		}
		break;
	case AUTH_REQUEST_STATUS_INTERNAL_FAIL:
		client->auth_process_comm_fail = TRUE;
		/* fall through */
	case AUTH_REQUEST_STATUS_FAIL:
	case AUTH_REQUEST_STATUS_ABORT:
		client->auth_request = NULL;

		if (args != NULL) {
			/* parse our username if it's there */
			for (i = 0; args[i] != NULL; i++) {
				if (str_begins(args[i], "user=")) {
					i_free(client->virtual_user);
					i_free_and_null(client->virtual_user_orig);
					i_free_and_null(client->virtual_auth_user);
					client->virtual_user =
						i_strdup(args[i] + 5);
				} else if (str_begins(args[i], "original_user=")) {
					i_free(client->virtual_user_orig);
					client->virtual_user_orig =
						i_strdup(args[i] + 14);
				} else if (str_begins(args[i], "auth_user=")) {
					i_free(client->virtual_auth_user);
					client->virtual_auth_user =
						i_strdup(args[i] + 10);
				}
			}
		}

		client->authenticating = FALSE;
		call_client_callback(client, SASL_SERVER_REPLY_AUTH_FAILED,
				     NULL, args);
		break;
	}
}

static bool get_cert_username(struct client *client, const char **username_r,
			      const char **error_r)
{
	/* this was proxied connection, so we use the name here */
	if (client->client_cert_common_name != NULL) {
		*username_r = client->client_cert_common_name;
		return TRUE;
	}

	/* no SSL */
	if (client->ssl_iostream == NULL) {
		*username_r = NULL;
		return TRUE;
	}

	/* no client certificate */
	if (!ssl_iostream_has_valid_client_cert(client->ssl_iostream)) {
		*username_r = NULL;
		return TRUE;
	}

	/* get peer name */
	const char *username = ssl_iostream_get_peer_name(client->ssl_iostream);

	/* if we wanted peer name, but it was not there, fail */
	if (client->set->auth_ssl_username_from_cert &&
	    (username == NULL || *username == '\0')) {
		if (client->set->auth_ssl_require_client_cert) {
			*error_r = "Missing username in certificate";
			return FALSE;
		}
	}

	*username_r = username;
	return TRUE;
}

void sasl_server_auth_begin(struct client *client,
			    const char *service, const char *mech_name,
			    bool private, const char *initial_resp_base64,
			    sasl_server_callback_t *callback)
{
	struct auth_request_info info;
	const struct auth_mech_desc *mech;
	const char *error;

	i_assert(auth_client_is_connected(auth_client));

	client->auth_attempts++;
	client->authenticating = TRUE;
	if (client->auth_first_started == 0)
		client->auth_first_started = ioloop_time;
	i_free(client->auth_mech_name);
	client->auth_mech_name = str_ucase(i_strdup(mech_name));
	client->auth_anonymous = FALSE;
	client->sasl_callback = callback;

	mech = sasl_server_find_available_mech(client, mech_name);
	if (mech == NULL ||
	    ((mech->flags & MECH_SEC_PRIVATE) != 0 && !private)) {
		sasl_server_auth_failed(client,
			"Unsupported authentication mechanism.",
			AUTH_CLIENT_FAIL_CODE_MECH_INVALID);
		return;
	}

	i_assert(!private || (mech->flags & MECH_SEC_PRIVATE) != 0);

	if (!client->secured && client->set->disable_plaintext_auth &&
	    (mech->flags & MECH_SEC_PLAINTEXT) != 0) {
		sasl_server_auth_failed(client,
			"Plaintext authentication disabled.",
			 AUTH_CLIENT_FAIL_CODE_MECH_SSL_REQUIRED);
		return;
	}

	i_zero(&info);
	info.mech = mech->name;
	info.service = service;
	info.session_id = client_get_session_id(client);

	if (!get_cert_username(client, &info.cert_username, &error)) {
		client_log_err(client, t_strdup_printf("Cannot get username "
						       "from certificate: %s", error));
		sasl_server_auth_failed(client,
			"Unable to validate certificate",
			AUTH_CLIENT_FAIL_CODE_AUTHZFAILED);
		return;
	}

	if (client->ssl_iostream != NULL) {
		info.cert_username = ssl_iostream_get_peer_name(client->ssl_iostream);
		info.ssl_cipher = ssl_iostream_get_cipher(client->ssl_iostream,
							 &info.ssl_cipher_bits);
		info.ssl_pfs = ssl_iostream_get_pfs(client->ssl_iostream);
		info.ssl_protocol =
			ssl_iostream_get_protocol_name(client->ssl_iostream);
	}
	info.flags = client_get_auth_flags(client);
	info.local_ip = client->local_ip;
	info.remote_ip = client->ip;
	info.local_port = client->local_port;
	info.local_name = client->local_name;
	info.remote_port = client->remote_port;
	info.real_local_ip = client->real_local_ip;
	info.real_remote_ip = client->real_remote_ip;
	info.real_local_port = client->real_local_port;
	info.real_remote_port = client->real_remote_port;
	if (client->client_id != NULL)
		info.client_id = str_c(client->client_id);
	if (client->forward_fields != NULL)
		info.forward_fields = str_c(client->forward_fields);
	info.initial_resp_base64 = initial_resp_base64;

	client->auth_request =
		auth_client_request_new(auth_client, &info,
					authenticate_callback, client);
}

static void ATTR_NULL(2, 3)
sasl_server_auth_cancel(struct client *client, const char *reason,
			const char *code, enum sasl_server_reply reply)
{
	i_assert(client->authenticating);

	if (client->set->auth_verbose && reason != NULL) {
		const char *auth_name =
			str_sanitize(client->auth_mech_name, MAX_MECH_NAME);
		client_log(client, t_strdup_printf(
			"Authenticate %s failed: %s", auth_name, reason));
	}

	client->authenticating = FALSE;
	if (client->auth_request != NULL)
		auth_client_request_abort(&client->auth_request, reason);

	if (code != NULL) {
		const char *args[2];

		args[0] = t_strconcat("code=", code, NULL);
		args[1] = NULL;
		call_client_callback(client, reply, reason, args);
		return;
	}

	call_client_callback(client, reply, reason, NULL);
}

void sasl_server_auth_failed(struct client *client, const char *reason,
	const char *code)
{
	sasl_server_auth_cancel(client, reason, code, SASL_SERVER_REPLY_AUTH_FAILED);
}

void sasl_server_auth_abort(struct client *client)
{
	client->auth_try_aborted = TRUE;
	sasl_server_auth_cancel(client, NULL, NULL, SASL_SERVER_REPLY_AUTH_ABORTED);
}
