/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "base64.h"
#include "buffer.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "safe-memset.h"
#include "str.h"
#include "imap-parser.h"
#include "auth-client.h"
#include "ssl-proxy.h"
#include "client.h"
#include "client-authenticate.h"
#include "auth-common.h"
#include "master.h"

const char *client_authenticate_get_capabilities(int secured)
{
	const struct auth_mech_desc *mech;
	unsigned int i, count;
	string_t *str;

	str = t_str_new(128);
	mech = auth_client_get_available_mechs(auth_client, &count);
	for (i = 0; i < count; i++) {
		/* a) transport is secured
		   b) auth mechanism isn't plaintext
		   c) we allow insecure authentication
		        - but don't advertise AUTH=PLAIN, as RFC 2595 requires
		*/
		if (mech[i].advertise &&
		    (secured || !mech[i].plaintext)) {
			str_append_c(str, ' ');
			str_append(str, "AUTH=");
			str_append(str, mech[i].name);
		}
	}

	return str_c(str);
}

static void client_auth_abort(struct imap_client *client, const char *msg)
{
	client->authenticating = FALSE;

	if (client->common.auth_request != NULL) {
		auth_client_request_abort(client->common.auth_request);
		client->common.auth_request = NULL;
	}

	client_send_tagline(client, msg != NULL ?
			    t_strconcat("NO ", msg, NULL) :
			    "NO Authentication failed.");

	/* get back to normal client input */
	if (client->common.io != NULL)
		io_remove(client->common.io);
	client->common.io = client->common.fd == -1 ? NULL :
		io_add(client->common.fd, IO_READ, client_input, client);

	client_unref(client);
}

static void master_callback(struct client *_client, int success)
{
	struct imap_client *client = (struct imap_client *) _client;
	const char *reason = NULL;

	if (success) {
		reason = t_strconcat("Login: ", client->common.virtual_user,
				     NULL);
	} else {
		reason = t_strconcat("Internal login failure: ",
				     client->common.virtual_user, NULL);
		client_send_line(client, "* BYE Internal login failure. "
				 "Error report written to server log.");
	}

	client_destroy(client, reason);
}

static void client_send_auth_data(struct imap_client *client,
				  const unsigned char *data, size_t size)
{
	buffer_t *buf;
	const void *buf_data;
	size_t buf_size;
	ssize_t ret;

	t_push();

	buf = buffer_create_dynamic(pool_datastack_create(),
				    size*2, (size_t)-1);
	buffer_append(buf, "+ ", 2);
	base64_encode(data, size, buf);
	buffer_append(buf, "\r\n", 2);

	buf_data = buffer_get_data(buf, &buf_size);
	if ((ret = o_stream_send(client->output, buf_data, buf_size)) < 0)
		client_destroy(client, "Disconnected");
	else if ((size_t)ret != buf_size)
		client_destroy(client, "Transmit buffer full");

	t_pop();
}

static void login_callback(struct auth_request *request,
			   struct auth_client_request_reply *reply,
			   const unsigned char *data, void *context)
{
	struct imap_client *client = context;
	const char *error;

	switch (auth_callback(request, reply, data, &client->common,
			      master_callback, &error)) {
	case -1:
	case 0:
		/* login failed */
		client_auth_abort(client, error);
		break;

	default:
		/* success, we should be able to log in. if we fail, just
		   disconnect the client. */
                client->authenticating = FALSE;
		client_send_tagline(client, "OK Logged in.");
		client_unref(client);
	}
}

static enum auth_client_request_new_flags
client_get_auth_flags(struct imap_client *client)
{
        enum auth_client_request_new_flags auth_flags = 0;

	if (client->common.proxy != NULL &&
	    ssl_proxy_has_valid_client_cert(client->common.proxy))
		auth_flags |= AUTH_CLIENT_FLAG_SSL_VALID_CLIENT_CERT;
	if (client->tls)
		auth_flags |= AUTH_CLIENT_FLAG_SSL_ENABLED;
	return auth_flags;
}

int cmd_login(struct imap_client *client, struct imap_arg *args)
{
	const char *user, *pass, *error;
	struct auth_request_info info;
	string_t *plain_login;

	/* two arguments: username and password */
	if (args[0].type != IMAP_ARG_ATOM && args[0].type != IMAP_ARG_STRING)
		return FALSE;
	if (args[1].type != IMAP_ARG_ATOM && args[1].type != IMAP_ARG_STRING)
		return FALSE;
	if (args[2].type != IMAP_ARG_EOL)
		return FALSE;

	user = IMAP_ARG_STR(&args[0]);
	pass = IMAP_ARG_STR(&args[1]);

	if (!client->secured && disable_plaintext_auth) {
		client_send_line(client,
			"* BAD [ALERT] Plaintext authentication is disabled, "
			"but your client sent password in plaintext anyway. "
			"If anyone was listening, the password was exposed.");
		client_send_tagline(client,
				    "NO Plaintext authentication disabled.");
		return TRUE;
	}

	/* authorization ID \0 authentication ID \0 pass */
	plain_login = t_str_new(64);
	str_append_c(plain_login, '\0');
	str_append(plain_login, user);
	str_append_c(plain_login, '\0');
	str_append(plain_login, pass);

	memset(&info, 0, sizeof(info));
	info.mech = "PLAIN";
	info.protocol = "IMAP";
	info.flags = client_get_auth_flags(client);
	info.local_ip = client->common.local_ip;
	info.remote_ip = client->common.ip;
	info.initial_resp_data = str_data(plain_login);
	info.initial_resp_size = str_len(plain_login);

	client_ref(client);

	client->common.auth_request =
		auth_client_request_new(auth_client, NULL, &info,
					login_callback, client, &error);
	if (client->common.auth_request == NULL) {
		client_send_tagline(client, t_strconcat(
			"NO Login failed: ", error, NULL));
		client_unref(client);
		return TRUE;
	}

	/* don't read any input from client until login is finished */
	if (client->common.io != NULL) {
		io_remove(client->common.io);
		client->common.io = NULL;
	}

	client->authenticating = TRUE;
	return TRUE;
}

static void authenticate_callback(struct auth_request *request,
				  struct auth_client_request_reply *reply,
				  const unsigned char *data, void *context)
{
	struct imap_client *client = context;
	const char *error;

	switch (auth_callback(request, reply, data, &client->common,
			      master_callback, &error)) {
	case -1:
		/* login failed */
		client_auth_abort(client, error);
		break;

	case 0:
		/* continue */
		client_send_auth_data(client, data, reply->data_size);
		break;
	default:
		/* success, we should be able to log in. if we fail, just
		   disconnect the client. */
                client->authenticating = FALSE;
		client_send_tagline(client, "OK Logged in.");
		client_unref(client);
	}
}

static void client_auth_input(void *context)
{
	struct imap_client *client = context;
	buffer_t *buf;
	char *line;
	size_t linelen, bufsize;

	if (!client_read(client))
		return;

	if (client->skip_line) {
		if (i_stream_next_line(client->input) == NULL)
			return;

		client->skip_line = FALSE;
	}

	/* @UNSAFE */
	line = i_stream_next_line(client->input);
	if (line == NULL)
		return;

	if (strcmp(line, "*") == 0) {
		client_auth_abort(client, "Authentication aborted");
		return;
	}

	linelen = strlen(line);
	buf = buffer_create_static_hard(pool_datastack_create(), linelen);

	if (base64_decode((const unsigned char *) line, linelen,
			  NULL, buf) <= 0) {
		/* failed */
		client_auth_abort(client, "Invalid base64 data");
	} else if (client->common.auth_request == NULL) {
		client_auth_abort(client, "Don't send unrequested data");
	} else {
		auth_client_request_continue(client->common.auth_request,
					     buffer_get_data(buf, NULL),
					     buffer_get_used_size(buf));
	}

	/* clear sensitive data */
	safe_memset(line, 0, linelen);

	bufsize = buffer_get_used_size(buf);
	safe_memset(buffer_free_without_data(buf), 0, bufsize);
}

int cmd_authenticate(struct imap_client *client, struct imap_arg *args)
{
	const struct auth_mech_desc *mech;
	const char *mech_name, *error;
	struct auth_request_info info;

	/* we want only one argument: authentication mechanism name */
	if (args[0].type != IMAP_ARG_ATOM && args[0].type != IMAP_ARG_STRING)
		return FALSE;
	if (args[1].type != IMAP_ARG_EOL)
		return FALSE;

	mech_name = IMAP_ARG_STR(&args[0]);
	if (*mech_name == '\0')
		return FALSE;

	mech = auth_client_find_mech(auth_client, mech_name);
	if (mech == NULL) {
		client_send_tagline(client,
				    "NO Unsupported authentication mechanism.");
		return TRUE;
	}

	if (!client->secured && mech->plaintext && disable_plaintext_auth) {
		client_send_tagline(client,
				    "NO Plaintext authentication disabled.");
		return TRUE;
	}

	memset(&info, 0, sizeof(info));
	info.mech = mech->name;
	info.protocol = "IMAP";
	info.flags = client_get_auth_flags(client);
	info.local_ip = client->common.local_ip;
	info.remote_ip = client->common.ip;

	client_ref(client);
	o_stream_uncork(client->output);

	client->common.auth_request =
		auth_client_request_new(auth_client, NULL, &info,
					authenticate_callback, client, &error);
	if (client->common.auth_request != NULL) {
		/* following input data will go to authentication */
		if (client->common.io != NULL)
			io_remove(client->common.io);
		client->common.io = io_add(client->common.fd, IO_READ,
					   client_auth_input, client);
                client->authenticating = TRUE;
	} else {
		client_send_tagline(client, t_strconcat(
			"NO Authentication failed: ", error, NULL));
		client_unref(client);
	}

	return TRUE;
}
