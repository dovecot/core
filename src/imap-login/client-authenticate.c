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
#include "../auth/auth-mech-desc.h"
#include "client.h"
#include "client-authenticate.h"
#include "auth-common.h"
#include "master.h"

const char *client_authenticate_get_capabilities(int tls)
{
	static enum auth_mech cached_auth_mechs = 0;
	static char *cached_capability = NULL;
        enum auth_mech auth_mechs;
	string_t *str;
	int i;

	auth_mechs = auth_client_get_available_mechs(auth_client);
	if (auth_mechs == cached_auth_mechs)
		return cached_capability;

	cached_auth_mechs = auth_mechs;
	i_free(cached_capability);

	str = t_str_new(128);

	for (i = 0; i < AUTH_MECH_COUNT; i++) {
		if ((auth_mechs & auth_mech_desc[i].mech) &&
		    auth_mech_desc[i].name != NULL &&
		    (tls || !auth_mech_desc[i].plaintext ||
		     !disable_plaintext_auth)) {
			str_append_c(str, ' ');
			str_append(str, "AUTH=");
			str_append(str, auth_mech_desc[i].name);
		}
	}

	cached_capability = i_strdup_empty(str_c(str));
	return cached_capability;
}

static struct auth_mech_desc *auth_mech_find(const char *name)
{
	int i;

	for (i = 0; i < AUTH_MECH_COUNT; i++) {
		if (auth_mech_desc[i].name != NULL &&
		    strcasecmp(auth_mech_desc[i].name, name) == 0)
			return &auth_mech_desc[i];
	}

	return NULL;
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
	o_stream_flush(client->output);

	/* get back to normal client input */
	if (client->common.io != NULL)
		io_remove(client->common.io);
	client->common.io = client->common.fd == -1 ? NULL :
		io_add(client->common.fd, IO_READ, client_input, client);
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
		client_send_line(client, "* BYE Internal login failure.");
	}

	client_destroy(client, reason);
}

static void client_send_auth_data(struct imap_client *client,
				  const unsigned char *data, size_t size)
{
	buffer_t *buf;

	t_push();

	buf = buffer_create_dynamic(data_stack_pool, size*2, (size_t)-1);
	buffer_append(buf, "+ ", 2);
	base64_encode(data, size, buf);
	buffer_append(buf, "\r\n", 2);

	o_stream_send(client->output, buffer_get_data(buf, NULL),
		      buffer_get_used_size(buf));
	o_stream_flush(client->output);

	t_pop();
}

static void login_callback(struct auth_request *request,
			   struct auth_client_request_reply *reply,
			   const unsigned char *data, void *context)
{
	struct imap_client *client = context;
	const char *error;
	const void *ptr;
	size_t size;

	switch (auth_callback(request, reply, data, &client->common,
			      master_callback, &error)) {
	case -1:
		/* login failed */
		client_auth_abort(client, error);
		break;

	case 0:
		/* continue */
		ptr = buffer_get_data(client->plain_login, &size);
		auth_client_request_continue(request, ptr, size);

		buffer_set_used_size(client->plain_login, 0);
		break;
	default:
		/* success, we should be able to log in. if we fail, just
		   disconnect the client. */
                client->authenticating = FALSE;
		client_send_tagline(client, "OK Logged in.");
	}
}

int cmd_login(struct imap_client *client, struct imap_arg *args)
{
	const char *user, *pass, *error;

	/* two arguments: username and password */
	if (args[0].type != IMAP_ARG_ATOM && args[0].type != IMAP_ARG_STRING)
		return FALSE;
	if (args[1].type != IMAP_ARG_ATOM && args[1].type != IMAP_ARG_STRING)
		return FALSE;
	if (args[2].type != IMAP_ARG_EOL)
		return FALSE;

	user = IMAP_ARG_STR(&args[0]);
	pass = IMAP_ARG_STR(&args[1]);

	if (!client->tls && disable_plaintext_auth) {
		client_send_line(client,
			"* BAD [ALERT] Plaintext authentication is disabled, "
			"but your client sent password in plaintext anyway."
			"If anyone was listening, the password was exposed.");
		client_send_tagline(client,
				    "NO Plaintext authentication disabled.");
		return TRUE;
	}

	/* authorization ID \0 authentication ID \0 pass */
	buffer_set_used_size(client->plain_login, 0);
	buffer_append_c(client->plain_login, '\0');
	buffer_append(client->plain_login, user, strlen(user));
	buffer_append_c(client->plain_login, '\0');
	buffer_append(client->plain_login, pass, strlen(pass));

	client->common.auth_request =
		auth_client_request_new(auth_client, AUTH_MECH_PLAIN,
					AUTH_PROTOCOL_IMAP, login_callback,
					client, &error);
	if (client->common.auth_request == NULL) {
		client_send_tagline(client, t_strconcat(
			"NO Login failed: ", error, NULL));
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
	buf = buffer_create_static_hard(data_stack_pool, linelen);

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
	struct auth_mech_desc *mech;
	const char *mech_name, *error;

	/* we want only one argument: authentication mechanism name */
	if (args[0].type != IMAP_ARG_ATOM && args[0].type != IMAP_ARG_STRING)
		return FALSE;
	if (args[1].type != IMAP_ARG_EOL)
		return FALSE;

	mech_name = IMAP_ARG_STR(&args[0]);
	if (*mech_name == '\0')
		return FALSE;

	mech = auth_mech_find(mech_name);
	if (mech == NULL) {
		client_send_tagline(client,
				    "NO Unsupported authentication mechanism.");
		return TRUE;
	}

	if (!client->tls && mech->plaintext && disable_plaintext_auth) {
		client_send_tagline(client,
				    "NO Plaintext authentication disabled.");
		return TRUE;
	}

	client->common.auth_request =
		auth_client_request_new(auth_client, mech->mech,
					AUTH_PROTOCOL_IMAP,
					authenticate_callback,
					client, &error);
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
	}

	return TRUE;
}
