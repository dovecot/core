/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "base64.h"
#include "buffer.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "safe-memset.h"
#include "str.h"
#include "auth-connection.h"
#include "../auth/auth-mech-desc.h"
#include "../pop3/capability.h"
#include "client.h"
#include "client-authenticate.h"
#include "master.h"

static enum auth_mech auth_mechs = 0;
static char *auth_mechs_capability = NULL;

int cmd_capa(struct pop3_client *client, const char *args __attr_unused__)
{
	string_t *str;
	int i;

	if (auth_mechs != available_auth_mechs) {
		auth_mechs = available_auth_mechs;
		i_free(auth_mechs_capability);

		str = t_str_new(128);

		str_append(str, "SASL");
		for (i = 0; i < AUTH_MECH_COUNT; i++) {
			if ((auth_mechs & auth_mech_desc[i].mech) &&
			    auth_mech_desc[i].name != NULL) {
				str_append_c(str, ' ');
				str_append(str, auth_mech_desc[i].name);
			}
		}

		auth_mechs_capability = i_strdup(str_c(str));
	}

	client_send_line(client, t_strconcat("+OK\r\n" POP3_CAPABILITY_REPLY,
					     auth_mechs_capability,
					     "\r\n.", NULL));
	return TRUE;
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

static void client_auth_abort(struct pop3_client *client, const char *msg)
{
	if (client->auth_request != NULL) {
		auth_abort_request(client->auth_request);
		client->auth_request = NULL;
	}

	client_send_line(client, msg != NULL ? msg :
			 "-ERR Authentication failed.");
	o_stream_flush(client->output);

	/* get back to normal client input */
	if (client->io != NULL)
		io_remove(client->io);
	client->io = client->common.fd == -1 ? NULL :
		io_add(client->common.fd, IO_READ, client_input, client);

	client_unref(client);
}

static void master_callback(struct client *_client, int success)
{
	struct pop3_client *client = (struct pop3_client *) _client;
	const char *reason = NULL;

	if (success)
		reason = t_strconcat("Login: ", client->virtual_user, NULL);
	else {
		reason = t_strconcat("Internal login failure: ",
				     client->virtual_user, NULL);
		client_send_line(client, "* BYE Internal login failure.");
	}

	client_destroy(client, reason);
	client_unref(client);
}

static void client_send_auth_data(struct pop3_client *client,
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

static const char *auth_login_get_str(struct auth_login_reply *reply,
				      const unsigned char *data, size_t idx)
{
	size_t stop;

	if (idx >= reply->data_size || idx >= reply->reply_idx)
		return NULL;

	stop = reply->reply_idx < reply->data_size ?
		reply->reply_idx-1 : reply->data_size;

	return t_strndup(data, stop);
}

static int auth_callback(struct auth_request *request,
			 struct auth_login_reply *reply,
			 const unsigned char *data, void *context)
{
	struct pop3_client *client = context;
	const char *user, *realm;

	if (reply == NULL) {
		/* failed */
		client->auth_request = NULL;
		client_auth_abort(client, "-ERR Authentication process died.");
		return FALSE;
	}

	switch (reply->result) {
	case AUTH_LOGIN_RESULT_CONTINUE:
		client->auth_request = request;
		return TRUE;

	case AUTH_LOGIN_RESULT_SUCCESS:
		client->auth_request = NULL;

		user = auth_login_get_str(reply, data, reply->username_idx);
		realm = auth_login_get_str(reply, data, reply->realm_idx);

		i_free(client->virtual_user);
		client->virtual_user = realm == NULL ?
			i_strdup(user) : i_strconcat(user, "@", realm, NULL);

		/* we should be able to log in. if we fail, just
		   disconnect the client. */
		client_send_line(client, "+OK Logged in.");

		master_request_imap(&client->common, master_callback,
				    request->conn->pid, request->id);

		/* disable IO until we're back from master */
		if (client->io != NULL) {
			io_remove(client->io);
			client->io = NULL;
		}
		return FALSE;

	case AUTH_LOGIN_RESULT_FAILURE:
		/* see if we have error message */
		client->auth_request = NULL;

		if (reply->data_size > 0 && data[reply->data_size-1] == '\0') {
			client_auth_abort(client, t_strconcat(
				"-ERR Authentication failed: ",
				(const char *) data, NULL));
		} else {
			/* default error message */
			client_auth_abort(client, NULL);
		}
		return FALSE;
	}

	i_unreached();
}

static void login_callback(struct auth_request *request,
			   struct auth_login_reply *reply,
			   const unsigned char *data, struct client *_client)
{
	struct pop3_client *client = (struct pop3_client *) _client;
	const void *ptr;
	size_t size;

	if (auth_callback(request, reply, data, client)) {
		ptr = buffer_get_data(client->plain_login, &size);
		auth_continue_request(request, ptr, size);

		buffer_set_used_size(client->plain_login, 0);
	}
}

int cmd_user(struct pop3_client *client, const char *args)
{
	if (!client->tls && disable_plaintext_auth) {
		client_send_line(client,
				 "-ERR Plaintext authentication disabled.");
		return TRUE;
	}

	/* authorization ID \0 authentication ID \0 pass */
	buffer_set_used_size(client->plain_login, 0);
	buffer_append_c(client->plain_login, '\0');
	buffer_append(client->plain_login, args, strlen(args));

	client_send_line(client, "+OK");
	return TRUE;
}

int cmd_pass(struct pop3_client *client, const char *args)
{
	const char *error;

	if (buffer_get_used_size(client->plain_login) == 0) {
		client_send_line(client, "-ERR No username given.");
		return TRUE;
	}

	buffer_append_c(client->plain_login, '\0');
	buffer_append(client->plain_login, args, strlen(args));

	client_ref(client);
	if (auth_init_request(AUTH_MECH_PLAIN, login_callback,
			      &client->common, &error)) {
		/* don't read any input from client until login is finished */
		if (client->io != NULL) {
			io_remove(client->io);
			client->io = NULL;
		}
		return TRUE;
	} else {
		client_send_line(client,
			t_strconcat("-ERR Login failed: ", error, NULL));
		client_unref(client);
		return TRUE;
	}
}

static void authenticate_callback(struct auth_request *request,
				  struct auth_login_reply *reply,
				  const unsigned char *data,
				  struct client *_client)
{
	struct pop3_client *client = (struct pop3_client *) _client;

	if (auth_callback(request, reply, data, client))
		client_send_auth_data(client, data, reply->data_size);
}

static void client_auth_input(void *context)
{
	struct pop3_client *client = context;
	buffer_t *buf;
	char *line;
	size_t linelen, bufsize;

	if (!client_read(client))
		return;

	/* @UNSAFE */
	line = i_stream_next_line(client->input);
	if (line == NULL)
		return;

	if (strcmp(line, "*") == 0) {
		client_auth_abort(client, "-ERR Authentication aborted");
		return;
	}

	linelen = strlen(line);
	buf = buffer_create_static_hard(data_stack_pool, linelen);

	if (base64_decode((const unsigned char *) line, linelen,
			  NULL, buf) <= 0) {
		/* failed */
		client_auth_abort(client, "-ERR Invalid base64 data");
	} else if (client->auth_request == NULL) {
		client_auth_abort(client, "-ERR Don't send unrequested data");
	} else {
		auth_continue_request(client->auth_request,
				      buffer_get_data(buf, NULL),
				      buffer_get_used_size(buf));
	}

	/* clear sensitive data */
	safe_memset(line, 0, linelen);

	bufsize = buffer_get_used_size(buf);
	safe_memset(buffer_free_without_data(buf), 0, bufsize);
}

int cmd_auth(struct pop3_client *client, const char *args)
{
	struct auth_mech_desc *mech;
	const char *error;

	/* we have only one argument: authentication mechanism name */
	mech = auth_mech_find(args);
	if (mech == NULL) {
		client_send_line(client,
				 "-ERR Unsupported authentication mechanism.");
		return TRUE;
	}

	if (!client->tls && mech->plaintext && disable_plaintext_auth) {
		client_send_line(client,
				 "-ERR Plaintext authentication disabled.");
		return TRUE;
	}

	client_ref(client);
	if (auth_init_request(mech->mech, authenticate_callback,
			      &client->common, &error)) {
		/* following input data will go to authentication */
		if (client->io != NULL)
			io_remove(client->io);
		client->io = io_add(client->common.fd, IO_READ,
				    client_auth_input, client);
	} else {
		client_send_line(client, t_strconcat(
			"-ERR Authentication failed: ", error, NULL));
		client_unref(client);
	}

	return TRUE;
}
