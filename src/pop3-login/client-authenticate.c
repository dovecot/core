/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "base64.h"
#include "buffer.h"
#include "hex-binary.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "safe-memset.h"
#include "str.h"
#include "auth-client.h"
#include "../pop3/capability.h"
#include "ssl-proxy.h"
#include "master.h"
#include "auth-common.h"
#include "client.h"
#include "client-authenticate.h"
#include "ssl-proxy.h"

int cmd_capa(struct pop3_client *client, const char *args __attr_unused__)
{
	const struct auth_mech_desc *mech;
	unsigned int i, count;
	string_t *str;

	str = t_str_new(128);
	str_append(str, "SASL");

	mech = auth_client_get_available_mechs(auth_client, &count);
	for (i = 0; i < count; i++) {
		/* a) transport is secured
		   b) auth mechanism isn't plaintext
		   c) we allow insecure authentication
		        - but don't advertise AUTH=PLAIN, as RFC 2595 requires
		*/
		if (mech[i].advertise &&
		    (client->secured || !mech[i].plaintext)) {
			str_append_c(str, ' ');
			str_append(str, mech[i].name);
		}
	}

	client_send_line(client, t_strconcat("+OK\r\n" POP3_CAPABILITY_REPLY,
					     (ssl_initialized && !client->tls) ?
					     "STLS\r\n" : "",
					     str_c(str),
					     "\r\n.", NULL));
	return TRUE;
}

static void client_auth_abort(struct pop3_client *client, const char *msg)
{
	if (client->common.auth_request != NULL) {
		auth_client_request_abort(client->common.auth_request);
		client->common.auth_request = NULL;
	}

	client_send_line(client, msg != NULL ? t_strconcat("-ERR ", msg, NULL) :
			 "-ERR Authentication failed.");

	/* get back to normal client input */
	if (client->common.io != NULL)
		io_remove(client->common.io);
	client->common.io = client->common.fd == -1 ? NULL :
		io_add(client->common.fd, IO_READ, client_input, client);

	client_unref(client);
}

static void master_callback(struct client *_client, int success)
{
	struct pop3_client *client = (struct pop3_client *) _client;
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

static void client_send_auth_data(struct pop3_client *client,
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
	if ((ret = o_stream_send(client->output, buf_data, buf_size) < 0))
		client_destroy(client, "Disconnected");
	else if ((size_t)ret != buf_size)
		client_destroy(client, "Transmit buffer full");

	t_pop();
}

static enum auth_client_request_new_flags
client_get_auth_flags(struct pop3_client *client)
{
        enum auth_client_request_new_flags auth_flags = 0;

	if (client->common.proxy != NULL &&
	    ssl_proxy_has_valid_client_cert(client->common.proxy))
		auth_flags |= AUTH_CLIENT_FLAG_SSL_VALID_CLIENT_CERT;
	return auth_flags;
}

static void login_callback(struct auth_request *request,
			   struct auth_client_request_reply *reply,
			   const unsigned char *data, void *context)
{
	struct pop3_client *client = context;
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
		client_send_line(client, "+OK Logged in.");
		client_unref(client);
	}
}

int cmd_user(struct pop3_client *client, const char *args)
{
	if (!client->secured && disable_plaintext_auth) {
		client_send_line(client,
				 "-ERR Plaintext authentication disabled.");
		return TRUE;
	}

	i_free(client->last_user);
	client->last_user = i_strdup(args);

	client_send_line(client, "+OK");
	return TRUE;
}

int cmd_pass(struct pop3_client *client, const char *args)
{
	const char *error;
	struct auth_request_info info;
	string_t *plain_login;

	if (client->last_user == NULL) {
		client_send_line(client, "-ERR No username given.");
		return TRUE;
	}

	/* authorization ID \0 authentication ID \0 pass */
	plain_login = t_str_new(128);
	str_append_c(plain_login, '\0');
	str_append(plain_login, client->last_user);
	str_append_c(plain_login, '\0');
	str_append(plain_login, args);

	memset(&info, 0, sizeof(info));
	info.mech = "PLAIN";
	info.protocol = "POP3";
	info.flags = client_get_auth_flags(client);
	info.local_ip = client->common.local_ip;
	info.remote_ip = client->common.ip;
	info.initial_resp_data = str_data(plain_login);
	info.initial_resp_size = str_len(plain_login);

	client_ref(client);
	client->common.auth_request =
		auth_client_request_new(auth_client, NULL, &info,
					login_callback, client, &error);

	if (client->common.auth_request != NULL) {
		/* don't read any input from client until login is finished */
		if (client->common.io != NULL) {
			io_remove(client->common.io);
			client->common.io = NULL;
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
				  struct auth_client_request_reply *reply,
				  const unsigned char *data, void *context)
{
	struct pop3_client *client = context;
	const char *error;

	switch (auth_callback(request, reply, data, &client->common,
			      master_callback, &error)) {
	case -1:
		/* login failed */
		client_auth_abort(client, error);
		break;

	case 0:
		client_send_auth_data(client, data, reply->data_size);
		break;

	default:
		/* success, we should be able to log in. if we fail, just
		   disconnect the client. */
		client_send_line(client, "+OK Logged in.");
		client_unref(client);
	}
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

int cmd_auth(struct pop3_client *client, const char *args)
{
	struct auth_request_info info;
	const struct auth_mech_desc *mech;
	const char *mech_name, *error, *p;
	string_t *buf;
	size_t argslen;

	if (*args == '\0' &&
	    auth_client_find_mech(auth_client, "NTLM") != NULL) {
		/* This is needed to allow MS Outlook to use NTLM
		   authentication. Sometimes this kludge is called
		   "old-style SASL discovery". */
		client_send_line(client, "+OK");
 		client_send_line(client, "NTLM");
 		client_send_line(client, ".");
 		return TRUE;
 	}

	/* <mechanism name> <initial response> */
	p = strchr(args, ' ');
	if (p == NULL) {
		mech_name = args;
		args = "";
	} else {
		mech_name = t_strdup_until(args, p);
		args = p+1;
	}

	mech = auth_client_find_mech(auth_client, mech_name);
	if (mech == NULL) {
		client_send_line(client,
				 "-ERR Unsupported authentication mechanism.");
		return TRUE;
	}

	if (!client->secured && mech->plaintext && disable_plaintext_auth) {
		client_send_line(client,
				 "-ERR Plaintext authentication disabled.");
		return TRUE;
	}

	argslen = strlen(args);
	buf = buffer_create_static_hard(pool_datastack_create(), argslen);

	if (base64_decode((const unsigned char *)args, argslen,
			  NULL, buf) <= 0) {
		/* failed */
		client_send_line(client, "-ERR Invalid base64 data.");
		return TRUE;
	}

	memset(&info, 0, sizeof(info));
	info.mech = mech->name;
	info.protocol = "POP3";
	info.flags = client_get_auth_flags(client);
	info.local_ip = client->common.local_ip;
	info.remote_ip = client->common.ip;
	info.initial_resp_data = str_data(buf);
	info.initial_resp_size = str_len(buf);

	client_ref(client);
	client->common.auth_request =
		auth_client_request_new(auth_client, NULL, &info,
					authenticate_callback, client, &error);
	if (client->common.auth_request != NULL) {
		/* following input data will go to authentication */
		if (client->common.io != NULL)
			io_remove(client->common.io);
		client->common.io = io_add(client->common.fd, IO_READ,
					   client_auth_input, client);
	} else {
		client_send_line(client, t_strconcat(
			"-ERR Authentication failed: ", error, NULL));
		client_unref(client);
	}

	return TRUE;
}

int cmd_apop(struct pop3_client *client, const char *args)
{
	struct auth_request_info info;
	const char *error, *p;
	buffer_t *apop_data;

	if (client->apop_challenge == NULL) {
	        client_send_line(client, "-ERR APOP not enabled.");
		return TRUE;
	}

	/* <username> <md5 sum in hex> */
	p = strchr(args, ' ');
	if (p == NULL || strlen(p+1) != 32) {
	        client_send_line(client, "-ERR Invalid parameters.");
		return TRUE;
	}

	/* APOP challenge \0 username \0 APOP response */
	apop_data = buffer_create_dynamic(pool_datastack_create(),
					  128, (size_t)-1);
	buffer_append(apop_data, client->apop_challenge,
		      strlen(client->apop_challenge)+1);
	buffer_append(apop_data, args, (size_t)(p-args));
	buffer_append_c(apop_data, '\0');

	if (hex_to_binary(p+1, apop_data) <= 0) {
		client_send_line(client,
				 "-ERR Invalid characters in MD5 response.");
		return TRUE;
	}

	memset(&info, 0, sizeof(info));
	info.mech = "APOP";
	info.protocol = "POP3";
	info.flags = client_get_auth_flags(client);
	info.local_ip = client->common.local_ip;
	info.remote_ip = client->common.ip;
	info.initial_resp_data =
		buffer_get_data(apop_data, &info.initial_resp_size);

	client_ref(client);
	o_stream_uncork(client->output);

	client->common.auth_request =
		auth_client_request_new(auth_client, &client->auth_id, &info,
					login_callback, client, &error);

	if (client->common.auth_request != NULL) {
		/* don't read any input from client until login is finished */
		if (client->common.io != NULL) {
			io_remove(client->common.io);
			client->common.io = NULL;
		}
	} else if (error == NULL) {
		/* the auth connection was lost. we have no choice
		   but to fail the APOP logins completely since the
		   challenge is auth connection-specific. disconnect. */
		client_destroy(client, "APOP auth connection lost");
		client_unref(client);
	} else {
		client_send_line(client,
			t_strconcat("-ERR Login failed: ", error, NULL));
		client_unref(client);
	}
	return TRUE;
}
