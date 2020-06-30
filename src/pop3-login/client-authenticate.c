/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "base64.h"
#include "buffer.h"
#include "hex-binary.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "safe-memset.h"
#include "str.h"
#include "str-sanitize.h"
#include "auth-client.h"
#include "../pop3/pop3-capability.h"
#include "client.h"
#include "client-authenticate.h"
#include "pop3-proxy.h"


static const char *capability_string = POP3_CAPABILITY_REPLY;

bool cmd_capa(struct pop3_client *client, const char *args ATTR_UNUSED)
{
	const struct auth_mech_desc *mech;
	unsigned int i, count;
	string_t *str;

	str = t_str_new(128);
	str_append(str, "+OK\r\n");
	str_append(str, capability_string);

	if (client_is_tls_enabled(&client->common) && !client->common.tls)
		str_append(str, "STLS\r\n");
	if (!client->common.set->disable_plaintext_auth ||
	    client->common.secured)
		str_append(str, "USER\r\n");

	str_append(str, "SASL");
	mech = sasl_server_get_advertised_mechs(&client->common, &count);
	for (i = 0; i < count; i++) {
		str_append_c(str, ' ');
		str_append(str, mech[i].name);
	}
	str_append(str, "\r\n.\r\n");

	client_send_raw(&client->common, str_c(str));
	return TRUE;
}

void pop3_client_auth_result(struct client *client,
			     enum client_auth_result result,
			     const struct client_auth_reply *reply ATTR_UNUSED,
			     const char *text)
{
	switch (result) {
	case CLIENT_AUTH_RESULT_SUCCESS:
		/* nothing to be done for POP3 */
		break;
	case CLIENT_AUTH_RESULT_TEMPFAIL:
		client_send_reply(client, POP3_CMD_REPLY_TEMPFAIL, text);
		break;
	case CLIENT_AUTH_RESULT_AUTHFAILED:
	case CLIENT_AUTH_RESULT_AUTHFAILED_REASON:
	case CLIENT_AUTH_RESULT_AUTHZFAILED:
	case CLIENT_AUTH_RESULT_PASS_EXPIRED:
	case CLIENT_AUTH_RESULT_SSL_REQUIRED:
	case CLIENT_AUTH_RESULT_LOGIN_DISABLED:
	case CLIENT_AUTH_RESULT_MECH_INVALID:
	case CLIENT_AUTH_RESULT_MECH_SSL_REQUIRED:
	case CLIENT_AUTH_RESULT_INVALID_BASE64:
		client_send_reply(client, POP3_CMD_REPLY_AUTH_ERROR, text);
		break;
	default:
		client_send_reply(client, POP3_CMD_REPLY_ERROR, text);
		break;
	}
}

int cmd_auth(struct pop3_client *pop3_client, bool *parsed_r)
{
	/* NOTE: This command's input is handled specially because the
	   SASL-IR can be large. */
	struct client *client = &pop3_client->common;
	const unsigned char *data;
	size_t i, size;
	int ret;

	*parsed_r = FALSE;

	/* <auth mechanism name> [<initial SASL response>] */
	if (!pop3_client->auth_mech_name_parsed) {
		data = i_stream_get_data(client->input, &size);
		for (i = 0; i < size; i++) {
			if (data[i] == ' ' ||
			    data[i] == '\r' || data[i] == '\n')
				break;
		}
		if (i == size)
			return 0;
		if (i == 0) {
			/* Old-style SASL discovery, used by MS Outlook */
			unsigned int i, count;
			const struct auth_mech_desc *mech;

			client_send_raw(client, "+OK\r\n");
			mech = sasl_server_get_advertised_mechs(client, &count);
			for (i = 0; i < count; i++) {
				client_send_raw(client, mech[i].name);
				client_send_raw(client, "\r\n");
			}
			client_send_raw(client, ".\r\n");
			*parsed_r = TRUE;
			return 1;
		}
		i_free(client->auth_mech_name);
		client->auth_mech_name = i_strndup(data, i);
		pop3_client->auth_mech_name_parsed = TRUE;
		if (data[i] == ' ')
			i++;
		i_stream_skip(client->input, i);
	}

	/* get SASL-IR, if any */
	if ((ret = client_auth_read_line(client)) <= 0)
		return ret;

	const char *ir = NULL;
	if (client->auth_response->used > 0)
		ir = t_strdup(str_c(client->auth_response));

	*parsed_r = TRUE;
	pop3_client->auth_mech_name_parsed = FALSE;
	return client_auth_begin(client, t_strdup(client->auth_mech_name), ir);
}

bool cmd_user(struct pop3_client *pop3_client, const char *args)
{
	if (!client_check_plaintext_auth(&pop3_client->common, FALSE)) {
		if (pop3_client->common.virtual_user == NULL)
			pop3_client->common.virtual_user = i_strdup(args);
		return TRUE;
	}

	i_free(pop3_client->last_user);
	pop3_client->last_user = i_strdup(args);

	client_send_raw(&pop3_client->common, "+OK\r\n");
	return TRUE;
}

bool cmd_pass(struct pop3_client *pop3_client, const char *args)
{
	struct client *client = &pop3_client->common;
	string_t *plain_login, *base64;

	if (pop3_client->last_user == NULL) {
		/* client may ignore the USER reply and only display the error
		   message from PASS */
		if (!client_check_plaintext_auth(client, TRUE))
			return TRUE;

		client_send_reply(client, POP3_CMD_REPLY_ERROR,
				  "No username given.");
		return TRUE;
	}

	/* authorization ID \0 authentication ID \0 pass */
	plain_login = t_str_new(128);
	str_append_c(plain_login, '\0');
	str_append(plain_login, pop3_client->last_user);
	str_append_c(plain_login, '\0');
	str_append(plain_login, args);

	i_free_and_null(pop3_client->last_user);

	base64 = t_buffer_create(MAX_BASE64_ENCODED_SIZE(plain_login->used));
	base64_encode(plain_login->data, plain_login->used, base64);

	(void)client_auth_begin(client, "PLAIN", str_c(base64));
	return TRUE;
}

bool cmd_apop(struct pop3_client *pop3_client, const char *args)
{
	struct client *client = &pop3_client->common;
	buffer_t *apop_data, *base64;
	const char *p;
	unsigned int server_pid, connect_uid;

	if (pop3_client->apop_challenge == NULL) {
		if (client->set->auth_verbose)
			e_info(client->event, "APOP failed: APOP not enabled");
		client_send_reply(client, POP3_CMD_REPLY_ERROR,
				  "APOP not enabled.");
		return TRUE;
	}

	/* <username> <md5 sum in hex> */
	p = strchr(args, ' ');
	if (p == NULL || strlen(p+1) != 32) {
		if (client->set->auth_verbose)
			e_info(client->event, "APOP failed: Invalid parameters");
		client_send_reply(client, POP3_CMD_REPLY_ERROR,
				  "Invalid parameters.");
		return TRUE;
	}

	/* APOP challenge \0 username \0 APOP response */
	apop_data = t_buffer_create(128);
	buffer_append(apop_data, pop3_client->apop_challenge,
		      strlen(pop3_client->apop_challenge)+1);
	buffer_append(apop_data, args, (size_t)(p-args));
	buffer_append_c(apop_data, '\0');

	if (hex_to_binary(p+1, apop_data) < 0) {
		if (client->set->auth_verbose) {
			e_info(client->event, "APOP failed: "
			       "Invalid characters in MD5 response");
		}
		client_send_reply(client, POP3_CMD_REPLY_ERROR,
				  "Invalid characters in MD5 response.");
		return TRUE;
	}

	base64 = t_buffer_create(MAX_BASE64_ENCODED_SIZE(apop_data->used));
	base64_encode(apop_data->data, apop_data->used, base64);

	auth_client_get_connect_id(auth_client, &server_pid, &connect_uid);
	if (pop3_client->apop_server_pid != server_pid ||
	    pop3_client->apop_connect_uid != connect_uid) {
		/* we reconnected to auth server and can't authenticate
		   with APOP in this session anymore. disconnecting the user
		   is probably the best solution now. */
		client_destroy(client,
			"Reconnected to auth server, can't do APOP");
		return TRUE;
	}

	(void)client_auth_begin_private(client, "APOP", str_c(base64));
	return TRUE;
}
