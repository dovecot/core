/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "base64.h"
#include "buffer.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "safe-memset.h"
#include "str.h"
#include "str-sanitize.h"
#include "net.h"
#include "imap-resp-code.h"
#include "imap-parser.h"
#include "imap-url.h"
#include "auth-client.h"
#include "imap-login-client.h"
#include "client-authenticate.h"
#include "imap-proxy.h"


void client_authenticate_get_capabilities(struct client *client, string_t *str)
{
	const struct auth_mech_desc *mech;
	unsigned int i, count;

	mech = sasl_server_get_advertised_mechs(client, &count);
	for (i = 0; i < count; i++) {
		str_append_c(str, ' ');
		str_append(str, "AUTH=");
		str_append(str, mech[i].name);
	}
}

void imap_client_auth_result(struct client *client,
			     enum client_auth_result result,
			     const struct client_auth_reply *reply,
			     const char *text)
{
	struct imap_url url;
	string_t *referral;

	switch (result) {
	case CLIENT_AUTH_RESULT_SUCCESS:
		/* nothing to be done for IMAP */
		break;
	case CLIENT_AUTH_RESULT_REFERRAL_SUCCESS:
	case CLIENT_AUTH_RESULT_REFERRAL_NOLOGIN:
		/* IMAP referral

		   [nologin] referral host=.. [port=..] [destuser=..]
		   [reason=..]

		   NO [REFERRAL imap://destuser;AUTH=..@host:port/] Can't login.
		   OK [...] Logged in, but you should use this server instead.
		   .. [REFERRAL ..] (Reason from auth server)
		*/
		referral = t_str_new(128);

		i_zero(&url);
		url.userid = reply->destuser;
		url.auth_type = client->auth_mech_name;
		url.host.name = reply->host;
		if (reply->port != 143)
			url.port = reply->port;
		str_append(referral, "REFERRAL ");
		str_append(referral, imap_url_create(&url));

		if (result == CLIENT_AUTH_RESULT_REFERRAL_SUCCESS) {
			client_send_reply_code(client, IMAP_CMD_REPLY_OK,
					       str_c(referral), text);
		} else {
			client_send_reply_code(client, IMAP_CMD_REPLY_NO,
					       str_c(referral), text);
		}
		break;
	case CLIENT_AUTH_RESULT_INVALID_BASE64:
	case CLIENT_AUTH_RESULT_ABORTED:
		client_send_reply(client, IMAP_CMD_REPLY_BAD, text);
		break;
	case CLIENT_AUTH_RESULT_AUTHFAILED_REASON:
	case CLIENT_AUTH_RESULT_MECH_INVALID:
		if (text[0] == '[')
			client_send_reply(client, IMAP_CMD_REPLY_NO, text);
		else {
			client_send_reply_code(client, IMAP_CMD_REPLY_NO,
					       "ALERT", text);
		}
		break;
	case CLIENT_AUTH_RESULT_AUTHZFAILED:
		client_send_reply_code(client, IMAP_CMD_REPLY_NO,
				       IMAP_RESP_CODE_AUTHZFAILED, text);
		break;
	case CLIENT_AUTH_RESULT_TEMPFAIL:
		client_send_reply_code(client, IMAP_CMD_REPLY_NO,
				       IMAP_RESP_CODE_UNAVAILABLE, text);
		break;
	case CLIENT_AUTH_RESULT_SSL_REQUIRED:
	case CLIENT_AUTH_RESULT_MECH_SSL_REQUIRED:
		client_send_reply_code(client, IMAP_CMD_REPLY_NO,
				       IMAP_RESP_CODE_PRIVACYREQUIRED, text);
		break;
	case CLIENT_AUTH_RESULT_PASS_EXPIRED:
		client_send_reply_code(client, IMAP_CMD_REPLY_NO,
				       IMAP_RESP_CODE_EXPIRED, text);
		break;
	case CLIENT_AUTH_RESULT_LOGIN_DISABLED:
	case CLIENT_AUTH_RESULT_ANONYMOUS_DENIED:
		client_send_reply_code(client, IMAP_CMD_REPLY_NO,
				       IMAP_RESP_CODE_CONTACTADMIN, text);
		break;
	case CLIENT_AUTH_RESULT_AUTHFAILED:
		client_send_reply_code(client, IMAP_CMD_REPLY_NO,
				       IMAP_RESP_CODE_AUTHFAILED, text);
		break;
	}
}

static int
imap_client_auth_begin(struct imap_client *imap_client, const char *mech_name,
		       const char *init_resp)
{
	char *prefix;

	prefix = i_strdup_printf("%d%s",
			imap_client->client_ignores_capability_resp_code ? 1 : 0,
			imap_client->cmd_tag);

	i_free(imap_client->common.master_data_prefix);
	imap_client->common.master_data_prefix = (void *)prefix;
	imap_client->common.master_data_prefix_len = strlen(prefix)+1;

	if (*init_resp == '\0')
		init_resp = NULL;
	else if (strcmp(init_resp, "=") == 0)
		init_resp = "";
	return client_auth_begin(&imap_client->common, mech_name, init_resp);
}

int cmd_authenticate(struct imap_client *imap_client, bool *parsed_r)
{
	/* NOTE: This command's input is handled specially because the
	   SASL-IR can be large. */
	struct client *client = &imap_client->common;
	const unsigned char *data;
	size_t i, size;
	int ret;

	*parsed_r = FALSE;

	/* <auth mechanism name> [<initial SASL response>] */
	if (!imap_client->auth_mech_name_parsed) {
		data = i_stream_get_data(client->input, &size);
		for (i = 0; i < size; i++) {
			if (data[i] == ' ' ||
			    data[i] == '\r' || data[i] == '\n')
				break;
		}
		if (i == size)
			return 0;
		if (i == 0) {
			/* empty mechanism name */
			imap_client->skip_line = TRUE;
			return -1;
		}
		i_free(client->auth_mech_name);
		client->auth_mech_name = i_strndup(data, i);
		imap_client->auth_mech_name_parsed = TRUE;
		if (data[i] == ' ')
			i++;
		i_stream_skip(client->input, i);
	}

	/* get SASL-IR, if any */
	if ((ret = client_auth_read_line(client)) <= 0)
		return ret;

	*parsed_r = TRUE;
	imap_client->auth_mech_name_parsed = FALSE;
	return imap_client_auth_begin(imap_client,
				      t_strdup(client->auth_mech_name),
				      t_strdup(str_c(client->auth_response)));
}

int cmd_login(struct imap_client *imap_client, const struct imap_arg *args)
{
	struct client *client = &imap_client->common;
	const char *user, *pass;
	string_t *plain_login, *base64;

	/* two arguments: username and password */
	if (!imap_arg_get_astring(&args[0], &user) ||
	    !imap_arg_get_astring(&args[1], &pass) ||
	    !IMAP_ARG_IS_EOL(&args[2]))
		return -1;

	if (!client_check_plaintext_auth(client, TRUE)) {
		if (client->virtual_user == NULL)
			client->virtual_user = i_strdup(user);
		return 1;
	}

	/* authorization ID \0 authentication ID \0 pass */
	plain_login = t_buffer_create(64);
	buffer_append_c(plain_login, '\0');
	buffer_append(plain_login, user, strlen(user));
	buffer_append_c(plain_login, '\0');
	buffer_append(plain_login, pass, strlen(pass));

	base64 = t_buffer_create(MAX_BASE64_ENCODED_SIZE(plain_login->used));
	base64_encode(plain_login->data, plain_login->used, base64);
	return imap_client_auth_begin(imap_client, "PLAIN", str_c(base64));
}
