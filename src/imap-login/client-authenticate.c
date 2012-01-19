/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "base64.h"
#include "buffer.h"
#include "hostpid.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "safe-memset.h"
#include "str.h"
#include "str-sanitize.h"
#include "time-util.h"
#include "imap-resp-code.h"
#include "imap-parser.h"
#include "auth-client.h"
#include "client.h"
#include "client-authenticate.h"
#include "imap-proxy.h"

#include <stdlib.h>

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

bool imap_client_auth_handle_reply(struct client *client,
				   const struct client_auth_reply *reply)
{
	struct imap_client *imap_client = (struct imap_client *)client;
	string_t *str;
	const char *timestamp, *msg;

	if (reply->host != NULL) {
		/* IMAP referral

		   [nologin] referral host=.. [port=..] [destuser=..]
		   [reason=..]

		   NO [REFERRAL imap://destuser;AUTH=..@host:port/] Can't login.
		   OK [...] Logged in, but you should use this server instead.
		   .. [REFERRAL ..] (Reason from auth server)
		*/
		str = t_str_new(128);
		str_append(str, imap_client->cmd_tag);
		str_append_c(str, ' ');
		str_append(str, reply->nologin ? "NO " : "OK ");
		str_printfa(str, "[REFERRAL imap://%s;AUTH=%s@%s",
			    reply->destuser, client->auth_mech_name,
			    reply->host);
		if (reply->port != 143)
			str_printfa(str, ":%u", reply->port);
		str_append(str, "/] ");
		if (reply->reason != NULL)
			str_append(str, reply->reason);
		else if (reply->nologin)
			str_append(str, "Try this server instead.");
		else {
			str_append(str, "Logged in, but you should use "
				   "this server instead.");
		}
		str_append(str, "\r\n");
		client_send_raw(client, str_c(str));
		if (!reply->nologin) {
			client_destroy_success(client, "Login with referral");
			return TRUE;
		}
	} else if (!reply->nologin) {
		/* normal login/failure */
		return FALSE;
	} else if (reply->reason != NULL) {
		client_send_line(client, CLIENT_CMD_REPLY_AUTH_FAIL_REASON,
				 reply->reason);
	} else if (reply->temp) {
		timestamp = t_strflocaltime("%Y-%m-%d %H:%M:%S", ioloop_time);
		msg = t_strdup_printf(AUTH_TEMP_FAILED_MSG" [%s:%s]",
				      my_hostname, timestamp);
		client_send_line(client,
				 CLIENT_CMD_REPLY_AUTH_FAIL_TEMP, msg);
	} else if (reply->authz_failure) {
		client_send_line(client, CLIENT_CMD_REPLY_AUTHZ_FAILED,
				 "Authorization failed");
	} else {
		client_send_line(client, CLIENT_CMD_REPLY_AUTH_FAILED,
				 AUTH_FAILED_MSG);
	}

	i_assert(reply->nologin);

	if (!client->destroyed)
		client_auth_failed(client);
	return TRUE;
}

static int
imap_client_auth_begin(struct imap_client *imap_client, const char *mech_name,
		       const char *init_resp)
{
	char *prefix;

	prefix = i_strdup_printf("%d%s",
			imap_client->client_ignores_capability_resp_code,
			imap_client->cmd_tag);

	i_free(imap_client->common.master_data_prefix);
	imap_client->common.master_data_prefix = (void *)prefix;
	imap_client->common.master_data_prefix_len = strlen(prefix)+1;

	return client_auth_begin(&imap_client->common, mech_name, init_resp);
}

int cmd_authenticate(struct imap_client *imap_client)
{
	/* NOTE: This command's input is handled specially because the
	   SASL-IR can be large. */
	struct client *client = &imap_client->common;
	const unsigned char *data;
	size_t i, size;
	int ret;

	/* <auth mechanism name> [<initial SASL response>] */
	if (client->auth_mech_name == NULL) {
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
		client->auth_mech_name = i_strndup(data, i);
		if (data[i] == ' ')
			i++;
		i_stream_skip(client->input, i);
	}

	/* get SASL-IR, if any */
	if ((ret = client_auth_read_line(client)) <= 0)
		return ret;

	return imap_client_auth_begin(imap_client,
				      t_strdup(client->auth_mech_name),
				      str_c(client->auth_response));
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

	if (!client_check_plaintext_auth(client, TRUE))
		return 1;

	/* authorization ID \0 authentication ID \0 pass */
	plain_login = buffer_create_dynamic(pool_datastack_create(), 64);
	buffer_append_c(plain_login, '\0');
	buffer_append(plain_login, user, strlen(user));
	buffer_append_c(plain_login, '\0');
	buffer_append(plain_login, pass, strlen(pass));

	base64 = buffer_create_dynamic(pool_datastack_create(),
        			MAX_BASE64_ENCODED_SIZE(plain_login->used));
	base64_encode(plain_login->data, plain_login->used, base64);
	return imap_client_auth_begin(imap_client, "PLAIN", str_c(base64));
}
