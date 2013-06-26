/* Copyright (c) 2004-2013 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "base64.h"
#include "str.h"
#include "str-sanitize.h"
#include "safe-memset.h"
#include "dsasl-client.h"
#include "client.h"
#include "client-authenticate.h"
#include "imap-resp-code.h"
#include "imap-quote.h"
#include "imap-proxy.h"

#include <stdlib.h>

enum imap_proxy_state {
	IMAP_PROXY_STATE_NONE,
	IMAP_PROXY_STATE_BANNER,
	IMAP_PROXY_STATE_ID,
	IMAP_PROXY_STATE_STARTTLS,
	IMAP_PROXY_STATE_CAPABILITY,
	IMAP_PROXY_STATE_AUTH_CONTINUE,
	IMAP_PROXY_STATE_LOGIN
};

static void proxy_write_id(struct imap_client *client, string_t *str)
{
	i_assert(client->common.proxy_ttl > 1);

	str_printfa(str, "I ID ("
		    "\"x-session-id\" \"%s\" "
		    "\"x-originating-ip\" \"%s\" "
		    "\"x-originating-port\" \"%u\" "
		    "\"x-connected-ip\" \"%s\" "
		    "\"x-connected-port\" \"%u\" "
		    "\"x-proxy-ttl\" \"%u\")\r\n",
		    client_get_session_id(&client->common),
		    net_ip2addr(&client->common.ip),
		    client->common.remote_port,
		    net_ip2addr(&client->common.local_ip),
		    client->common.local_port,
		    client->common.proxy_ttl - 1);
}

static void proxy_free_password(struct client *client)
{
	if (client->proxy_password == NULL)
		return;

	safe_memset(client->proxy_password, 0, strlen(client->proxy_password));
	i_free_and_null(client->proxy_password);
}

static int proxy_write_login(struct imap_client *client, string_t *str)
{
	struct dsasl_client_settings sasl_set;
	const unsigned char *output;
	unsigned int len;
	const char *mech_name, *error;

	if (client->proxy_backend_capability == NULL)
		str_append(str, "C CAPABILITY\r\n");

	if (client->common.proxy_mech == NULL) {
		/* logging in normally - use LOGIN command */
		str_append(str, "L LOGIN ");
		imap_append_string(str, client->common.proxy_user);
		str_append_c(str, ' ');
		imap_append_string(str, client->common.proxy_password);
		str_append(str, "\r\n");

		proxy_free_password(&client->common);
		return 0;
	}

	i_assert(client->common.proxy_sasl_client == NULL);
	memset(&sasl_set, 0, sizeof(sasl_set));
	sasl_set.authid = client->common.proxy_master_user != NULL ?
		client->common.proxy_master_user : client->common.proxy_user;
	sasl_set.authzid = client->common.proxy_user;
	sasl_set.password = client->common.proxy_password;
	client->common.proxy_sasl_client =
		dsasl_client_new(client->common.proxy_mech, &sasl_set);
	mech_name = dsasl_client_mech_get_name(client->common.proxy_mech);

	str_append(str, "L AUTHENTICATE ");
	str_append(str, mech_name);
	if (client->proxy_sasl_ir) {
		if (dsasl_client_output(client->common.proxy_sasl_client,
					&output, &len, &error) < 0) {
			client_log_err(&client->common, t_strdup_printf(
				"proxy: SASL mechanism %s init failed: %s",
				mech_name, error));
			return -1;
		}
		str_append_c(str, ' ');
		if (len == 0)
			str_append_c(str, '=');
		else
			base64_encode(output, len, str);
	}
	str_append(str, "\r\n");
	proxy_free_password(&client->common);
	return 0;
}

static int proxy_input_banner(struct imap_client *client,
			      struct ostream *output, const char *line)
{
	enum login_proxy_ssl_flags ssl_flags;
	const char *const *capabilities = NULL;
	string_t *str;

	if (strncmp(line, "* OK ", 5) != 0) {
		client_log_err(&client->common, t_strdup_printf(
			"proxy: Remote returned invalid banner: %s",
			str_sanitize(line, 160)));
		return -1;
	}

	str = t_str_new(128);
	if (strncmp(line + 5, "[CAPABILITY ", 12) == 0) {
		capabilities = t_strsplit(t_strcut(line + 5 + 12, ']'), " ");
		if (str_array_icase_find(capabilities, "ID"))
			proxy_write_id(client, str);
		if (str_array_icase_find(capabilities, "SASL-IR"))
			client->proxy_sasl_ir = TRUE;
		i_free(client->proxy_backend_capability);
		client->proxy_backend_capability =
			i_strdup(t_strcut(line + 5 + 12, ']'));
	}

	ssl_flags = login_proxy_get_ssl_flags(client->common.login_proxy);
	if ((ssl_flags & PROXY_SSL_FLAG_STARTTLS) != 0) {
		if (capabilities != NULL &&
		    !str_array_icase_find(capabilities, "STARTTLS")) {
			client_log_err(&client->common,
				"proxy: Remote doesn't support STARTTLS");
			return -1;
		}
		str_append(str, "S STARTTLS\r\n");
	} else {
		if (proxy_write_login(client, str) < 0)
			return -1;
	}

	o_stream_nsend(output, str_data(str), str_len(str));
	return 0;
}

static void
client_send_login_reply(struct imap_client *client, string_t *str,
			const char *line)
{
	const char *capability;
	bool tagged_capability;

	capability = client->proxy_backend_capability;
	tagged_capability = strncasecmp(line, "[CAPABILITY ", 12) == 0;
	if (tagged_capability)
		capability = t_strcut(line + 12, ']');

	if (client->client_ignores_capability_resp_code && capability != NULL) {
		/* client has used CAPABILITY command, so it didn't understand
		   the capabilities in the banner. send the backend's untagged
		   CAPABILITY reply and hope that the client understands it */
		str_printfa(str, "* CAPABILITY %s\r\n", capability);
	}
	str_append(str, client->cmd_tag);
	str_append(str, " OK ");
	if (!client->client_ignores_capability_resp_code &&
	    !tagged_capability && capability != NULL) {
		str_printfa(str, "[CAPABILITY %s] ", capability);
		if (*line == '[') {
			/* we need to send the capability.
			   skip over this resp-code */
			while (*line != ']' && *line != '\0')
				line++;
			if (*line == ' ') line++;
		}
	}
	str_append(str, line);
	str_append(str, "\r\n");
}

int imap_proxy_parse_line(struct client *client, const char *line)
{
	struct imap_client *imap_client = (struct imap_client *)client;
	struct ostream *output;
	string_t *str;
	const unsigned char *data;
	unsigned int data_len;
	const char *error;
	int ret;

	i_assert(!client->destroyed);

	output = login_proxy_get_ostream(client->login_proxy);
	if (!imap_client->proxy_seen_banner) {
		/* this is a banner */
		client->proxy_state = IMAP_PROXY_STATE_BANNER;
		imap_client->proxy_seen_banner = TRUE;
		if (proxy_input_banner(imap_client, output, line) < 0) {
			client_proxy_failed(client, TRUE);
			return -1;
		}
		return 0;
	} else if (*line == '+') {
		/* AUTHENTICATE started. finish it. */
		if (client->proxy_sasl_client == NULL) {
			/* used literals with LOGIN command, just ignore. */
			return 0;
		}
		client->proxy_state = IMAP_PROXY_STATE_AUTH_CONTINUE;

		str = t_str_new(128);
		if (line[1] != ' ' ||
		    base64_decode(line+2, strlen(line+2), NULL, str) < 0) {
			client_log_err(client,
				"proxy: Server sent invalid base64 data in AUTHENTICATE response");
			client_proxy_failed(client, TRUE);
			return -1;
		}
		ret = dsasl_client_input(client->proxy_sasl_client,
					 str_data(str), str_len(str), &error);
		if (ret == 0) {
			ret = dsasl_client_output(client->proxy_sasl_client,
						  &data, &data_len, &error);
		}
		if (ret < 0) {
			client_log_err(client, t_strdup_printf(
				"proxy: Server sent invalid authentication data: %s",
				error));
			client_proxy_failed(client, TRUE);
			return -1;
		}
		i_assert(ret == 0);

		str_truncate(str, 0);
		base64_encode(data, data_len, str);
		str_append(str, "\r\n");

		o_stream_nsend(output, str_data(str), str_len(str));
		return 0;
	} else if (strncmp(line, "S ", 2) == 0) {
		if (strncmp(line, "S OK ", 5) != 0) {
			/* STARTTLS failed */
			client_log_err(client, t_strdup_printf(
				"proxy: Remote STARTTLS failed: %s",
				str_sanitize(line + 5, 160)));
			client_proxy_failed(client, TRUE);
			return -1;
		}
		/* STARTTLS successful, begin TLS negotiation. */
		client->proxy_state = IMAP_PROXY_STATE_STARTTLS;
		if (login_proxy_starttls(client->login_proxy) < 0) {
			client_proxy_failed(client, TRUE);
			return -1;
		}
		/* i/ostreams changed. */
		output = login_proxy_get_ostream(client->login_proxy);
		str = t_str_new(128);
		if (proxy_write_login(imap_client, str) < 0) {
			client_proxy_failed(client, TRUE);
			return -1;
		}
		o_stream_nsend(output, str_data(str), str_len(str));
		return 1;
	} else if (strncmp(line, "L OK ", 5) == 0) {
		/* Login successful. Send this line to client. */
		client->proxy_state = IMAP_PROXY_STATE_LOGIN;
		str = t_str_new(128);
		client_send_login_reply(imap_client, str, line + 5);
		o_stream_nsend(client->output, str_data(str), str_len(str));

		(void)client_skip_line(imap_client);
		client_proxy_finish_destroy_client(client);
		return 1;
	} else if (strncmp(line, "L ", 2) == 0) {
		line += 2;
		if (client->set->auth_verbose) {
			const char *log_line = line;

			if (strncasecmp(log_line, "NO ", 3) == 0)
				log_line += 3;
			client_proxy_log_failure(client, log_line);
		}
#define STR_NO_IMAP_RESP_CODE_AUTHFAILED "NO ["IMAP_RESP_CODE_AUTHFAILED"]"
		if (strncmp(line, STR_NO_IMAP_RESP_CODE_AUTHFAILED,
			    strlen(STR_NO_IMAP_RESP_CODE_AUTHFAILED)) == 0) {
			/* the remote sent a generic "authentication failed"
			   error. replace it with our one, so that in case
			   the remote is sending a different error message
			   an attacker can't find out what users exist in
			   the system. */
			client_send_reply_code(client, IMAP_CMD_REPLY_NO,
					       IMAP_RESP_CODE_AUTHFAILED,
					       AUTH_FAILED_MSG);
		} else if (strncmp(line, "NO [", 4) == 0) {
			/* remote sent some other resp-code. forward it. */
			client_send_raw(client, t_strconcat(
				imap_client->cmd_tag, " ", line, "\r\n", NULL));
		} else {
			/* there was no [resp-code], so remote isn't Dovecot
			   v1.2+. we could either forward the line as-is and
			   leak information about what users exist in this
			   system, or we could hide other errors than password
			   failures. since other errors are pretty rare,
			   it's safer to just hide them. they're still
			   available in logs though. */
			client_send_reply_code(client, IMAP_CMD_REPLY_NO,
					       IMAP_RESP_CODE_AUTHFAILED,
					       AUTH_FAILED_MSG);
		}

		client->proxy_auth_failed = TRUE;
		client_proxy_failed(client, FALSE);
		return -1;
	} else if (strncasecmp(line, "* CAPABILITY ", 13) == 0) {
		i_free(imap_client->proxy_backend_capability);
		imap_client->proxy_backend_capability = i_strdup(line + 13);
		return 0;
	} else if (strncmp(line, "C ", 2) == 0) {
		/* Reply to CAPABILITY command we sent, ignore it */
		client->proxy_state = IMAP_PROXY_STATE_CAPABILITY;
		return 0;
	} else if (strncasecmp(line, "I ", 2) == 0 ||
		   strncasecmp(line, "* ID ", 5) == 0) {
		/* Reply to ID command we sent, ignore it */
		client->proxy_state = IMAP_PROXY_STATE_ID;
		return 0;
	} else if (strncmp(line, "* ", 2) == 0) {
		/* untagged reply. just foward it. */
		client_send_raw(client, t_strconcat(line, "\r\n", NULL));
		return 0;
	} else {
		/* tagged reply, shouldn't happen. */
		client_log_err(client, t_strdup_printf(
			"proxy: Unexpected input, ignoring: %s",
			str_sanitize(line, 160)));
		return 0;
	}
}

void imap_proxy_reset(struct client *client)
{
	struct imap_client *imap_client = (struct imap_client *)client;

	imap_client->proxy_sasl_ir = FALSE;
	imap_client->proxy_seen_banner = FALSE;
	client->proxy_state = IMAP_PROXY_STATE_NONE;
}

void imap_proxy_error(struct client *client, const char *text)
{
	client_send_reply_code(client, IMAP_CMD_REPLY_NO,
			       IMAP_RESP_CODE_UNAVAILABLE, text);
}
