/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

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
#include "imap-login-client.h"
#include "client-authenticate.h"
#include "imap-resp-code.h"
#include "imap-quote.h"
#include "imap-proxy.h"

static const char *imap_proxy_sent_state_names[IMAP_PROXY_SENT_STATE_COUNT] = {
	"id", "starttls", "capability",
	"authenticate", "auth-continue", "login"
};
static const char *imap_proxy_rcvd_state_names[IMAP_PROXY_RCVD_STATE_COUNT] = {
	"none", "banner", "id", "starttls", "capability",
	"auth-continue", "login"
};

static void proxy_write_id(struct imap_client *client, string_t *str)
{
	i_assert(client->common.proxy_ttl > 1);

	str_append(str, "I ID (");
	if (client->common.client_id != NULL &&
	    str_len(client->common.client_id) > 0) {
		str_append_str(str, client->common.client_id);
		str_append_c(str, ' ');
	}
	str_printfa(str, "\"x-session-id\" \"%s\" "
		    "\"x-originating-ip\" \"%s\" "
		    "\"x-originating-port\" \"%u\" "
		    "\"x-connected-ip\" \"%s\" "
		    "\"x-connected-port\" \"%u\" "
		    "\"x-proxy-ttl\" \"%u\"",
		    client_get_session_id(&client->common),
		    net_ip2addr(&client->common.ip),
		    client->common.remote_port,
		    net_ip2addr(&client->common.local_ip),
		    client->common.local_port,
		    client->common.proxy_ttl - 1);

	/* append any forward_ variables to request */
	for(const char *const *ptr = client->common.auth_passdb_args; *ptr != NULL; ptr++) {
		if (strncasecmp(*ptr, "forward_", 8) == 0) {
			const char *key = t_strconcat("x-forward-",
						      t_strcut((*ptr)+8, '='),
						      NULL);
			const char *val = i_strchr_to_next(*ptr, '=');
			str_append_c(str, ' ');
			imap_append_string(str, key);
			str_append_c(str, ' ');
			imap_append_nstring(str, val);
		}
	}

	str_append(str, ")\r\n");
}

static void proxy_free_password(struct client *client)
{
	if (client->proxy_password == NULL)
		return;

	safe_memset(client->proxy_password, 0, strlen(client->proxy_password));
	i_free_and_null(client->proxy_password);
}

static int proxy_write_starttls(struct imap_client *client, string_t *str)
{
	enum login_proxy_ssl_flags ssl_flags = login_proxy_get_ssl_flags(client->common.login_proxy);
	if ((ssl_flags & PROXY_SSL_FLAG_STARTTLS) != 0) {
		if (client->proxy_backend_capability != NULL &&
		    !str_array_icase_find(t_strsplit(client->proxy_backend_capability, " "), "STARTTLS")) {
			e_error(login_proxy_get_event(client->common.login_proxy),
				"Remote doesn't support STARTTLS");
			client_proxy_failed(&client->common, TRUE);
			return -1;
		}
		str_append(str, "S STARTTLS\r\n");
		client->proxy_sent_state |= IMAP_PROXY_SENT_STATE_STARTTLS;
		return 1;
	}
	return 0;
}

static int proxy_write_login(struct imap_client *client, string_t *str)
{
	struct dsasl_client_settings sasl_set;
	const unsigned char *output;
	size_t len;
	const char *mech_name, *error;

	/* Send CAPABILITY command if we don't know the capabilities yet.
	   Also as kind of a Dovecot-backend workaround if the client insisted
	   on sending CAPABILITY command (even though our banner already sent
	   it), send the (unnecessary) CAPABILITY command to backend as well
	   to avoid sending the CAPABILITY reply twice (untagged and OK resp
	   code). */
	if (!client->proxy_capability_request_sent &&
	    (client->proxy_backend_capability == NULL ||
	     client->client_ignores_capability_resp_code)) {
		client->proxy_capability_request_sent = TRUE;
		client->proxy_sent_state |= IMAP_PROXY_SENT_STATE_CAPABILITY;
		str_append(str, "C CAPABILITY\r\n");
		if (client->common.proxy_nopipelining) {
			/* authenticate only after receiving C OK reply. */
			return 0;
		}
	}

	if (client->common.proxy_mech == NULL) {
		/* logging in normally - use LOGIN command */
		if (client->proxy_logindisabled &&
		    login_proxy_get_ssl_flags(client->common.login_proxy) == 0) {
			e_error(login_proxy_get_event(client->common.login_proxy),
				"Remote advertised LOGINDISABLED and SSL/TLS not enabled");
			client_proxy_failed(&client->common, TRUE);
			return -1;
		}
		str_append(str, "L LOGIN ");
		imap_append_string(str, client->common.proxy_user);
		str_append_c(str, ' ');
		imap_append_string(str, client->common.proxy_password);
		str_append(str, "\r\n");

		client->proxy_sent_state |= IMAP_PROXY_SENT_STATE_LOGIN;
		proxy_free_password(&client->common);
		return 0;
	}

	i_assert(client->common.proxy_sasl_client == NULL);
	i_zero(&sasl_set);
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
			e_error(login_proxy_get_event(client->common.login_proxy),
				"SASL mechanism %s init failed: %s",
				mech_name, error);
			client_proxy_failed(&client->common, TRUE);
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
	client->proxy_sent_state |= IMAP_PROXY_SENT_STATE_AUTHENTICATE;
	return 0;
}

static int proxy_input_banner(struct imap_client *client,
			      struct ostream *output, const char *line)
{
	const char *const *capabilities = NULL;
	string_t *str;
	int ret;

	if (!str_begins(line, "* OK ")) {
		e_error(login_proxy_get_event(client->common.login_proxy),
			"Remote returned invalid banner: %s",
			str_sanitize(line, 160));
		client_proxy_failed(&client->common, TRUE);
		return -1;
	}

	str = t_str_new(128);
	if (str_begins(line + 5, "[CAPABILITY ")) {
		capabilities = t_strsplit(t_strcut(line + 5 + 12, ']'), " ");
		if (str_array_icase_find(capabilities, "SASL-IR"))
			client->proxy_sasl_ir = TRUE;
		if (str_array_icase_find(capabilities, "LOGINDISABLED"))
			client->proxy_logindisabled = TRUE;
		i_free(client->proxy_backend_capability);
		client->proxy_backend_capability =
			i_strdup(t_strcut(line + 5 + 12, ']'));
		if (str_array_icase_find(capabilities, "ID") &&
		    !client->common.proxy_not_trusted) {
			client->proxy_sent_state |= IMAP_PROXY_SENT_STATE_ID;
			proxy_write_id(client, str);
			if (client->common.proxy_nopipelining) {
				/* write login or starttls after I OK */
				o_stream_nsend(output, str_data(str), str_len(str));
				return 0;
			}
		}
	}

	if ((ret = proxy_write_starttls(client, str)) < 0) {
		return -1;
	} else if (ret == 0) {
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
	size_t data_len;
	const char *error;
	int ret;

	i_assert(!client->destroyed);

	output = login_proxy_get_ostream(client->login_proxy);
	if (!imap_client->proxy_seen_banner) {
		/* this is a banner */
		imap_client->proxy_rcvd_state = IMAP_PROXY_RCVD_STATE_BANNER;
		imap_client->proxy_seen_banner = TRUE;
		if (proxy_input_banner(imap_client, output, line) < 0)
			return -1;
		return 0;
	} else if (*line == '+') {
		/* AUTHENTICATE started. finish it. */
		if (client->proxy_sasl_client == NULL) {
			/* used literals with LOGIN command, just ignore. */
			return 0;
		}
		imap_client->proxy_sent_state &= ~IMAP_PROXY_SENT_STATE_AUTHENTICATE;
		imap_client->proxy_rcvd_state = IMAP_PROXY_RCVD_STATE_AUTH_CONTINUE;

		str = t_str_new(128);
		if (line[1] != ' ' ||
		    base64_decode(line+2, strlen(line+2), NULL, str) < 0) {
			e_error(login_proxy_get_event(client->login_proxy),
				"Server sent invalid base64 data in AUTHENTICATE response");
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
			e_error(login_proxy_get_event(client->login_proxy),
				"Server sent invalid authentication data: %s",
				error);
			client_proxy_failed(client, TRUE);
			return -1;
		}
		i_assert(ret == 0);

		str_truncate(str, 0);
		base64_encode(data, data_len, str);
		str_append(str, "\r\n");

		imap_client->proxy_sent_state |= IMAP_PROXY_SENT_STATE_AUTH_CONTINUE;
		o_stream_nsend(output, str_data(str), str_len(str));
		return 0;
	} else if (str_begins(line, "S ")) {
		imap_client->proxy_sent_state &= ~IMAP_PROXY_SENT_STATE_STARTTLS;
		imap_client->proxy_rcvd_state = IMAP_PROXY_RCVD_STATE_STARTTLS;

		if (!str_begins(line, "S OK ")) {
			/* STARTTLS failed */
			e_error(login_proxy_get_event(client->login_proxy),
				"Remote STARTTLS failed: %s",
				str_sanitize(line + 5, 160));
			client_proxy_failed(client, TRUE);
			return -1;
		}
		/* STARTTLS successful, begin TLS negotiation. */
		if (login_proxy_starttls(client->login_proxy) < 0)
			return -1;
		/* i/ostreams changed. */
		output = login_proxy_get_ostream(client->login_proxy);
		str = t_str_new(128);
		if (proxy_write_login(imap_client, str) < 0)
			return -1;
		o_stream_nsend(output, str_data(str), str_len(str));
		return 1;
	} else if (str_begins(line, "L OK ")) {
		/* Login successful. Send this line to client. */
		imap_client->proxy_sent_state &= ~IMAP_PROXY_SENT_STATE_LOGIN;
		imap_client->proxy_rcvd_state = IMAP_PROXY_RCVD_STATE_LOGIN;
		str = t_str_new(128);
		client_send_login_reply(imap_client, str, line + 5);
		o_stream_nsend(client->output, str_data(str), str_len(str));

		client_proxy_finish_destroy_client(client);
		return 1;
	} else if (str_begins(line, "L ")) {
		imap_client->proxy_sent_state &= ~IMAP_PROXY_SENT_STATE_LOGIN;
		imap_client->proxy_rcvd_state = IMAP_PROXY_RCVD_STATE_LOGIN;

		line += 2;
		if (client->set->auth_verbose) {
			const char *log_line = line;

			if (strncasecmp(log_line, "NO ", 3) == 0)
				log_line += 3;
			client_proxy_log_failure(client, log_line);
		}
#define STR_NO_IMAP_RESP_CODE_AUTHFAILED "NO ["IMAP_RESP_CODE_AUTHFAILED"]"
		if (str_begins(line, STR_NO_IMAP_RESP_CODE_AUTHFAILED)) {
			/* the remote sent a generic "authentication failed"
			   error. replace it with our one, so that in case
			   the remote is sending a different error message
			   an attacker can't find out what users exist in
			   the system. */
			client_send_reply_code(client, IMAP_CMD_REPLY_NO,
					       IMAP_RESP_CODE_AUTHFAILED,
					       AUTH_FAILED_MSG);
		} else if (str_begins(line, "NO [")) {
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
	} else if (str_begins(line, "C ")) {
		/* Reply to CAPABILITY command we sent */
		imap_client->proxy_sent_state &= ~IMAP_PROXY_SENT_STATE_CAPABILITY;
		imap_client->proxy_rcvd_state = IMAP_PROXY_RCVD_STATE_CAPABILITY;
		if (str_begins(line, "C OK ") &&
		    client->proxy_password != NULL) {
			/* pipelining was disabled, send the login now. */
			str = t_str_new(128);
			if (proxy_write_login(imap_client, str) < 0)
				return -1;
			o_stream_nsend(output, str_data(str), str_len(str));
			return 1;
		}
		return 0;
	} else if (strncasecmp(line, "I ", 2) == 0) {
		/* Reply to ID command we sent, ignore it unless
		   pipelining is disabled, in which case send
		   either STARTTLS or login */
		imap_client->proxy_sent_state &= ~IMAP_PROXY_SENT_STATE_ID;
		imap_client->proxy_rcvd_state = IMAP_PROXY_RCVD_STATE_ID;

		if (client->proxy_nopipelining) {
			str = t_str_new(128);
			if ((ret = proxy_write_starttls(imap_client, str)) < 0) {
				return -1;
			} else if (ret == 0) {
				if (proxy_write_login(imap_client, str) < 0)
					return -1;
			}
			o_stream_nsend(output, str_data(str), str_len(str));
			return 1;
		}
		return 0;
	} else if (strncasecmp(line, "* ID ", 5) == 0) {
		/* Reply to ID command we sent, ignore it */
		return 0;
	} else if (str_begins(line, "* ")) {
		/* untagged reply. just forward it. */
		client_send_raw(client, t_strconcat(line, "\r\n", NULL));
		return 0;
	} else {
		/* tagged reply, shouldn't happen. */
		e_error(login_proxy_get_event(client->login_proxy),
			"Unexpected input, ignoring: %s",
			str_sanitize(line, 160));
		return 0;
	}
}

void imap_proxy_reset(struct client *client)
{
	struct imap_client *imap_client = (struct imap_client *)client;

	imap_client->proxy_sasl_ir = FALSE;
	imap_client->proxy_logindisabled = FALSE;
	imap_client->proxy_seen_banner = FALSE;
	imap_client->proxy_capability_request_sent = FALSE;
	imap_client->proxy_sent_state = 0;
	imap_client->proxy_rcvd_state = IMAP_PROXY_RCVD_STATE_NONE;
}

void imap_proxy_error(struct client *client, const char *text)
{
	client_send_reply_code(client, IMAP_CMD_REPLY_NO,
			       IMAP_RESP_CODE_UNAVAILABLE, text);
}

const char *imap_proxy_get_state(struct client *client)
{
	struct imap_client *imap_client = (struct imap_client *)client;
	string_t *str = t_str_new(128);

	for (unsigned int i = 0; i < IMAP_PROXY_SENT_STATE_COUNT; i++) {
		if ((imap_client->proxy_sent_state & (1 << i)) != 0) {
			if (str_len(str) > 0)
				str_append_c(str, '+');
			str_append(str, imap_proxy_sent_state_names[i]);
		}
	}
	str_append_c(str, '/');
	str_append(str, imap_proxy_rcvd_state_names[imap_client->proxy_rcvd_state]);
	return str_c(str);
}
