/* Copyright (c) 2004-2012 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "base64.h"
#include "safe-memset.h"
#include "str.h"
#include "str-sanitize.h"
#include "client.h"
#include "pop3-proxy.h"

static void proxy_free_password(struct client *client)
{
	if (client->proxy_password == NULL)
		return;

	safe_memset(client->proxy_password, 0, strlen(client->proxy_password));
	i_free_and_null(client->proxy_password);
}

static void get_plain_auth(struct client *client, string_t *dest)
{
	string_t *str;

	str = t_str_new(128);
	str_append(str, client->proxy_user);
	str_append_c(str, '\0');
	str_append(str, client->proxy_master_user);
	str_append_c(str, '\0');
	str_append(str, client->proxy_password);
	base64_encode(str_data(str), str_len(str), dest);
}

static void proxy_send_login(struct pop3_client *client, struct ostream *output)
{
	string_t *str;

	i_assert(client->common.proxy_ttl > 0);
	if (client->proxy_xclient) {
		/* remote supports XCLIENT, send it */
		o_stream_nsend_str(output, t_strdup_printf(
			"XCLIENT ADDR=%s PORT=%u SESSION=%s TTL=%u\r\n",
			net_ip2addr(&client->common.ip),
			client->common.remote_port,
			client_get_session_id(&client->common),
			client->common.proxy_ttl - 1));
		client->common.proxy_state = POP3_PROXY_XCLIENT;
	} else {
		client->common.proxy_state = POP3_PROXY_LOGIN1;
	}

	str = t_str_new(128);
	if (client->common.proxy_master_user == NULL) {
		/* send USER command */
		str_append(str, "USER ");
		str_append(str, client->common.proxy_user);
		str_append(str, "\r\n");
	} else {
		/* master user login - use AUTH PLAIN. */
		str_append(str, "AUTH PLAIN\r\n");
	}
	o_stream_nsend(output, str_data(str), str_len(str));
}

int pop3_proxy_parse_line(struct client *client, const char *line)
{
	struct pop3_client *pop3_client = (struct pop3_client *)client;
	struct ostream *output;
	enum login_proxy_ssl_flags ssl_flags;
	string_t *str;

	i_assert(!client->destroyed);

	output = login_proxy_get_ostream(client->login_proxy);
	switch (client->proxy_state) {
	case POP3_PROXY_BANNER:
		/* this is a banner */
		if (strncmp(line, "+OK", 3) != 0) {
			client_log_err(client, t_strdup_printf(
				"proxy: Remote returned invalid banner: %s",
				str_sanitize(line, 160)));
			client_proxy_failed(client, TRUE);
			return -1;
		}
		pop3_client->proxy_xclient =
			strncmp(line+3, " [XCLIENT]", 10) == 0;

		ssl_flags = login_proxy_get_ssl_flags(client->login_proxy);
		if ((ssl_flags & PROXY_SSL_FLAG_STARTTLS) == 0) {
			proxy_send_login(pop3_client, output);
		} else {
			o_stream_nsend_str(output, "STLS\r\n");
			client->proxy_state = POP3_PROXY_STARTTLS;
		}
		return 0;
	case POP3_PROXY_STARTTLS:
		if (strncmp(line, "+OK", 3) != 0) {
			client_log_err(client, t_strdup_printf(
				"proxy: Remote STLS failed: %s",
				str_sanitize(line, 160)));
			client_proxy_failed(client, TRUE);
			return -1;
		}
		if (login_proxy_starttls(client->login_proxy) < 0) {
			client_proxy_failed(client, TRUE);
			return -1;
		}
		/* i/ostreams changed. */
		output = login_proxy_get_ostream(client->login_proxy);
		proxy_send_login(pop3_client, output);
		return 1;
	case POP3_PROXY_XCLIENT:
		if (strncmp(line, "+OK", 3) != 0) {
			client_log_err(client, t_strdup_printf(
				"proxy: Remote XCLIENT failed: %s",
				str_sanitize(line, 160)));
			client_proxy_failed(client, TRUE);
			return -1;
		}
		client->proxy_state = POP3_PROXY_LOGIN1;
		return 0;
	case POP3_PROXY_LOGIN1:
		str = t_str_new(128);
		if (client->proxy_master_user == NULL) {
			if (strncmp(line, "+OK", 3) != 0)
				break;

			/* USER successful, send PASS */
			str_append(str, "PASS ");
			str_append(str, client->proxy_password);
			str_append(str, "\r\n");
		} else {
			if (*line != '+')
				break;
			/* AUTH successful, send the authentication data */
			get_plain_auth(client, str);
			str_append(str, "\r\n");
		}
		o_stream_nsend(output, str_data(str), str_len(str));
		proxy_free_password(client);
		client->proxy_state = POP3_PROXY_LOGIN2;
		return 0;
	case POP3_PROXY_LOGIN2:
		if (strncmp(line, "+OK", 3) != 0)
			break;

		/* Login successful. Send this line to client. */
		line = t_strconcat(line, "\r\n", NULL);
		o_stream_nsend_str(client->output, line);

		client_proxy_finish_destroy_client(client);
		return 1;
	}

	/* Login failed. Pass through the error message to client.

	   If the backend server isn't Dovecot, the error message may
	   be different from Dovecot's "user doesn't exist" error. This
	   would allow an attacker to find out what users exist in the
	   system.

	   The optimal way to handle this would be to replace the
	   backend's "password failed" error message with Dovecot's
	   AUTH_FAILED_MSG, but this would require a new setting and
	   the sysadmin to actually bother setting it properly.

	   So for now we'll just forward the error message. This
	   shouldn't be a real problem since of course everyone will
	   be using only Dovecot as their backend :) */
	if (strncmp(line, "-ERR ", 5) != 0) {
		client_send_reply(client, POP3_CMD_REPLY_ERROR,
				  AUTH_FAILED_MSG);
	} else {
		client_send_raw(client, t_strconcat(line, "\r\n", NULL));
	}

	if (client->set->auth_verbose) {
		if (strncmp(line, "-ERR ", 5) == 0)
			line += 5;
		client_proxy_log_failure(client, line);
	}
	client->proxy_auth_failed = TRUE;
	client_proxy_failed(client, FALSE);
	return -1;
}

void pop3_proxy_reset(struct client *client)
{
	client->proxy_state = POP3_PROXY_BANNER;
}

void pop3_proxy_error(struct client *client, const char *text)
{
	client_send_reply(client, POP3_CMD_REPLY_ERROR, text);
}
