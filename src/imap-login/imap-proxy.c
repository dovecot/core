/* Copyright (c) 2004-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "base64.h"
#include "str.h"
#include "str-sanitize.h"
#include "safe-memset.h"
#include "client.h"
#include "imap-resp-code.h"
#include "imap-quote.h"
#include "imap-proxy.h"

#define PROXY_FAILURE_MSG \
	"NO ["IMAP_RESP_CODE_UNAVAILABLE"] "AUTH_TEMP_FAILED_MSG

static bool imap_banner_has_capability(const char *line, const char *capability)
{
	unsigned int capability_len = strlen(capability);

	if (strncmp(line, "[CAPABILITY ", 12) != 0)
		return FALSE;

	line += 12;
	while (strncmp(line, capability, capability_len) != 0 ||
	       (line[capability_len] != ' ' &&
		line[capability_len] != '\0')) {
		/* skip over the capability */
		while (*line != ' ') {
			if (*line == '\0')
				return FALSE;
			line++;
		}
		line++;
	}
	return TRUE;
}

static void proxy_write_id(struct imap_client *client, string_t *str)
{
	str_printfa(str, "I ID ("
		    "\"x-originating-ip\" \"%s\" "
		    "\"x-originating-port\" \"%u\" "
		    "\"x-connected-ip\" \"%s\" "
		    "\"x-connected-port\" \"%u\")\r\n",
		    net_ip2addr(&client->common.ip),
		    client->common.remote_port,
		    net_ip2addr(&client->common.local_ip),
		    client->common.local_port);
}

static void proxy_free_password(struct imap_client *client)
{
	if (client->proxy_password == NULL)
		return;

	safe_memset(client->proxy_password, 0, strlen(client->proxy_password));
	i_free_and_null(client->proxy_password);
}

static void proxy_failed(struct imap_client *client, bool send_tagline)
{
	if (send_tagline)
		client_send_tagline(client, PROXY_FAILURE_MSG);

	login_proxy_free(&client->proxy);
	proxy_free_password(client);
	i_free_and_null(client->proxy_user);
	i_free_and_null(client->proxy_master_user);

	/* call this last - it may destroy the client */
	client_auth_failed(client, TRUE);
}

static void get_plain_auth(struct imap_client *client, string_t *dest)
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

static int proxy_input_banner(struct imap_client *client,
			      struct ostream *output, const char *line)
{
	string_t *str;

	if (strncmp(line, "* OK ", 5) != 0) {
		client_syslog_err(&client->common, t_strdup_printf(
			"proxy: Remote returned invalid banner: %s",
			str_sanitize(line, 160)));
		return -1;
	}

	str = t_str_new(128);
	if (imap_banner_has_capability(line + 5, "ID"))
		proxy_write_id(client, str);

	if (client->proxy_master_user == NULL) {
		/* logging in normally - use LOGIN command */
		str_append(str, "L LOGIN ");
		imap_quote_append_string(str, client->proxy_user, FALSE);
		str_append_c(str, ' ');
		imap_quote_append_string(str, client->proxy_password, FALSE);

		proxy_free_password(client);
	} else if (imap_banner_has_capability(line + 5, "SASL-IR")) {
		/* master user login with SASL initial response support */
		str_append(str, "L AUTHENTICATE PLAIN ");
		get_plain_auth(client, str);
		proxy_free_password(client);
	} else {
		/* master user login without SASL initial response */
		str_append(str, "L AUTHENTICATE PLAIN");
	}

	str_append(str, "\r\n");
	(void)o_stream_send(output, str_data(str), str_len(str));
	client->proxy_login_sent = TRUE;
	return 0;
}

static int proxy_input_line(struct imap_client *client,
			    struct ostream *output, const char *line)
{
	string_t *str;

	i_assert(!client->destroyed);

	if (!client->proxy_login_sent) {
		/* this is a banner */
		if (proxy_input_banner(client, output, line) < 0) {
			proxy_failed(client, TRUE);
			return -1;
		}
		return 0;
	} else if (*line == '+') {
		/* AUTHENTICATE started. finish it. */
		str = t_str_new(128);
		get_plain_auth(client, str);
		str_append(str, "\r\n");
		proxy_free_password(client);

		(void)o_stream_send(output, str_data(str), str_len(str));
		return 0;
	} else if (strncmp(line, "L OK ", 5) == 0) {
		/* Login successful. Send this line to client. */
		str = t_str_new(128);
		str_append(str, client->cmd_tag);
		str_append(str, line + 1);
		str_append(str, "\r\n");
		(void)o_stream_send(client->output,
				    str_data(str), str_len(str));

		str_truncate(str, 0);
		str_printfa(str, "proxy(%s): started proxying to %s:%u",
			    client->common.virtual_user,
			    login_proxy_get_host(client->proxy),
			    login_proxy_get_port(client->proxy));
		if (strcmp(client->common.virtual_user,
			   client->proxy_user) != 0) {
			/* remote username is different, log it */
			str_append_c(str, '/');
			str_append(str, client->proxy_user);
		}
		if (client->proxy_master_user != NULL) {
			str_printfa(str, " (master %s)",
				    client->proxy_master_user);
		}

		(void)client_skip_line(client);
		login_proxy_detach(client->proxy, client->common.input,
				   client->output);

		client->proxy = NULL;
		client->common.input = NULL;
		client->output = NULL;
		client->common.fd = -1;
		client_destroy_success(client, str_c(str));
		return -1;
	} else if (strncmp(line, "L ", 2) == 0) {
		/* If the backend server isn't Dovecot, the error message may
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
		client_send_tagline(client, line + 2);

		if (login_settings->verbose_auth) {
			str = t_str_new(128);
			str_printfa(str, "proxy(%s): Login failed to %s:%u",
				    client->common.virtual_user,
				    login_proxy_get_host(client->proxy),
				    login_proxy_get_port(client->proxy));
			if (strcmp(client->common.virtual_user,
				   client->proxy_user) != 0) {
				/* remote username is different, log it */
				str_append_c(str, '/');
				str_append(str, client->proxy_user);
			}
			if (client->proxy_master_user != NULL) {
				str_printfa(str, " (master %s)",
					    client->proxy_master_user);
			}
			str_append(str, ": ");
			if (strncasecmp(line + 2, "NO ", 3) == 0)
				str_append(str, line + 2 + 3);
			else
				str_append(str, line + 2);
			i_info("%s", str_c(str));
		}
		proxy_failed(client, FALSE);
		return -1;
	} else {
		/* probably some untagged reply */
		return 0;
	}
}

static void proxy_input(struct istream *input, struct ostream *output,
			struct imap_client *client)
{
	const char *line;

	if (input == NULL) {
		if (client->proxy == NULL) {
			/* we're just freeing the proxy */
			return;
		}

		if (client->destroyed) {
			/* we came here from client_destroy() */
			return;
		}

		/* failed for some reason, probably server disconnected */
		proxy_failed(client, TRUE);
		return;
	}

	i_assert(!client->destroyed);

	switch (i_stream_read(input)) {
	case -2:
		client_syslog_err(&client->common,
				  "proxy: Remote input buffer full");
		proxy_failed(client, TRUE);
		return;
	case -1:
		client_syslog_err(&client->common,
				  "proxy: Remote disconnected");
		proxy_failed(client, TRUE);
		return;
	}

	while ((line = i_stream_next_line(input)) != NULL) {
		if (proxy_input_line(client, output, line) < 0)
			break;
	}
}

int imap_proxy_new(struct imap_client *client, const char *host,
		   unsigned int port, const char *user, const char *master_user,
		   const char *password)
{
	i_assert(user != NULL);
	i_assert(!client->destroyed);

	if (password == NULL) {
		client_syslog_err(&client->common, "proxy: password not given");
		client_send_tagline(client, PROXY_FAILURE_MSG);
		return -1;
	}

	i_assert(client->refcount > 1);
	connection_queue_add(1);

	if (client->destroyed) {
		/* connection_queue_add() decided that we were the oldest
		   connection and killed us. */
		return -1;
	}
	if (login_proxy_is_ourself(&client->common, host, port, user)) {
		client_syslog_err(&client->common, "Proxying loops to itself");
		client_send_tagline(client, PROXY_FAILURE_MSG);
		return -1;
	}

	client->proxy = login_proxy_new(&client->common, host, port,
					proxy_input, client);
	if (client->proxy == NULL) {
		client_send_tagline(client, PROXY_FAILURE_MSG);
		return -1;
	}

	client->proxy_login_sent = FALSE;
	client->proxy_user = i_strdup(user);
	client->proxy_master_user = i_strdup(master_user);
	client->proxy_password = i_strdup(password);

	/* disable input until authentication is finished */
	if (client->io != NULL)
		io_remove(&client->io);
	return 0;
}
