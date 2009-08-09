/* Copyright (c) 2004-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "base64.h"
#include "str.h"
#include "str-sanitize.h"
#include "safe-memset.h"
#include "client.h"
#include "client-authenticate.h"
#include "imap-resp-code.h"
#include "imap-quote.h"
#include "imap-proxy.h"

#include <stdlib.h>

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
	if (send_tagline) {
		client_send_line(&client->common,
				 CLIENT_CMD_REPLY_AUTH_FAIL_TEMP,
				 AUTH_TEMP_FAILED_MSG);
	}

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

static void
client_send_capability_if_needed(struct imap_client *client, string_t *str,
				 const char *capability)
{
	if (!client->client_ignores_capability_resp_code || capability == NULL)
		return;

	/* reset this so that we don't re-send the CAPABILITY in case server
	   sends it multiple times */
	client->client_ignores_capability_resp_code = FALSE;

	/* client has used CAPABILITY command, so it didn't understand the
	   capabilities in the banner. send the backend's untagged CAPABILITY
	   reply and hope that the client understands it */
	str_printfa(str, "* CAPABILITY %s\r\n", capability);
}

static void proxy_write_login(struct imap_client *client, string_t *str)
{
	if (client->client_ignores_capability_resp_code)
		str_append(str, "C CAPABILITY\r\n");

	if (client->proxy_master_user == NULL) {
		/* logging in normally - use LOGIN command */
		str_append(str, "L LOGIN ");
		imap_quote_append_string(str, client->proxy_user, FALSE);
		str_append_c(str, ' ');
		imap_quote_append_string(str, client->proxy_password, FALSE);

		proxy_free_password(client);
	} else if (client->proxy_sasl_ir) {
		/* master user login with SASL initial response support */
		str_append(str, "L AUTHENTICATE PLAIN ");
		get_plain_auth(client, str);
		proxy_free_password(client);
	} else {
		/* master user login without SASL initial response */
		str_append(str, "L AUTHENTICATE PLAIN");
	}
	str_append(str, "\r\n");
}

static int proxy_input_banner(struct imap_client *client,
			      struct ostream *output, const char *line)
{
	enum login_proxy_ssl_flags ssl_flags;
	const char *const *capabilities = NULL;
	string_t *str;

	if (strncmp(line, "* OK ", 5) != 0) {
		client_syslog_err(&client->common, t_strdup_printf(
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
	}

	ssl_flags = login_proxy_get_ssl_flags(client->proxy);
	if ((ssl_flags & PROXY_SSL_FLAG_STARTTLS) != 0) {
		if (capabilities != NULL &&
		    !str_array_icase_find(capabilities, "STARTTLS")) {
			client_syslog_err(&client->common,
				"proxy: Remote doesn't support STARTTLS");
			return -1;
		}
		str_append(str, "S STARTTLS\r\n");
	} else {
		proxy_write_login(client, str);
	}

	(void)o_stream_send(output, str_data(str), str_len(str));
	return 0;
}

static int proxy_input_line(struct imap_client *client, const char *line)
{
	struct ostream *output;
	const char *capability;
	string_t *str;

	i_assert(!client->destroyed);

	output = login_proxy_get_ostream(client->proxy);
	if (!client->proxy_seen_banner) {
		/* this is a banner */
		client->proxy_seen_banner = TRUE;
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
	} else if (strncmp(line, "S ", 2) == 0) {
		if (strncmp(line, "S OK ", 5) != 0) {
			/* STARTTLS failed */
			client_syslog_err(&client->common, t_strdup_printf(
				"proxy: Remote STARTTLS failed: %s",
				str_sanitize(line + 5, 160)));
			proxy_failed(client, TRUE);
			return -1;
		}
		/* STARTTLS successful, begin TLS negotiation. */
		if (login_proxy_starttls(client->proxy) < 0) {
			proxy_failed(client, TRUE);
			return -1;
		}
		/* i/ostreams changed. */
		output = login_proxy_get_ostream(client->proxy);
		str = t_str_new(128);
		proxy_write_login(client, str);
		(void)o_stream_send(output, str_data(str), str_len(str));
		return 1;
	} else if (strncmp(line, "L OK ", 5) == 0) {
		/* Login successful. Send this line to client. */
		capability = client->proxy_backend_capability;
		if (strncmp(line + 5, "[CAPABILITY ", 12) == 0)
			capability = t_strcut(line + 5 + 12, ']');

		str = t_str_new(128);
		client_send_capability_if_needed(client, str, capability);
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
		client->common.proxying = TRUE;
		client_destroy_success(client, str_c(str));
		return 1;
	} else if (strncmp(line, "L ", 2) == 0) {
		line += 2;
		if (client->common.set->verbose_auth) {
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
			if (strncasecmp(line, "NO ", 3) == 0)
				str_append(str, line + 3);
			else
				str_append(str, line);
			i_info("%s", str_c(str));
		}
#define STR_NO_IMAP_RESP_CODE_AUTHFAILED "NO ["IMAP_RESP_CODE_AUTHFAILED"]"
		if (strncmp(line, STR_NO_IMAP_RESP_CODE_AUTHFAILED,
			    strlen(STR_NO_IMAP_RESP_CODE_AUTHFAILED)) == 0) {
			/* the remote sent a generic "authentication failed"
			   error. replace it with our one, so that in case
			   the remote is sending a different error message
			   an attacker can't find out what users exist in
			   the system. */
			client_send_line(&client->common,
					 CLIENT_CMD_REPLY_AUTH_FAILED,
					 AUTH_FAILED_MSG);
		} else if (strncmp(line, "NO [", 4) == 0) {
			/* remote sent some other resp-code. forward it. */
			client_send_raw(client, t_strconcat(
				client->cmd_tag, " ", line, "\r\n", NULL));
		} else {
			/* there was no [resp-code], so remote isn't Dovecot
			   v1.2+. we could either forward the line as-is and
			   leak information about what users exist in this
			   system, or we could hide other errors than password
			   failures. since other errors are pretty rare,
			   it's safer to just hide them. they're still
			   available in logs though. */
			client_send_line(&client->common,
					 CLIENT_CMD_REPLY_AUTH_FAILED,
					 AUTH_FAILED_MSG);
		}

		proxy_failed(client, FALSE);
		return -1;
	} else if (strncasecmp(line, "* CAPABILITY ", 13) == 0) {
		i_free(client->proxy_backend_capability);
		client->proxy_backend_capability = i_strdup(line + 13);
		return 0;
	} else if (strncasecmp(line, "I ", 2) == 0 ||
		   strncasecmp(line, "* ID ", 5) == 0) {
		/* Reply to ID command we sent, ignore it */
		return 0;
	} else if (strncmp(line, "* ", 2) == 0) {
		/* untagged reply. just foward it. */
		client_send_raw(client, t_strconcat(line, "\r\n", NULL));
		return 0;
	} else {
		/* tagged reply, shouldn't happen. */
		return 0;
	}
}

static void proxy_input(struct imap_client *client)
{
	struct istream *input;
	const char *line;

	if (client->proxy == NULL) {
		/* we're just freeing the proxy */
		return;
	}

	input = login_proxy_get_istream(client->proxy);
	if (input == NULL) {
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
		if (proxy_input_line(client, line) != 0)
			break;
	}
}

int imap_proxy_new(struct imap_client *client, const char *host,
		   unsigned int port, const char *user, const char *master_user,
		   const char *password, enum login_proxy_ssl_flags ssl_flags)
{
	i_assert(user != NULL);
	i_assert(!client->destroyed);

	if (password == NULL) {
		client_syslog_err(&client->common, "proxy: password not given");
		client_send_line(&client->common,
				 CLIENT_CMD_REPLY_AUTH_FAIL_TEMP,
				 AUTH_TEMP_FAILED_MSG);
		return -1;
	}

	i_assert(client->refcount > 1);

	if (client->destroyed) {
		/* connection_queue_add() decided that we were the oldest
		   connection and killed us. */
		return -1;
	}
	if (login_proxy_is_ourself(&client->common, host, port, user)) {
		client_syslog_err(&client->common, "Proxying loops to itself");
		client_send_line(&client->common,
				 CLIENT_CMD_REPLY_AUTH_FAIL_TEMP,
				 AUTH_TEMP_FAILED_MSG);
		return -1;
	}

	client->proxy = login_proxy_new(&client->common, host, port, ssl_flags,
					proxy_input, client);
	if (client->proxy == NULL) {
		client_send_line(&client->common,
				 CLIENT_CMD_REPLY_AUTH_FAIL_TEMP,
				 AUTH_TEMP_FAILED_MSG);
		return -1;
	}

	client->proxy_sasl_ir = FALSE;
	client->proxy_seen_banner = FALSE;
	client->proxy_user = i_strdup(user);
	client->proxy_master_user = i_strdup(master_user);
	client->proxy_password = i_strdup(password);

	/* disable input until authentication is finished */
	if (client->io != NULL)
		io_remove(&client->io);
	return 0;
}
