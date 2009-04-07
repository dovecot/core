/* Copyright (c) 2004-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "base64.h"
#include "safe-memset.h"
#include "str.h"
#include "str-sanitize.h"
#include "client.h"
#include "pop3-proxy.h"

#define PROXY_FAILURE_MSG "-ERR [IN-USE] "AUTH_TEMP_FAILED_MSG

static void proxy_free_password(struct pop3_client *client)
{
	if (client->proxy_password == NULL)
		return;

	safe_memset(client->proxy_password, 0, strlen(client->proxy_password));
	i_free_and_null(client->proxy_password);
}

static void proxy_failed(struct pop3_client *client, bool send_line)
{
	if (send_line)
		client_send_line(client, PROXY_FAILURE_MSG);

	login_proxy_free(&client->proxy);
	proxy_free_password(client);
	i_free_and_null(client->proxy_user);
	i_free_and_null(client->proxy_master_user);

	/* call this last - it may destroy the client */
	client_auth_failed(client, TRUE);
}

static void get_plain_auth(struct pop3_client *client, string_t *dest)
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

static int proxy_input_line(struct pop3_client *client,
			    struct ostream *output, const char *line)
{
	string_t *str;

	i_assert(!client->destroyed);

	switch (client->proxy_state) {
	case 0:
		/* this is a banner */
		if (strncmp(line, "+OK", 3) != 0) {
			client_syslog_err(&client->common, t_strdup_printf(
				"proxy: Remote returned invalid banner: %s",
				str_sanitize(line, 160)));
			proxy_failed(client, TRUE);
			return -1;
		}

		str = t_str_new(128);
		if (client->proxy_master_user == NULL) {
			/* send USER command */
			str_append(str, "USER ");
			str_append(str, client->proxy_user);
			str_append(str, "\r\n");
		} else {
			/* master user login - use AUTH PLAIN. */
			str_append(str, "AUTH PLAIN\r\n");
		}
		(void)o_stream_send(output, str_data(str), str_len(str));

		client->proxy_state++;
		return 0;
	case 1:
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
		(void)o_stream_send(output, str_data(str), str_len(str));
		proxy_free_password(client);
		client->proxy_state++;
		return 0;
	case 2:
		if (strncmp(line, "+OK", 3) != 0)
			break;

		/* Login successful. Send this line to client. */
		line = t_strconcat(line, "\r\n", NULL);
		(void)o_stream_send_str(client->output, line);

		str = t_str_new(128);
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

		login_proxy_detach(client->proxy, client->common.input,
				   client->output);

		client->proxy = NULL;
		client->common.input = NULL;
		client->output = NULL;
		client->common.fd = -1;
		client_destroy_success(client, str_c(str));
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
	if (strncmp(line, "-ERR ", 5) != 0)
		client_send_line(client, "-ERR "AUTH_FAILED_MSG);
	else
		client_send_line(client, line);

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
		if (strncmp(line, "-ERR ", 5) == 0)
			str_append(str, line + 5);
		else
			str_append(str, line);
		i_info("%s", str_c(str));
	}
	proxy_failed(client, FALSE);
	return -1;
}

static void proxy_input(struct istream *input, struct ostream *output,
			struct pop3_client *client)
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
		if (proxy_input_line(client, output, line) != 0)
			break;
	}
}

int pop3_proxy_new(struct pop3_client *client, const char *host,
		   unsigned int port, const char *user, const char *master_user,
		   const char *password)
{
	i_assert(user != NULL);
	i_assert(!client->destroyed);

	if (password == NULL) {
		client_syslog_err(&client->common, "proxy: password not given");
		client_send_line(client, PROXY_FAILURE_MSG);
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
		client_send_line(client, PROXY_FAILURE_MSG);
		return -1;
	}

	client->proxy = login_proxy_new(&client->common, host, port,
					proxy_input, client);
	if (client->proxy == NULL) {
		client_send_line(client, PROXY_FAILURE_MSG);
		return -1;
	}

	client->proxy_state = 0;
	client->proxy_user = i_strdup(user);
	client->proxy_master_user = i_strdup(master_user);
	client->proxy_password = i_strdup(password);

	/* disable input until authentication is finished */
	if (client->io != NULL)
		io_remove(&client->io);
	return 0;
}
