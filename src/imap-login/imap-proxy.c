/* Copyright (c) 2004-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "str-sanitize.h"
#include "safe-memset.h"
#include "client.h"
#include "imap-quote.h"
#include "imap-proxy.h"

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

static int proxy_input_line(struct imap_client *client,
			    struct ostream *output, const char *line)
{
	string_t *str;

	i_assert(!client->destroyed);

	if (!client->proxy_login_sent) {
		/* this is a banner */
		if (strncmp(line, "* OK ", 5) != 0) {
			client_syslog(&client->common, t_strdup_printf(
				"proxy: Remote returned invalid banner: %s",
				str_sanitize(line, 160)));
			client_destroy_internal_failure(client);
			return -1;
		}

		str = t_str_new(128);
		if (imap_banner_has_capability(line + 5, "ID"))
			proxy_write_id(client, str);

		/* send LOGIN command */
		str_append(str, "P LOGIN ");
		imap_quote_append_string(str, client->proxy_user, FALSE);
		str_append_c(str, ' ');
		imap_quote_append_string(str, client->proxy_password, FALSE);
		str_append(str, "\r\n");
		(void)o_stream_send(output, str_data(str), str_len(str));

		safe_memset(client->proxy_password, 0,
			    strlen(client->proxy_password));
		i_free(client->proxy_password);
		client->proxy_password = NULL;
		client->proxy_login_sent = TRUE;
		return 0;
	} else if (strncmp(line, "P OK ", 5) == 0) {
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

		(void)client_skip_line(client);
		login_proxy_detach(client->proxy, client->common.input,
				   client->output);

		client->proxy = NULL;
		client->common.input = NULL;
		client->output = NULL;
		client->common.fd = -1;
		client_destroy_success(client, str_c(str));
		return -1;
	} else if (strncmp(line, "P ", 2) == 0) {
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

		/* allow client input again */
		i_assert(client->io == NULL);
		client->io = io_add(client->common.fd, IO_READ,
				    client_input, client);

		login_proxy_free(client->proxy);
		client->proxy = NULL;

		i_free(client->proxy_user);
		client->proxy_user = NULL;
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
		if (client->io != NULL) {
			/* remote authentication failed, we're just
			   freeing the proxy */
			return;
		}

		if (client->destroyed) {
			/* we came here from client_destroy() */
			return;
		}

		/* failed for some reason, probably server disconnected */
		client_send_line(client, "* BYE Temporary login failure.");
		client_destroy_success(client, NULL);
		return;
	}

	i_assert(!client->destroyed);

	switch (i_stream_read(input)) {
	case -2:
		/* buffer full */
		client_syslog(&client->common,
			      "proxy: Remote input buffer full");
		client_destroy_internal_failure(client);
		return;
	case -1:
		/* disconnected */
		client_destroy_success(client, "Proxy: Remote disconnected");
		return;
	}

	while ((line = i_stream_next_line(input)) != NULL) {
		if (proxy_input_line(client, output, line) < 0)
			break;
	}
}

int imap_proxy_new(struct imap_client *client, const char *host,
		   unsigned int port, const char *user, const char *password)
{
	i_assert(user != NULL);
	i_assert(!client->destroyed);

	if (password == NULL) {
		client_syslog(&client->common, "proxy: password not given");
		return -1;
	}

	i_assert(client->refcount > 1);
	connection_queue_add(1);

	if (client->destroyed) {
		/* connection_queue_add() decided that we were the oldest
		   connection and killed us. */
		return -1;
	}

	client->proxy = login_proxy_new(&client->common, host, port,
					proxy_input, client);
	if (client->proxy == NULL)
		return -1;

	client->proxy_login_sent = FALSE;
	client->proxy_user = i_strdup(user);
	client->proxy_password = i_strdup(password);

	/* disable input until authentication is finished */
	if (client->io != NULL)
		io_remove(&client->io);

	return 0;
}
