/* Copyright (C) 2004 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "safe-memset.h"
#include "client.h"
#include "imap-quote.h"
#include "imap-proxy.h"

static int proxy_input_line(struct imap_client *client,
			    struct ostream *output, const char *line)
{
	string_t *str;

	if (client->proxy_user != NULL) {
		/* this is a banner */
		if (strncmp(line, "* OK ", 5) != 0) {
			i_error("imap-proxy(%s): "
				"Remote returned invalid banner: %s",
				client->common.virtual_user, line);
			client_destroy_internal_failure(client);
			return -1;
		}

		/* send LOGIN command */
		str = t_str_new(128);
		str_append(str, "P LOGIN ");
		imap_quote_append_string(str, client->proxy_user, FALSE);
		str_append_c(str, ' ');
		imap_quote_append_string(str, client->proxy_password, FALSE);
		str_append(str, "\r\n");
		(void)o_stream_send(output, str_data(str), str_len(str));

		safe_memset(client->proxy_password, 0,
			    strlen(client->proxy_password));
		i_free(client->proxy_user);
		i_free(client->proxy_password);
		client->proxy_user = NULL;
		client->proxy_password = NULL;
		return 0;
	} else if (strncmp(line, "P OK ", 5) == 0) {
		/* Login successful. Send this line to client. */
		(void)o_stream_send_str(client->output, client->cmd_tag);
		(void)o_stream_send_str(client->output, line + 2);
		(void)o_stream_send(client->output, "\r\n", 2);

		login_proxy_detach(client->proxy, client->input,
				   client->output);

		client->proxy = NULL;
		client->input = NULL;
		client->output = NULL;
		client->common.fd = -1;
		client_destroy(client, t_strdup_printf("proxy(%s): started",
						client->common.virtual_user));
		return -1;
	} else if (strncmp(line, "P ", 2) == 0) {
		/* Login failed. Send our own failure reply so client can't
		   figure out if user exists or not just by looking at the
		   reply string. */
		client_send_tagline(client, "NO "AUTH_FAILED_MSG);

		/* allow client input again */
		i_assert(client->io == NULL);
		client->io = io_add(client->common.fd, IO_READ,
				    client_input, client);

		login_proxy_free(client->proxy);
		client->proxy = NULL;
		return -1;
	} else {
		/* probably some untagged reply */
		return 0;
	}
}

static void proxy_input(struct istream *input, struct ostream *output,
			void *context)
{
	struct imap_client *client = context;
	const char *line;

	if (input == NULL) {
		if (client->io != NULL) {
			/* remote authentication failed, we're just
			   freeing the proxy */
			return;
		}

		/* failed for some reason */
		client_destroy_internal_failure(client);
		return;
	}

	switch (i_stream_read(input)) {
	case -2:
		/* buffer full */
		i_error("imap-proxy(%s): Remote input buffer full",
			client->common.virtual_user);
		client_destroy_internal_failure(client);
		return;
	case -1:
		/* disconnected */
		client_destroy(client, "Proxy: Remote disconnected");
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

	if (password == NULL) {
		i_error("proxy(%s): password not given",
			client->common.virtual_user);
		return -1;
	}

	client->proxy = login_proxy_new(&client->common, host, port,
					proxy_input, client);
	if (client->proxy == NULL)
		return -1;

	client->proxy_user = i_strdup(user);
	client->proxy_password = i_strdup(password);

	/* disable input until authentication is finished */
	if (client->io != NULL) {
		io_remove(client->io);
		client->io = NULL;
	}

	return 0;
}
