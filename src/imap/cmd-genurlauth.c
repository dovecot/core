/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "imap-commands.h"
#include "imap-quote.h"
#include "imap-urlauth.h"

bool cmd_genurlauth(struct client_command_context *cmd)
{
	const struct imap_arg *args;
	string_t *response;
	int ret;

	if (cmd->client->urlauth_ctx == NULL) {
		client_send_command_error(cmd, "URLAUTH disabled.");
		return TRUE;
	}

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	response = t_str_new(1024);
	str_append(response, "* GENURLAUTH");
	for (;;) {
		const char *url_rump, *mechanism, *url, *client_error;

		if (IMAP_ARG_IS_EOL(args))
			break;
		if (!imap_arg_get_astring(args++, &url_rump) ||
		    !imap_arg_get_atom(args++, &mechanism)) {
			client_send_command_error(cmd, "Invalid arguments.");
			return FALSE;
		}

		ret = imap_urlauth_generate(cmd->client->urlauth_ctx,
					    mechanism, url_rump, &url,
					    &client_error);
		if (ret <= 0) {
			if (ret < 0)
				client_send_internal_error(cmd);
			else
				client_send_command_error(cmd, client_error);
			return TRUE;
		}

		str_append_c(response, ' ');
		imap_append_astring(response, url);
	}

	client_send_line(cmd->client, str_c(response));
	client_send_tagline(cmd, "OK GENURLAUTH completed.");
	return TRUE;
}
