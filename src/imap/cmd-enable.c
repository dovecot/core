/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"

bool cmd_enable(struct client_command_context *cmd)
{
	const struct imap_arg *args;
	const char *str;
	string_t *reply;

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	reply = t_str_new(64);
	str_append(reply, "* ENABLED");
	for (; !IMAP_ARG_IS_EOL(args); args++) {
		if (!imap_arg_get_atom(args, &str)) {
			client_send_command_error(cmd, "Invalid arguments.");
			return TRUE;
		}
		str = t_str_ucase(str);
		if (strcmp(str, "CONDSTORE") == 0) {
			if (client_enable(cmd->client,
					  imap_feature_condstore) == 0)
				str_append(reply, " CONDSTORE");
		} else if (strcmp(str, "QRESYNC") == 0) {
			if (client_enable(cmd->client, imap_feature_qresync |
					  imap_feature_condstore) == 0)
				str_append(reply, " QRESYNC");
		}
	}
	if (str_len(reply) > 9)
		client_send_line(cmd->client, str_c(reply));
	client_send_tagline(cmd, "OK Enabled.");
	return TRUE;
}

