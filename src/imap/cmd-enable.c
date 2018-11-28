/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "imap-feature.h"

bool cmd_enable(struct client_command_context *cmd)
{
	const struct imap_arg *args;
	const char *str;
	string_t *reply;
	unsigned int feature_idx;

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	reply = t_str_new(64);
	str_append(reply, "* ENABLED");
	for (; !IMAP_ARG_IS_EOL(args); args++) {
		if (!imap_arg_get_atom(args, &str)) {
			client_send_command_error(cmd, "Invalid arguments.");
			return TRUE;
		}
		if (imap_feature_lookup(str, &feature_idx)) {
			(void)client_enable(cmd->client, feature_idx);
			str_append_c(reply, ' ');
			str_append(reply, t_str_ucase(str));
		}
	}
	if (str_len(reply) > 9)
		client_send_line(cmd->client, str_c(reply));
	client_send_tagline(cmd, "OK Enabled.");
	return TRUE;
}

