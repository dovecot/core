/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "base64.h"
#include "str.h"
#include "imap-commands.h"
#include "imap-state.h"

bool cmd_x_state(struct client_command_context *cmd)
{
	/* FIXME: state importing can cause unnecessarily large memory usage
	   by specifying an old modseq, because the EXPUNGE/FETCH replies
	   aren't currently sent asynchronously. so this command is disabled
	   for now. */
#if 0
	const struct imap_arg *args;
	const char *str, *error;
	buffer_t *state, *state_encoded;
	int ret;

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	state = buffer_create_dynamic(cmd->pool, 256);
	if (imap_arg_get_astring(&args[0], &str)) {
		if (cmd->client->mailbox != NULL) {
			client_send_tagline(cmd,
				"BAD Can't be used in SELECTED state");
			return TRUE;
		}
		if (base64_decode(str, strlen(str), NULL, state) < 0)
			ret = 0;
		else {
			ret = imap_state_import_external(cmd->client,
				state->data, state->used, &error);
		}
		if (ret < 0) {
			client_send_tagline(cmd, t_strdup_printf(
				"NO Failed to restore state: %s", error));
		} else if (ret == 0) {
			client_send_tagline(cmd, t_strdup_printf(
				"BAD Broken state: %s", error));
		} else {
			client_send_tagline(cmd, "OK State imported.");
		}
		return TRUE;
	} else if (args[0].type == IMAP_ARG_EOL) {
		if (!imap_state_export_external(cmd->client, state, &error)) {
			client_send_tagline(cmd, t_strdup_printf(
				"NO Can't save state: %s", error));
			return TRUE;
		}
		state_encoded = buffer_create_dynamic(cmd->pool,
				MAX_BASE64_ENCODED_SIZE(state->used)+10);
		str_append(state_encoded, "* STATE ");
		base64_encode(state->data, state->used, state_encoded);
		client_send_line(cmd->client, str_c(state_encoded));
		client_send_tagline(cmd, "OK State exported.");
		return TRUE;
	} else {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}
#else
	client_send_command_error(cmd, "Command is disabled for now.");
	return TRUE;
#endif
}
