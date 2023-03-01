/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-id.h"
#include "str.h"
#include "str-sanitize.h"

static void
cmd_id_log_params(const struct imap_arg *args, struct event *event,
		  string_t *reply)
{
	if (!imap_arg_get_list(args, &args))
		return;

	const char *key, *value;
	struct imap_id_log_entry log_entry = {
		.event = event,
		.reply = reply,
	};
	while (!IMAP_ARG_IS_EOL(&args[0]) &&
	       !IMAP_ARG_IS_EOL(&args[1])) {
		if (!imap_arg_get_string(args, &key)) {
			/* broken input */
			args += 2;
			continue;
		}
		args++;
		if (strlen(key) > IMAP_ID_KEY_MAX_LEN) {
			/* broken: ID spec requires fields to be max. 30
			   octets */
			args++;
			continue;
		}

		if (!imap_arg_get_nstring(args, &value))
			value = "";
		imap_id_add_log_entry(&log_entry, key, value);
		args++;
	}
}

bool cmd_id(struct client_command_context *cmd)
{
	const struct imap_settings *set = cmd->client->set;
	const struct imap_arg *args;

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (!cmd->client->id_logged) {
		cmd->client->id_logged = TRUE;

		struct event *event = event_create(cmd->client->event);
		event_set_name(event, "imap_id_received");

		string_t *log_reply = str_new(default_pool, 64);
		cmd_id_log_params(args, event, log_reply);
		if (str_len(log_reply) > 0)
			e_debug(event, "ID sent: %s",
				str_sanitize(str_c(log_reply),
					     IMAP_ID_PARAMS_LOG_MAX_LEN));
		event_unref(&event);
		str_free(&log_reply);
	}

	client_send_line(cmd->client, t_strdup_printf(
		"* ID %s", imap_id_reply_generate(set->imap_id_send)));
	client_send_tagline(cmd, "OK ID completed.");
	return TRUE;
}

