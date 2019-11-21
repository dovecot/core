/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-resp-code.h"
#include "imap-commands.h"
#include "imap-urlauth.h"

static bool cmd_resetkey_all(struct client_command_context *cmd)
{
	if (imap_urlauth_reset_all_keys(cmd->client->urlauth_ctx) < 0) {
		client_send_internal_error(cmd);
		return TRUE;
	}

	client_send_tagline(cmd, "OK All keys removed.");
	return TRUE;
}

static bool
cmd_resetkey_mailbox(struct client_command_context *cmd,
		     const char *mailbox, const struct imap_arg *mech_args)
{
	struct mail_namespace *ns;
	enum mailbox_flags flags = MAILBOX_FLAG_READONLY;
	struct mailbox *box;

	/* check mechanism arguments (we support only INTERNAL mechanism) */
	while (!IMAP_ARG_IS_EOL(mech_args)) {
		const char *mechanism;

		if (imap_arg_get_astring(mech_args, &mechanism)) {
			if (strcasecmp(mechanism, "INTERNAL") != 0) {
				client_send_tagline(cmd,
					"NO Unsupported URLAUTH mechanism.");
				return TRUE;
			}
		} else {
			client_send_command_error(cmd, "Invalid arguments.");
			return TRUE;
		}

		mech_args++;
	}

	/* find mailbox namespace */
	ns = client_find_namespace(cmd, &mailbox);
	if (ns == NULL)
		return TRUE;

	/* open mailbox */
	box = mailbox_alloc(ns->list, mailbox, flags);
	event_add_str(cmd->event, "mailbox", mailbox_get_vname(box));
	mailbox_set_reason(box, "RESETKEY");
	if (mailbox_open(box) < 0) {
		client_send_box_error(cmd, box);
		mailbox_free(&box);
		return TRUE;
	}

	/* check urlauth environment and reset requested key */
	if (imap_urlauth_reset_mailbox_key(cmd->client->urlauth_ctx, box) < 0) {
		client_send_internal_error(cmd);
		mailbox_free(&box);
		return TRUE;
	}

	/* confirm success */
	/* FIXME: RFC Says: `Any current IMAP session logged in as the user
	   that has the mailbox selected will receive an untagged OK response
	   with the URLMECH status response code'. We currently don't do that
	   at all. We could probably do it by communicating via mailbox list
	   index. */
	client_send_tagline(cmd, "OK [URLMECH INTERNAL] Key removed.");
	mailbox_free(&box);
	return TRUE;
}

bool cmd_resetkey(struct client_command_context *cmd)
{
	const struct imap_arg *args;
	const char *mailbox;

	if (cmd->client->urlauth_ctx == NULL) {
		client_send_command_error(cmd, "URLAUTH disabled.");
		return TRUE;
	}

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (IMAP_ARG_IS_EOL(&args[0]))
		return cmd_resetkey_all(cmd);
	else if (imap_arg_get_astring(&args[0], &mailbox))
		return cmd_resetkey_mailbox(cmd, mailbox, &args[1]);

	client_send_command_error(cmd, "Invalid arguments.");
	return TRUE;
}
