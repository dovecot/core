/* Copyright (C) 2002-2004 Timo Sirainen */

#include "common.h"
#include "ostream.h"
#include "commands.h"
#include "imap-fetch.h"
#include "imap-search.h"
#include "mail-search.h"

const char *all_macro[] = {
	"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", NULL
};
const char *fast_macro[] = {
	"FLAGS", "INTERNALDATE", "RFC822.SIZE", NULL
};
const char *full_macro[] = {
	"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY", NULL
};

static int
fetch_parse_args(struct client *client, struct imap_fetch_context *ctx,
		 struct imap_arg *arg)
{
	const char *str, *const *macro;

	if (arg->type == IMAP_ARG_ATOM) {
		str = str_ucase(IMAP_ARG_STR(arg));
		arg++;

		/* handle macros first */
		if (strcmp(str, "ALL") == 0)
			macro = all_macro;
		else if (strcmp(str, "FAST") == 0)
			macro = fast_macro;
		else if (strcmp(str, "FULL") == 0)
			macro = full_macro;
		else {
			macro = NULL;
			if (!imap_fetch_init_handler(ctx, str, &arg))
				return FALSE;
		}
		if (macro != NULL) {
			while (*macro != NULL) {
				if (!imap_fetch_init_handler(ctx, *macro, &arg))
					return FALSE;
				macro++;
			}
		}
	} else {
		arg = IMAP_ARG_LIST(arg)->args;
		while (arg->type == IMAP_ARG_ATOM) {
			str = str_ucase(IMAP_ARG_STR(arg));
			arg++;
			if (!imap_fetch_init_handler(ctx, str, &arg))
				return FALSE;
		}
		if (arg->type != IMAP_ARG_EOL) {
			client_send_command_error(client,
				"FETCH list contains non-atoms.");
			return FALSE;
		}
	}

	if (client->cmd_uid) {
		if (!imap_fetch_init_handler(ctx, "UID", &arg))
			return FALSE;
	}

	return TRUE;
}

static int cmd_fetch_finish(struct client *client, int failed)
{
	static const char *ok_message = "OK Fetch completed.";

	if (failed) {
		struct mail_storage *storage;
		const char *error;
		int syntax;

                storage = mailbox_get_storage(client->mailbox);
		error = mail_storage_get_last_error(storage, &syntax);
		if (!syntax) {
			/* We never want to reply NO to FETCH requests,
			   BYE is preferrable (see imap-ml for reasons). */
			if (error == NULL) {
				error = "Out of sync: "
					"Trying to fetch expunged message";
			}
			client_disconnect_with_error(client, error);
		} else {
			/* user error, we'll reply with BAD */
			client_send_storage_error(client, storage);
		}
		return TRUE;
	}

	if ((client_workarounds & WORKAROUND_OE6_FETCH_NO_NEWMAIL) != 0) {
		client_send_tagline(client, ok_message);
		return TRUE;
	} else {
		return cmd_sync(client, MAILBOX_SYNC_FLAG_FAST |
				(client->cmd_uid ? 0 :
				 MAILBOX_SYNC_FLAG_NO_EXPUNGES), ok_message);
	}
}

static int cmd_fetch_continue(struct client *client)
{
        struct imap_fetch_context *ctx = client->cmd_context;
	int ret;

	if (client->output->closed)
		ret = -1;
	else {
		if ((ret = imap_fetch(ctx)) == 0) {
			/* unfinished */
			return FALSE;
		}
	}
	if (ret < 0)
		ctx->failed = TRUE;

	if (imap_fetch_deinit(ctx) < 0)
		ret = -1;
	return cmd_fetch_finish(client, ret < 0);
}

int cmd_fetch(struct client *client)
{
        struct imap_fetch_context *ctx;
	struct imap_arg *args;
	struct mail_search_arg *search_arg;
	const char *messageset;
	int ret;

	if (!client_read_args(client, 0, 0, &args))
		return FALSE;

	if (!client_verify_open_mailbox(client))
		return TRUE;

	messageset = imap_arg_string(&args[0]);
	if (messageset == NULL ||
	    (args[1].type != IMAP_ARG_LIST && args[1].type != IMAP_ARG_ATOM)) {
		client_send_command_error(client, "Invalid arguments.");
		return TRUE;
	}

	search_arg = imap_search_get_arg(client, messageset, client->cmd_uid);
	if (search_arg == NULL)
		return TRUE;

	ctx = imap_fetch_init(client);
	if (ctx == NULL)
		return TRUE;

	if (!fetch_parse_args(client, ctx, &args[1])) {
		imap_fetch_deinit(ctx);
		return TRUE;
	}

	imap_fetch_begin(ctx, search_arg);
	if ((ret = imap_fetch(ctx)) == 0) {
		/* unfinished */
		client->command_pending = TRUE;
		client->cmd_func = cmd_fetch_continue;
		client->cmd_context = ctx;
		return FALSE;
	}
	if (ret < 0)
		ctx->failed = TRUE;
	if (imap_fetch_deinit(ctx) < 0)
		ret = -1;
	return cmd_fetch_finish(client, ret < 0);
}
