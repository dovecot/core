/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-search-args.h"
#include "imap-search.h"

bool cmd_search(struct client_command_context *cmd)
{
	struct imap_search_context *ctx;
	struct mail_search_args *sargs;
	const struct imap_arg *args;
	const char *charset;
	int ret;

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	ctx = p_new(cmd->pool, struct imap_search_context, 1);
	ctx->cmd = cmd;

	if ((ret = cmd_search_parse_return_if_found(ctx, &args)) <= 0) {
		/* error / waiting for unambiguity */
		return ret < 0;
	}

	if (args->type == IMAP_ARG_ATOM &&
	    strcasecmp(IMAP_ARG_STR_NONULL(args), "CHARSET") == 0) {
		/* CHARSET specified */
		args++;
		if (args->type != IMAP_ARG_ATOM &&
		    args->type != IMAP_ARG_STRING) {
			client_send_command_error(cmd,
						  "Invalid charset argument.");
			return TRUE;
		}

		charset = IMAP_ARG_STR(args);
		args++;
	} else {
		charset = "UTF-8";
	}

	ret = imap_search_args_build(cmd, args, charset, &sargs);
	if (ret <= 0)
		return ret < 0;

	return imap_search_start(ctx, sargs, NULL);
}
