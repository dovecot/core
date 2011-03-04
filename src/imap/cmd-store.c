/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "seq-range-array.h"
#include "str.h"
#include "imap-commands.h"
#include "imap-search-args.h"
#include "imap-util.h"

#include <stdlib.h>

struct imap_store_context {
	struct client_command_context *cmd;
	uint64_t max_modseq;

	enum mail_flags flags;
	struct mail_keywords *keywords;

	enum modify_type modify_type;
	bool silent;
};

static bool
get_modify_type(struct imap_store_context *ctx, const char *type)
{
	if (*type == '+') {
		ctx->modify_type = MODIFY_ADD;
		type++;
	} else if (*type == '-') {
		ctx->modify_type = MODIFY_REMOVE;
		type++;
	} else {
		ctx->modify_type = MODIFY_REPLACE;
	}

	if (strncasecmp(type, "FLAGS", 5) != 0)
		return FALSE;

	ctx->silent = strcasecmp(type+5, ".SILENT") == 0;
	if (!ctx->silent && type[5] != '\0')
		return FALSE;
	return TRUE;
}

static bool
store_parse_modifiers(struct imap_store_context *ctx,
		      const struct imap_arg *args)
{
	const char *name, *value;

	for (; !IMAP_ARG_IS_EOL(args); args += 2) {
		if (!imap_arg_get_atom(&args[0], &name) ||
		    !imap_arg_get_atom(&args[1], &value)) {
			client_send_command_error(ctx->cmd,
				"Invalid STORE modifiers.");
			return FALSE;
		}

		if (strcasecmp(name, "UNCHANGEDSINCE") == 0) {
			if (str_to_uint64(value, &ctx->max_modseq) < 0) {
				client_send_command_error(ctx->cmd,
							  "Invalid modseq");
				return FALSE;
			}
			client_enable(ctx->cmd->client,
				      MAILBOX_FEATURE_CONDSTORE);
		} else {
			client_send_command_error(ctx->cmd,
						  "Unknown STORE modifier");
			return FALSE;
		}
	}
	return TRUE;
}

static bool
store_parse_args(struct imap_store_context *ctx, const struct imap_arg *args)
{
	struct client_command_context *cmd = ctx->cmd;
	const struct imap_arg *list_args;
	const char *type;
	const char *const *keywords_list = NULL;

	ctx->max_modseq = (uint64_t)-1;
	if (imap_arg_get_list(args, &list_args)) {
		if (!store_parse_modifiers(ctx, list_args))
			return FALSE;
		args++;
	}

	if (!imap_arg_get_astring(args, &type) ||
	    !get_modify_type(ctx, type)) {
		client_send_command_error(cmd, "Invalid arguments.");
		return FALSE;
	}
	args++;

	if (imap_arg_get_list(args, &list_args)) {
		if (!client_parse_mail_flags(cmd, list_args,
					     &ctx->flags, &keywords_list))
			return FALSE;
	} else {
		if (!client_parse_mail_flags(cmd, args,
					     &ctx->flags, &keywords_list))
			return FALSE;
	}

	if (keywords_list != NULL || ctx->modify_type == MODIFY_REPLACE) {
		if (mailbox_keywords_create(cmd->client->mailbox, keywords_list,
					    &ctx->keywords) < 0) {
			/* invalid keywords */
			client_send_storage_error(cmd,
				mailbox_get_storage(cmd->client->mailbox));
			return FALSE;
		}
	}
	return TRUE;
}

bool cmd_store(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	const struct imap_arg *args;
	struct mail_search_args *search_args;
	struct mail_search_context *search_ctx;
        struct mailbox_transaction_context *t;
	struct mail *mail;
	struct imap_store_context ctx;
	ARRAY_TYPE(seq_range) modified_set, uids;
	enum mailbox_transaction_flags flags = 0;
	enum imap_sync_flags imap_sync_flags = 0;
	const char *set, *reply, *tagged_reply;
	string_t *str;
	int ret;

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	if (!imap_arg_get_atom(args, &set)) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}
	ret = imap_search_get_seqset(cmd, set, cmd->uid, &search_args);
	if (ret <= 0)
		return ret < 0;

	memset(&ctx, 0, sizeof(ctx));
	ctx.cmd = cmd;
	if (!store_parse_args(&ctx, ++args))
		return TRUE;

	if (client->mailbox_examined) {
		if (ctx.max_modseq < (uint64_t)-1)
			reply = "NO CONDSTORE failed: Mailbox is read-only.";
		else
			reply = "OK Store ignored with read-only mailbox.";
		return cmd_sync(cmd, MAILBOX_SYNC_FLAG_FAST |
				(cmd->uid ? 0 : MAILBOX_SYNC_FLAG_NO_EXPUNGES),
				0, reply);
	}

	if (ctx.silent)
		flags |= MAILBOX_TRANSACTION_FLAG_HIDE;
	if (ctx.max_modseq < (uint64_t)-1) {
		/* update modseqs so we can check them early */
		flags |= MAILBOX_TRANSACTION_FLAG_REFRESH;
	}

	t = mailbox_transaction_begin(client->mailbox, flags);
	search_ctx = mailbox_search_init(t, search_args, NULL);
	mail_search_args_unref(&search_args);

	i_array_init(&modified_set, 64);
	if (ctx.max_modseq < (uint32_t)-1) {
		/* STORE UNCHANGEDSINCE is being used */
		mailbox_transaction_set_max_modseq(t, ctx.max_modseq,
						   &modified_set);
	}

	mail = mail_alloc(t, MAIL_FETCH_FLAGS, NULL);
	while (mailbox_search_next(search_ctx, mail)) {
		if (ctx.max_modseq < (uint64_t)-1) {
			/* check early so there's less work for transaction
			   commit if something has to be cancelled */
			if (mail_get_modseq(mail) > ctx.max_modseq) {
				seq_range_array_add(&modified_set, 0,
						    mail->seq);
				continue;
			}
		}
		if (ctx.modify_type == MODIFY_REPLACE || ctx.flags != 0)
			mail_update_flags(mail, ctx.modify_type, ctx.flags);
		if (ctx.modify_type == MODIFY_REPLACE || ctx.keywords != NULL) {
			mail_update_keywords(mail, ctx.modify_type,
					     ctx.keywords);
		}
	}
	mail_free(&mail);

	if (ctx.keywords != NULL)
		mailbox_keywords_unref(client->mailbox, &ctx.keywords);

	ret = mailbox_search_deinit(&search_ctx);
	if (ret < 0)
		mailbox_transaction_rollback(&t);
	 else
		ret = mailbox_transaction_commit(&t);
	if (ret < 0) {
		array_free(&modified_set);
		client_send_storage_error(cmd,
			mailbox_get_storage(client->mailbox));
		return TRUE;
	}

	if (array_count(&modified_set) == 0)
		tagged_reply = "OK Store completed.";
	else {
		if (cmd->uid) {
			i_array_init(&uids, array_count(&modified_set)*2);
			mailbox_get_uid_range(client->mailbox, &modified_set,
					      &uids);
			array_free(&modified_set);
			modified_set = uids;
		}
		str = str_new(cmd->pool, 256);
		str_append(str, "OK [MODIFIED ");
		imap_write_seq_range(str, &modified_set);
		str_append(str, "] Conditional store failed.");
		tagged_reply = str_c(str);
	}
	array_free(&modified_set);

	/* With UID STORE we have to return UID for the flags as well.
	   Unfortunately we don't have the ability to separate those
	   flag changes that were caused by UID STORE and those that
	   came externally, so we'll just send the UID for all flag
	   changes that we see. */
	if (cmd->uid && (!ctx.silent || (client->enabled_features &
					 MAILBOX_FEATURE_CONDSTORE) != 0))
		imap_sync_flags |= IMAP_SYNC_FLAG_SEND_UID;

	return cmd_sync(cmd, (cmd->uid ? 0 : MAILBOX_SYNC_FLAG_NO_EXPUNGES),
			imap_sync_flags, tagged_reply);
}
