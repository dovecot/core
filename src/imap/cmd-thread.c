/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "ostream.h"
#include "imap-commands.h"
#include "imap-search-args.h"
#include "mail-thread.h"

static int imap_thread_write(struct mail_thread_iterate_context *iter,
			     string_t *str, bool root)
{
	const struct mail_thread_child_node *node;
	struct mail_thread_iterate_context *child_iter;
	unsigned int count;
	int ret = 0;

	count = mail_thread_iterate_count(iter);
	if (count == 0)
		return 0;

	if (count == 1 && !root) {
		/* only one child - special case to avoid extra paranthesis */
		node = mail_thread_iterate_next(iter, &child_iter);
		str_printfa(str, "%u", node->uid);
		if (child_iter != NULL) {
			str_append_c(str, ' ');
			T_BEGIN {
				ret = imap_thread_write(child_iter, str, FALSE);
			} T_END;
			if (mail_thread_iterate_deinit(&child_iter) < 0)
				return -1;
		}
		return ret;
	}

	while ((node = mail_thread_iterate_next(iter, &child_iter)) != NULL) {
		if (child_iter == NULL) {
			/* no children */
			str_printfa(str, "(%u)", node->uid);
		} else {
			/* node with children */
			str_append_c(str, '(');
			if (node->uid != 0)
				str_printfa(str, "%u ", node->uid);
			T_BEGIN {
				ret = imap_thread_write(child_iter, str, FALSE);
			} T_END;
			if (mail_thread_iterate_deinit(&child_iter) < 0 ||
			    ret < 0)
				return -1;
			str_append_c(str, ')');
		}
	}
	return 0;
}

static int
imap_thread_write_reply(struct mail_thread_context *ctx, string_t *str,
			enum mail_thread_type thread_type, bool write_seqs)
{
	struct mail_thread_iterate_context *iter;
	int ret;

	iter = mail_thread_iterate_init(ctx, thread_type, write_seqs);
	str_append(str, "* THREAD ");
	T_BEGIN {
		ret = imap_thread_write(iter, str, TRUE);
	} T_END;
	if (mail_thread_iterate_deinit(&iter) < 0)
		ret = -1;

	str_append(str, "\r\n");
	return ret;
}

static int imap_thread(struct client_command_context *cmd,
		       struct mail_search_args *search_args,
		       enum mail_thread_type thread_type)
{
	struct mail_thread_context *ctx;
	string_t *str;
	int ret;

	i_assert(thread_type == MAIL_THREAD_REFERENCES ||
		 thread_type == MAIL_THREAD_REFS);

	str = str_new(default_pool, 1024);
	ret = mail_thread_init(cmd->client->mailbox,
			       search_args, &ctx);
	if (ret == 0) {
		ret = imap_thread_write_reply(ctx, str, thread_type,
					      !cmd->uid);
		mail_thread_deinit(&ctx);
	}

	if (ret == 0) {
		(void)o_stream_send(cmd->client->output,
				    str_data(str), str_len(str));
	}
	str_free(&str);
	return ret;
}

bool cmd_thread(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	enum mail_thread_type thread_type;
	struct mail_search_args *sargs;
	const struct imap_arg *args;
	const char *charset, *str;
	int ret;

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	if (!imap_arg_get_astring(&args[0], &str) ||
	    !imap_arg_get_astring(&args[1], &charset)) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}
	args += 2;

	if (!mail_thread_type_parse(str, &thread_type)) {
		client_send_command_error(cmd, "Unknown thread algorithm.");
		return TRUE;
	}

	ret = imap_search_args_build(cmd, args, charset, &sargs);
	if (ret <= 0)
		return ret < 0;

	ret = imap_thread(cmd, sargs, thread_type);
	mail_search_args_unref(&sargs);
	if (ret < 0) {
		client_send_storage_error(cmd,
			mailbox_get_storage(client->mailbox));
		return TRUE;
	}

	return cmd_sync(cmd, MAILBOX_SYNC_FLAG_FAST |
			(cmd->uid ? 0 : MAILBOX_SYNC_FLAG_NO_EXPUNGES),
			0, "OK Thread completed.");
}
