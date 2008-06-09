/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "str.h"
#include "ostream.h"
#include "commands.h"
#include "imap-search.h"
#include "imap-thread.h"

static int imap_thread_write(struct mail_thread_iterate_context *iter,
			     string_t *str, bool root)
{
	const struct mail_thread_child_node *node;
	struct mail_thread_iterate_context *child_iter;
	unsigned int count;
	int ret;

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
imap_thread_write_reply(struct imap_thread_context *ctx, string_t *str,
			enum mail_thread_type thread_type, bool write_seqs)
{
	struct mail_thread_iterate_context *iter;
	int ret;

	iter = imap_thread_iterate_init(ctx, thread_type, write_seqs);
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
	struct imap_thread_context *ctx;
	string_t *str;
	bool reset = FALSE;
	int ret;

	i_assert(thread_type == MAIL_THREAD_REFERENCES ||
		 thread_type == MAIL_THREAD_REFERENCES2);

	str = str_new(default_pool, 1024);
	for (;;) {
		ret = imap_thread_init(cmd->client->mailbox, reset,
				       search_args, &ctx);
		if (ret == 0) {
			ret = imap_thread_write_reply(ctx, str, thread_type,
						      !cmd->uid);
			imap_thread_deinit(&ctx);
		}

		if (ret == 0 || reset)
			break;
		/* try again with in-memory hash */
		reset = TRUE;
		str_truncate(str, 0);
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
	int ret, args_count;
	const char *charset, *str;

	args_count = imap_parser_read_args(cmd->parser, 0, 0, &args);
	if (args_count == -2)
		return FALSE;
	client->input_lock = NULL;

	if (args_count < 3) {
		client_send_command_error(cmd, args_count < 0 ? NULL :
					  "Missing or invalid arguments.");
		return TRUE;
	}

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	if (args->type != IMAP_ARG_ATOM && args->type != IMAP_ARG_STRING) {
		client_send_command_error(cmd,
					  "Invalid thread algorithm argument.");
		return TRUE;
	}

	str = IMAP_ARG_STR(args);
	if (strcasecmp(str, "REFERENCES") == 0)
		thread_type = MAIL_THREAD_REFERENCES;
	else if (strcasecmp(str, "X-REFERENCES2") == 0)
		thread_type = MAIL_THREAD_REFERENCES2;
	else if (strcasecmp(str, "ORDEREDSUBJECT") == 0) {
		client_send_command_error(cmd,
			"ORDEREDSUBJECT threading is currently not supported.");
		return TRUE;
	} else {
		client_send_command_error(cmd, "Unknown thread algorithm.");
		return TRUE;
	}
	args++;

	/* charset */
	if (args->type != IMAP_ARG_ATOM && args->type != IMAP_ARG_STRING) {
		client_send_command_error(cmd,
					  "Invalid charset argument.");
		return TRUE;
	}
	charset = IMAP_ARG_STR(args);
	args++;

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
