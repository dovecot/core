/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ostream.h"
#include "str.h"
#include "seq-range-array.h"
#include "commands.h"
#include "mail-search.h"
#include "mail-search-build.h"
#include "imap-quote.h"
#include "imap-util.h"
#include "imap-search.h"

enum search_return_options {
	SEARCH_RETURN_ESEARCH		= 0x01,
	SEARCH_RETURN_MIN		= 0x02,
	SEARCH_RETURN_MAX		= 0x04,
	SEARCH_RETURN_ALL		= 0x08,
	SEARCH_RETURN_COUNT		= 0x10,
	SEARCH_RETURN_MODSEQ		= 0x20
#define SEARCH_RETURN_EXTRAS (SEARCH_RETURN_ESEARCH | SEARCH_RETURN_MODSEQ)
};

struct imap_search_context {
	struct client_command_context *cmd;
	struct mailbox *box;
	struct mailbox_transaction_context *trans;
        struct mail_search_context *search_ctx;
	struct mail *mail;
	struct mail_search_arg *sargs;
	enum search_return_options return_options;

	struct timeout *to;
	ARRAY_TYPE(seq_range) result;
	unsigned int result_count;

	uint64_t highest_seen_modseq;
	struct timeval start_time;
};

static bool search_parse_return_options(struct imap_search_context *ctx,
					const struct imap_arg *args)
{
	const char *name;

	while (args->type != IMAP_ARG_EOL) {
		if (args->type != IMAP_ARG_ATOM) {
			client_send_command_error(ctx->cmd,
				"SEARCH return options contain non-atoms.");
			return FALSE;
		}
		name = t_str_ucase(IMAP_ARG_STR(args));
		args++;
		if (strcmp(name, "MIN") == 0)
			ctx->return_options |= SEARCH_RETURN_MIN;
		else if (strcmp(name, "MAX") == 0)
			ctx->return_options |= SEARCH_RETURN_MAX;
		else if (strcmp(name, "ALL") == 0)
			ctx->return_options |= SEARCH_RETURN_ALL;
		else if (strcmp(name, "COUNT") == 0)
			ctx->return_options |= SEARCH_RETURN_COUNT;
		else {
			client_send_command_error(ctx->cmd,
				"Unknown SEARCH return option");
			return FALSE;
		}
	}
	if (ctx->return_options == 0)
		ctx->return_options = SEARCH_RETURN_ALL;
	ctx->return_options |= SEARCH_RETURN_ESEARCH;
	return TRUE;
}

static bool imap_search_args_have_modseq(const struct mail_search_arg *sargs)
{
	for (; sargs != NULL; sargs = sargs->next) {
		switch (sargs->type) {
		case SEARCH_MODSEQ:
			return TRUE;
		case SEARCH_OR:
		case SEARCH_SUB:
			if (imap_search_args_have_modseq(sargs->value.subargs))
				return TRUE;
			break;
		default:
			break;
		}
	}
	return FALSE;
}

static struct imap_search_context *
imap_search_init(struct imap_search_context *ctx, const char *charset,
		 struct mail_search_arg *sargs)
{
	if (imap_search_args_have_modseq(sargs)) {
		ctx->return_options |= SEARCH_RETURN_MODSEQ;
		client_enable(ctx->cmd->client, MAILBOX_FEATURE_CONDSTORE);
	}

	ctx->box = ctx->cmd->client->mailbox;
	ctx->trans = mailbox_transaction_begin(ctx->box, 0);
	ctx->sargs = sargs;
	ctx->search_ctx = mailbox_search_init(ctx->trans, charset, sargs, NULL);
	ctx->mail = mail_alloc(ctx->trans, 0, NULL);
	(void)gettimeofday(&ctx->start_time, NULL);
	i_array_init(&ctx->result, 128);
	return ctx;
}

static void imap_search_send_result_standard(struct imap_search_context *ctx)
{
	const struct seq_range *range;
	unsigned int i, count;
	string_t *str;
	uint32_t seq;

	str = t_str_new(1024);
	range = array_get(&ctx->result, &count);
	str_append(str, "* SEARCH");
	for (i = 0; i < count; i++) {
		for (seq = range[i].seq1; seq <= range[i].seq2; seq++)
			str_printfa(str, " %u", seq);
		if (str_len(str) >= 1024-32) {
			o_stream_send(ctx->cmd->client->output,
				      str_data(str), str_len(str));
			str_truncate(str, 0);
		}
	}

	if (ctx->highest_seen_modseq != 0) {
		str_printfa(str, " (MODSEQ %llu)",
			    (unsigned long long)ctx->highest_seen_modseq);
	}
	str_append(str, "\r\n");
	o_stream_send(ctx->cmd->client->output,
		      str_data(str), str_len(str));
}

static void imap_search_send_result(struct imap_search_context *ctx)
{
	const struct seq_range *range;
	unsigned int count;
	string_t *str;

	if ((ctx->return_options & SEARCH_RETURN_ESEARCH) == 0) {
		imap_search_send_result_standard(ctx);
		return;
	}

	str = str_new(default_pool, 1024);
	str_append(str, "* ESEARCH (TAG ");
	imap_quote_append_string(str, ctx->cmd->tag, FALSE);
	str_append_c(str, ')');

	range = array_get(&ctx->result, &count);
	if (count > 0) {
		if ((ctx->return_options & SEARCH_RETURN_MIN) != 0)
			str_printfa(str, " MIN %u", range[0].seq1);
		if ((ctx->return_options & SEARCH_RETURN_MAX) != 0)
			str_printfa(str, " MAX %u", range[count-1].seq2);
		if ((ctx->return_options & SEARCH_RETURN_ALL) != 0) {
			str_append(str, " ALL ");
			imap_write_seq_range(str, &ctx->result);
		}
	}

	if ((ctx->return_options & SEARCH_RETURN_COUNT) != 0)
		str_printfa(str, " COUNT %u", ctx->result_count);
	if (ctx->highest_seen_modseq != 0) {
		str_printfa(str, " MODSEQ %llu",
			    (unsigned long long)ctx->highest_seen_modseq);
	}
	str_append(str, "\r\n");
	o_stream_send(ctx->cmd->client->output,
		      str_data(str), str_len(str));
}

static int imap_search_deinit(struct imap_search_context *ctx)
{
	int ret = 0;

	mail_free(&ctx->mail);
	if (mailbox_search_deinit(&ctx->search_ctx) < 0)
		ret = -1;
	else if (!ctx->cmd->cancel)
		imap_search_send_result(ctx);

	(void)mailbox_transaction_commit(&ctx->trans);

	if (ctx->to != NULL)
		timeout_remove(&ctx->to);
	array_free(&ctx->result);
	mail_search_args_deinit(ctx->sargs, ctx->box);

	ctx->cmd->context = NULL;
	return ret;
}

static bool cmd_search_more(struct client_command_context *cmd)
{
	struct imap_search_context *ctx = cmd->context;
	enum search_return_options opts = ctx->return_options;
	struct timeval end_time;
	const struct seq_range *range;
	unsigned int count;
	uint64_t modseq;
	uint32_t id, id_min, id_max;
	bool tryagain;

	if (cmd->cancel) {
		(void)imap_search_deinit(ctx);
		return TRUE;
	}

	range = array_get(&ctx->result, &count);
	if (count == 0) {
		id_min = (uint32_t)-1;
		id_max = 0;
	} else {
		id_min = range[0].seq1;
		id_max = range[count-1].seq2;
	}

	while (mailbox_search_next_nonblock(ctx->search_ctx, ctx->mail,
					    &tryagain) > 0) {
		id = cmd->uid ? ctx->mail->uid : ctx->mail->seq;
		ctx->result_count++;

		if ((opts & ~(SEARCH_RETURN_EXTRAS |
			      SEARCH_RETURN_MIN | SEARCH_RETURN_MAX)) == 0) {
			/* we only care about min/max */
			if (id < id_min && (opts & SEARCH_RETURN_MIN) != 0)
				id_min = id;
			if (id > id_max && (opts & SEARCH_RETURN_MAX) != 0)
				id_max = id;
			if (id == id_min || id == id_max) {
				/* modseq is looked up when we know the
				   actual min/max values */
				seq_range_array_add(&ctx->result, 0, id);
			}
			continue;
		}

		if ((ctx->return_options & SEARCH_RETURN_MODSEQ) != 0) {
			modseq = mail_get_modseq(ctx->mail);
			if (ctx->highest_seen_modseq < modseq)
				ctx->highest_seen_modseq = modseq;
		}

		if ((opts & ~(SEARCH_RETURN_EXTRAS |
			      SEARCH_RETURN_COUNT)) == 0) {
			/* we only want to count (and get modseqs) */
			continue;
		}
		seq_range_array_add(&ctx->result, 0, id);
	}
	if (tryagain)
		return FALSE;

	if (ctx->highest_seen_modseq == 0 &&
	    (ctx->return_options & SEARCH_RETURN_MODSEQ) != 0 &&
	    array_count(&ctx->result) > 0) {
		/* get highest modseq only from MIN/MAX messages */
		if ((opts & SEARCH_RETURN_MIN) != 0) {
			i_assert(id_min != (uint32_t)-1);
			if (cmd->uid) {
				if (!mail_set_uid(ctx->mail, id_min))
					i_unreached();
			} else {
				mail_set_seq(ctx->mail, id_min);
			}
			ctx->highest_seen_modseq = mail_get_modseq(ctx->mail);
		}
		if ((opts & SEARCH_RETURN_MAX) != 0) {
			i_assert(id_max != 0);
			if (cmd->uid) {
				if (!mail_set_uid(ctx->mail, id_max))
					i_unreached();
			} else {
				mail_set_seq(ctx->mail, id_max);
			}
			modseq = mail_get_modseq(ctx->mail);
			if (ctx->highest_seen_modseq < modseq)
				ctx->highest_seen_modseq = modseq;
		}
	}

	if (imap_search_deinit(ctx) < 0) {
		client_send_storage_error(cmd,
			mailbox_get_storage(cmd->client->mailbox));
		return TRUE;
	}

	if (gettimeofday(&end_time, NULL) < 0)
		memset(&end_time, 0, sizeof(end_time));
	end_time.tv_sec -= ctx->start_time.tv_sec;
	end_time.tv_usec -= ctx->start_time.tv_usec;
	if (end_time.tv_usec < 0) {
		end_time.tv_sec++;
		end_time.tv_usec += 1000000;
	}

	return cmd_sync(cmd, MAILBOX_SYNC_FLAG_FAST |
			(cmd->uid ? 0 : MAILBOX_SYNC_FLAG_NO_EXPUNGES), 0,
			t_strdup_printf("OK Search completed (%d.%03d secs).",
					(int)end_time.tv_sec,
					(int)(end_time.tv_usec/1000)));
}

static void cmd_search_more_callback(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	bool finished;

	o_stream_cork(client->output);
	finished = cmd_search_more(cmd);
	o_stream_uncork(client->output);

	if (!finished)
		(void)client_handle_unfinished_cmd(cmd);
	else
		client_command_free(cmd);
	(void)cmd_sync_delayed(client);
	client_continue_pending_input(&client);
}

bool cmd_search(struct client_command_context *cmd)
{
	struct imap_search_context *ctx;
	struct mail_search_arg *sargs;
	const struct imap_arg *args;
	int args_count;
	const char *error, *charset;

	args_count = imap_parser_read_args(cmd->parser, 0, 0, &args);
	if (args_count < 1) {
		if (args_count == -2)
			return FALSE;

		client_send_command_error(cmd, args_count < 0 ? NULL :
					  "Missing SEARCH arguments.");
		return TRUE;
	}
	cmd->client->input_lock = NULL;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	ctx = p_new(cmd->pool, struct imap_search_context, 1);
	ctx->cmd = cmd;

	if (args->type == IMAP_ARG_ATOM && args[1].type == IMAP_ARG_LIST &&
	    strcasecmp(IMAP_ARG_STR_NONULL(args), "RETURN") == 0) {
		args++;
		if (!search_parse_return_options(ctx, IMAP_ARG_LIST_ARGS(args)))
			return TRUE;
		args++;
	} else {
		ctx->return_options = SEARCH_RETURN_ALL;
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

	sargs = imap_search_args_build(cmd->pool, cmd->client->mailbox,
				       args, &error);
	if (sargs == NULL) {
		/* error in search arguments */
		client_send_tagline(cmd, t_strconcat("BAD ", error, NULL));
		return TRUE;
	}

	imap_search_init(ctx, charset, sargs);
	cmd->func = cmd_search_more;
	cmd->context = ctx;

	if (cmd_search_more(cmd))
		return TRUE;

	/* we could have moved onto syncing by now */
	if (cmd->func == cmd_search_more)
		ctx->to = timeout_add(0, cmd_search_more_callback, cmd);
	return FALSE;
}
