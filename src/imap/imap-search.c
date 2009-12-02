/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "ostream.h"
#include "str.h"
#include "seq-range-array.h"
#include "time-util.h"
#include "imap-resp-code.h"
#include "imap-quote.h"
#include "imap-seqset.h"
#include "imap-util.h"
#include "mail-search-build.h"
#include "imap-commands.h"
#include "imap-search-args.h"
#include "imap-search.h"

static int imap_search_deinit(struct imap_search_context *ctx);

static int
imap_partial_range_parse(struct imap_search_context *ctx, const char *str)
{
	ctx->partial1 = 0;
	ctx->partial2 = 0;
	for (; *str >= '0' && *str <= '9'; str++)
		ctx->partial1 = ctx->partial1 * 10 + *str-'0';
	if (*str != ':' || ctx->partial1 == 0)
		return -1;
	for (str++; *str >= '0' && *str <= '9'; str++)
		ctx->partial2 = ctx->partial2 * 10 + *str-'0';
	if (*str != '\0' || ctx->partial2 == 0)
		return -1;

	if (ctx->partial1 > ctx->partial2) {
		uint32_t temp = ctx->partial2;
		ctx->partial2 = ctx->partial1;
		ctx->partial1 = temp;
	}

	return 0;
}

static bool
search_parse_return_options(struct imap_search_context *ctx,
			    const struct imap_arg *args)
{
	struct client_command_context *cmd = ctx->cmd;
	const char *name, *str;
	unsigned int idx;

	while (args->type != IMAP_ARG_EOL) {
		if (args->type != IMAP_ARG_ATOM) {
			client_send_command_error(cmd,
				"SEARCH return options contain non-atoms.");
			return FALSE;
		}
		name = t_str_ucase(IMAP_ARG_STR_NONULL(args));
		args++;
		if (strcmp(name, "MIN") == 0)
			ctx->return_options |= SEARCH_RETURN_MIN;
		else if (strcmp(name, "MAX") == 0)
			ctx->return_options |= SEARCH_RETURN_MAX;
		else if (strcmp(name, "ALL") == 0)
			ctx->return_options |= SEARCH_RETURN_ALL;
		else if (strcmp(name, "COUNT") == 0)
			ctx->return_options |= SEARCH_RETURN_COUNT;
		else if (strcmp(name, "SAVE") == 0)
			ctx->return_options |= SEARCH_RETURN_SAVE;
		else if (strcmp(name, "UPDATE") == 0)
			ctx->return_options |= SEARCH_RETURN_UPDATE;
		else if (strcmp(name, "PARTIAL") == 0) {
			if (ctx->partial1 != 0) {
				client_send_command_error(cmd,
					"PARTIAL can be used only once.");
				return FALSE;
			}
			ctx->return_options |= SEARCH_RETURN_PARTIAL;
			if (args->type != IMAP_ARG_ATOM) {
				client_send_command_error(cmd,
					"PARTIAL range missing.");
				return FALSE;
			}
			str = IMAP_ARG_STR_NONULL(args);
			if (imap_partial_range_parse(ctx, str) < 0) {
				client_send_command_error(cmd,
					"PARTIAL range broken.");
				return FALSE;
			}
			args++;
		} else {
			client_send_command_error(cmd,
				"Unknown SEARCH return option");
			return FALSE;
		}
	}

	if ((ctx->return_options & SEARCH_RETURN_UPDATE) != 0 &&
	    client_search_update_lookup(cmd->client, cmd->tag, &idx) != NULL) {
		client_send_command_error(cmd, "Duplicate search update tag");
		return FALSE;
	}
	if ((ctx->return_options & SEARCH_RETURN_PARTIAL) != 0 &&
	    (ctx->return_options & SEARCH_RETURN_ALL) != 0) {
		client_send_command_error(cmd, "PARTIAL conflicts with ALL");
		return FALSE;
	}

	if (ctx->return_options == 0)
		ctx->return_options = SEARCH_RETURN_ALL;
	ctx->return_options |= SEARCH_RETURN_ESEARCH;
	return TRUE;
}

static void imap_search_args_check(struct imap_search_context *ctx,
				   const struct mail_search_arg *sargs)
{
	for (; sargs != NULL; sargs = sargs->next) {
		switch (sargs->type) {
		case SEARCH_SEQSET:
			ctx->have_seqsets = TRUE;
			break;
		case SEARCH_MODSEQ:
			ctx->have_modseqs = TRUE;
			break;
		case SEARCH_OR:
		case SEARCH_SUB:
			imap_search_args_check(ctx, sargs->value.subargs);
			break;
		default:
			break;
		}
	}
}

static void imap_search_result_save(struct imap_search_context *ctx)
{
	struct client *client = ctx->cmd->client;
	struct mail_search_result *result;
	struct imap_search_update *update;

	if (!array_is_created(&client->search_updates))
		i_array_init(&client->search_updates, 32);
	else if (array_count(&client->search_updates) >=
		 CLIENT_MAX_SEARCH_UPDATES) {
		/* too many updates */
		string_t *str = t_str_new(256);
		str_append(str, "* NO [NOUPDATE ");
		imap_quote_append_string(str, ctx->cmd->tag, FALSE);
		str_append_c(str, ']');
		client_send_line(client, str_c(str));
		ctx->return_options &= ~SEARCH_RETURN_UPDATE;
		return;
	}
	result = mailbox_search_result_save(ctx->search_ctx,
					MAILBOX_SEARCH_RESULT_FLAG_UPDATE |
					MAILBOX_SEARCH_RESULT_FLAG_QUEUE_SYNC);

	update = array_append_space(&client->search_updates);
	update->tag = i_strdup(ctx->cmd->tag);
	update->result = result;
	update->return_uids = ctx->cmd->uid;
}

static void imap_search_send_result_standard(struct imap_search_context *ctx)
{
	const struct seq_range *range;
	string_t *str;
	uint32_t seq;

	str = t_str_new(1024);
	str_append(str, ctx->sorting ? "* SORT" : "* SEARCH");
	array_foreach(&ctx->result, range) {
		for (seq = range->seq1; seq <= range->seq2; seq++)
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

static void
imap_search_send_partial(struct imap_search_context *ctx, string_t *str)
{
	struct seq_range *range;
	uint32_t n, diff;
	unsigned int i, count, delete_count;

	str_printfa(str, " PARTIAL (%u:%u ", ctx->partial1, ctx->partial2);
	ctx->partial1--;
	ctx->partial2--;

	/* we need to be able to handle non-sorted seq ranges, so do this
	   ourself instead of using seq_range_array_*() functions. */
	range = array_get_modifiable(&ctx->result, &count);
	delete_count = 0;
	for (i = n = 0; i < count; i++) {
		diff = range[i].seq2 - range[i].seq1;
		if (n + diff >= ctx->partial1) {
			range[i].seq1 += ctx->partial1 - n;
			delete_count = i;
			break;
		}
		n += diff + 1;
	}
	for (n = ctx->partial1; i < count; i++) {
		diff = range[i].seq2 - range[i].seq1;
		if (n + diff >= ctx->partial2) {
			range[i].seq2 = range[i].seq1 + (ctx->partial2 - n);
			array_delete(&ctx->result, i + 1, count-(i+1));
			break;
		}
		n += diff + 1;
	}
	array_delete(&ctx->result, 0, delete_count);

	if (array_count(&ctx->result) == 0) {
		/* no results (in range) */
		str_append(str, "NIL");
	} else {
		imap_write_seq_range(str, &ctx->result);
	}
	str_append_c(str, ')');
}

static void imap_search_send_result(struct imap_search_context *ctx)
{
	struct client *client = ctx->cmd->client;
	const struct seq_range *range;
	unsigned int count;
	string_t *str;

	if ((ctx->return_options & SEARCH_RETURN_ESEARCH) == 0) {
		imap_search_send_result_standard(ctx);
		return;
	}

	if (ctx->return_options ==
	    (SEARCH_RETURN_ESEARCH | SEARCH_RETURN_SAVE)) {
		/* we only wanted to save the result, don't return
		   ESEARCH result. */
		return;
	}

	str = str_new(default_pool, 1024);
	str_append(str, "* ESEARCH (TAG ");
	imap_quote_append_string(str, ctx->cmd->tag, FALSE);
	str_append_c(str, ')');

	if (ctx->cmd->uid)
		str_append(str, " UID");

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

	if ((ctx->return_options & SEARCH_RETURN_PARTIAL) != 0)
		imap_search_send_partial(ctx, str);

	if ((ctx->return_options & SEARCH_RETURN_COUNT) != 0)
		str_printfa(str, " COUNT %u", ctx->result_count);
	if (ctx->highest_seen_modseq != 0) {
		str_printfa(str, " MODSEQ %llu",
			    (unsigned long long)ctx->highest_seen_modseq);
	}
	str_append(str, "\r\n");
	o_stream_send(client->output, str_data(str), str_len(str));
}

static void search_update_mail(struct imap_search_context *ctx)
{
	uint64_t modseq;

	if ((ctx->return_options & SEARCH_RETURN_MODSEQ) != 0) {
		modseq = mail_get_modseq(ctx->mail);
		if (ctx->highest_seen_modseq < modseq)
			ctx->highest_seen_modseq = modseq;
	}
	if ((ctx->return_options & SEARCH_RETURN_SAVE) != 0) {
		seq_range_array_add(&ctx->cmd->client->search_saved_uidset,
				    0, ctx->mail->uid);
	}
}

static void search_add_result_id(struct imap_search_context *ctx, uint32_t id)
{
	struct seq_range *range;
	unsigned int count;

	/* only append the data. this is especially important when we're
	   returning a sort result. */
	range = array_get_modifiable(&ctx->result, &count);
	if (count > 0 && id == range[count-1].seq2 + 1) {
		range[count-1].seq2++;
	} else {
		range = array_append_space(&ctx->result);
		range->seq1 = range->seq2 = id;
	}
}

static bool cmd_search_more(struct client_command_context *cmd)
{
	struct imap_search_context *ctx = cmd->context;
	enum search_return_options opts = ctx->return_options;
	enum mailbox_sync_flags sync_flags;
	struct timeval end_time;
	const struct seq_range *range;
	unsigned int count;
	uint32_t id, id_min, id_max;
	const char *ok_reply;
	int time_msecs;
	bool tryagain, minmax, lost_data;

	if (cmd->cancel) {
		(void)imap_search_deinit(ctx);
		return TRUE;
	}

	range = array_get(&ctx->result, &count);
	if (count == 0) {
		id_min = 0;
		id_max = 0;
	} else {
		id_min = range[0].seq1;
		id_max = range[count-1].seq2;
	}

	minmax = (opts & (SEARCH_RETURN_MIN | SEARCH_RETURN_MAX)) != 0 &&
		(opts & ~(SEARCH_RETURN_NORESULTS |
			  SEARCH_RETURN_MIN | SEARCH_RETURN_MAX)) == 0;
	while (mailbox_search_next_nonblock(ctx->search_ctx, ctx->mail,
					    &tryagain)) {
		id = cmd->uid ? ctx->mail->uid : ctx->mail->seq;
		ctx->result_count++;

		if (minmax) {
			/* we only care about min/max */
			if (id_min == 0 && (opts & SEARCH_RETURN_MIN) != 0)
				id_min = id;
			if ((opts & SEARCH_RETURN_MAX) != 0)
				id_max = id;
			if (id == id_min || id == id_max) {
				/* return option updates are delayed until
				   we know the actual min/max values */
				search_add_result_id(ctx, id);
			}
			continue;
		}

		search_update_mail(ctx);
		if ((opts & ~(SEARCH_RETURN_NORESULTS |
			      SEARCH_RETURN_COUNT)) == 0) {
			/* we only want to count (and get modseqs) */
			continue;
		}
		search_add_result_id(ctx, id);
	}
	if (tryagain)
		return FALSE;

	if (minmax && array_count(&ctx->result) > 0 &&
	    (opts & (SEARCH_RETURN_MODSEQ | SEARCH_RETURN_SAVE)) != 0) {
		/* handle MIN/MAX modseq/save updates */
		if ((opts & SEARCH_RETURN_MIN) != 0) {
			i_assert(id_min != 0);
			if (cmd->uid) {
				if (!mail_set_uid(ctx->mail, id_min))
					i_unreached();
			} else {
				mail_set_seq(ctx->mail, id_min);
			}
			search_update_mail(ctx);
		}
		if ((opts & SEARCH_RETURN_MAX) != 0) {
			i_assert(id_max != 0);
			if (cmd->uid) {
				if (!mail_set_uid(ctx->mail, id_max))
					i_unreached();
			} else {
				mail_set_seq(ctx->mail, id_max);
			}
			search_update_mail(ctx);
		}
	}

	lost_data = mailbox_search_seen_lost_data(ctx->search_ctx);
	if (imap_search_deinit(ctx) < 0) {
		client_send_storage_error(cmd,
			mailbox_get_storage(cmd->client->mailbox));
		return TRUE;
	}

	if (gettimeofday(&end_time, NULL) < 0)
		memset(&end_time, 0, sizeof(end_time));

	time_msecs = timeval_diff_msecs(&end_time, &ctx->start_time);

	sync_flags = MAILBOX_SYNC_FLAG_FAST;
	if (!cmd->uid || ctx->have_seqsets)
		sync_flags |= MAILBOX_SYNC_FLAG_NO_EXPUNGES;
	ok_reply = t_strdup_printf("OK %s%s completed (%d.%03d secs).",
		lost_data ? "["IMAP_RESP_CODE_EXPUNGEISSUED"] " : "",
		!ctx->sorting ? "Search"  : "Sort",
		time_msecs/1000, time_msecs%1000);
	return cmd_sync(cmd, sync_flags, 0, ok_reply);
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
		client_command_free(&cmd);
	(void)cmd_sync_delayed(client);

	if (client->disconnected)
		client_destroy(client, NULL);
	else
		client_continue_pending_input(client);
}

int cmd_search_parse_return_if_found(struct imap_search_context *ctx,
				     const struct imap_arg **_args)
{
	const struct imap_arg *args = *_args;
	struct client_command_context *cmd = ctx->cmd;

	if (!(args->type == IMAP_ARG_ATOM && args[1].type == IMAP_ARG_LIST &&
	      strcasecmp(IMAP_ARG_STR_NONULL(args), "RETURN") == 0)) {
		ctx->return_options = SEARCH_RETURN_ALL;
		return 1;
	}

	args++;
	if (!search_parse_return_options(ctx, IMAP_ARG_LIST_ARGS(args)))
		return -1;
	args++;

	if ((ctx->return_options & SEARCH_RETURN_SAVE) != 0) {
		/* wait if there is another SEARCH SAVE command running. */
		cmd->search_save_result = TRUE;
		if (client_handle_search_save_ambiguity(cmd))
			return 0;

		/* make sure the search result gets cleared if SEARCH fails */
		if (array_is_created(&cmd->client->search_saved_uidset))
			array_clear(&cmd->client->search_saved_uidset);
		else
			i_array_init(&cmd->client->search_saved_uidset, 128);
	}

	*_args = args;
	return 1;
}

static void wanted_fields_get(struct mailbox *box,
			      const enum mail_sort_type *sort_program,
			      enum mail_fetch_field *wanted_fields_r,
			      struct mailbox_header_lookup_ctx **headers_ctx_r)
{
	const char *headers[2];

	*wanted_fields_r = 0;
	*headers_ctx_r = NULL;

	if (sort_program == NULL)
		return;

	headers[0] = headers[1] = NULL;
	switch (sort_program[0] & MAIL_SORT_MASK) {
	case MAIL_SORT_ARRIVAL:
		*wanted_fields_r = MAIL_FETCH_RECEIVED_DATE;
		break;
	case MAIL_SORT_CC:
		headers[0] = "Cc";
		break;
	case MAIL_SORT_DATE:
		*wanted_fields_r = MAIL_FETCH_DATE;
		break;
	case MAIL_SORT_FROM:
		headers[0] = "From";
		break;
	case MAIL_SORT_SIZE:
		*wanted_fields_r = MAIL_FETCH_VIRTUAL_SIZE;
		break;
	case MAIL_SORT_SUBJECT:
		headers[0] = "Subject";
		break;
	case MAIL_SORT_TO:
		headers[0] = "To";
		break;
	}

	if (headers[0] != NULL)
		*headers_ctx_r = mailbox_header_lookup_init(box, headers);
}

bool imap_search_start(struct imap_search_context *ctx,
		       struct mail_search_args *sargs,
		       const enum mail_sort_type *sort_program)
{
	struct client_command_context *cmd = ctx->cmd;
	enum mail_fetch_field wanted_fields;
	struct mailbox_header_lookup_ctx *wanted_headers;

	imap_search_args_check(ctx, sargs->args);

	if (ctx->have_modseqs) {
		ctx->return_options |= SEARCH_RETURN_MODSEQ;
		client_enable(cmd->client, MAILBOX_FEATURE_CONDSTORE);
	}

	ctx->box = cmd->client->mailbox;
	wanted_fields_get(ctx->box, sort_program,
			  &wanted_fields, &wanted_headers);

	ctx->trans = mailbox_transaction_begin(ctx->box, 0);
	ctx->sargs = sargs;
	ctx->search_ctx = mailbox_search_init(ctx->trans, sargs, sort_program);
	ctx->mail = mail_alloc(ctx->trans, wanted_fields, wanted_headers);
	ctx->sorting = sort_program != NULL;
	(void)gettimeofday(&ctx->start_time, NULL);
	i_array_init(&ctx->result, 128);
	if ((ctx->return_options & SEARCH_RETURN_UPDATE) != 0)
		imap_search_result_save(ctx);

	cmd->func = cmd_search_more;
	cmd->context = ctx;

	if (cmd_search_more(cmd))
		return TRUE;

	/* we may have moved onto syncing by now */
	if (cmd->func == cmd_search_more)
		ctx->to = timeout_add(0, cmd_search_more_callback, cmd);
	return FALSE;
}

static int imap_search_deinit(struct imap_search_context *ctx)
{
	int ret = 0;

	mail_free(&ctx->mail);
	if (mailbox_search_deinit(&ctx->search_ctx) < 0)
		ret = -1;

	if (ret == 0 && !ctx->cmd->cancel)
		imap_search_send_result(ctx);
	else {
		/* search failed */
		if ((ctx->return_options & SEARCH_RETURN_SAVE) != 0)
			array_clear(&ctx->cmd->client->search_saved_uidset);
	}

	(void)mailbox_transaction_commit(&ctx->trans);

	if (ctx->to != NULL)
		timeout_remove(&ctx->to);
	array_free(&ctx->result);
	mail_search_args_deinit(ctx->sargs);
	mail_search_args_unref(&ctx->sargs);

	ctx->cmd->context = NULL;
	return ret;
}
