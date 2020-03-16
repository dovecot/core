/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

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
#include "imap-fetch.h"
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
search_parse_fetch_att(struct imap_search_context *ctx,
		       const struct imap_arg *update_args)
{
	const char *client_error;

	ctx->fetch_pool = pool_alloconly_create("search update fetch", 512);
	if (imap_fetch_att_list_parse(ctx->cmd->client, ctx->fetch_pool,
				      update_args, &ctx->fetch_ctx,
				      &client_error) < 0) {
		client_send_command_error(ctx->cmd, t_strconcat(
			"SEARCH UPDATE fetch-att: ", client_error, NULL));
		pool_unref(&ctx->fetch_pool);
		return FALSE;
	}
	return TRUE;
}

static bool
search_parse_return_options(struct imap_search_context *ctx,
			    const struct imap_arg *args)
{
	struct client_command_context *cmd = ctx->cmd;
	const struct imap_arg *update_args;
	const char *name, *str;
	unsigned int idx;

	while (!IMAP_ARG_IS_EOL(args)) {
		if (!imap_arg_get_atom(args, &name)) {
			client_send_command_error(cmd,
				"SEARCH return options contain non-atoms.");
			return FALSE;
		}
		name = t_str_ucase(name);
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
		else if (strcmp(name, "CONTEXT") == 0) {
			/* no-op */
		} else if (strcmp(name, "UPDATE") == 0) {
			if ((ctx->return_options & SEARCH_RETURN_UPDATE) != 0) {
				client_send_command_error(cmd,
					"SEARCH return options have duplicate UPDATE.");
				return FALSE;
			}
			ctx->return_options |= SEARCH_RETURN_UPDATE;
			if (imap_arg_get_list(args, &update_args)) {
				if (!search_parse_fetch_att(ctx, update_args))
					return FALSE;
				args++;
			}
		} else if (strcmp(name, "RELEVANCY") == 0)
			ctx->return_options |= SEARCH_RETURN_RELEVANCY;
		else if (strcmp(name, "PARTIAL") == 0) {
			if (ctx->partial1 != 0) {
				client_send_command_error(cmd,
					"PARTIAL can be used only once.");
				return FALSE;
			}
			ctx->return_options |= SEARCH_RETURN_PARTIAL;
			if (!imap_arg_get_atom(args, &str)) {
				client_send_command_error(cmd,
					"PARTIAL range missing.");
				return FALSE;
			}
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
		imap_append_quoted(str, ctx->cmd->tag);
		str_append_c(str, ']');
		client_send_line(client, str_c(str));
		ctx->return_options &= ~SEARCH_RETURN_UPDATE;
		imap_search_context_free(ctx);
		return;
	}
	result = mailbox_search_result_save(ctx->search_ctx,
					MAILBOX_SEARCH_RESULT_FLAG_UPDATE |
					MAILBOX_SEARCH_RESULT_FLAG_QUEUE_SYNC);

	update = array_append_space(&client->search_updates);
	update->tag = i_strdup(ctx->cmd->tag);
	update->result = result;
	update->return_uids = ctx->cmd->uid;
	update->fetch_pool = ctx->fetch_pool;
	update->fetch_ctx = ctx->fetch_ctx;
	ctx->fetch_pool = NULL;
	ctx->fetch_ctx = NULL;
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
			o_stream_nsend(ctx->cmd->client->output,
				       str_data(str), str_len(str));
			str_truncate(str, 0);
		}
	}

	if (ctx->highest_seen_modseq != 0) {
		str_printfa(str, " (MODSEQ %"PRIu64")",
			    ctx->highest_seen_modseq);
	}
	str_append(str, "\r\n");
	o_stream_nsend(ctx->cmd->client->output, str_data(str), str_len(str));
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

	/* we need to be able to handle non-sorted seq ranges (for SORT
	   replies), so do this ourself instead of using seq_range_array_*()
	   functions. */
	range = array_get_modifiable(&ctx->result, &count);
	/* delete everything up to partial1 */
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
	if (i == count) {
		/* partial1 points past the result */
		array_clear(&ctx->result);
	} else {
		/* delete everything after partial2 */
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
	}

	if (array_count(&ctx->result) == 0) {
		/* no results (in range) */
		str_append(str, "NIL");
	} else {
		imap_write_seq_range(str, &ctx->result);
	}
	str_append_c(str, ')');
}

static void
imap_search_send_relevancy(struct imap_search_context *ctx, string_t *dest)
{
	const float *scores;
	unsigned int i, count;
	float diff, imap_score;

	scores = array_get(&ctx->relevancy_scores, &count);
	if (count == 0)
		return;

	/* we'll need to convert float scores to numbers 1..100
	   FIXME: would be a good idea to try to detect non-linear score
	   mappings and convert them better.. */
	diff = ctx->max_relevancy - ctx->min_relevancy;
	if (diff == 0)
		diff = 1.0;
	for (i = 0; i < count; i++) {
		if (i > 0)
			str_append_c(dest, ' ');
		imap_score = (scores[i] - ctx->min_relevancy) / diff * 100.0;
		if (imap_score < 1)
			str_append(dest, "1");
		else
			str_printfa(dest, "%u", (unsigned int)imap_score);
	}
}

static void imap_search_send_result(struct imap_search_context *ctx)
{
	struct client *client = ctx->cmd->client;
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
	imap_append_string(str, ctx->cmd->tag);
	str_append_c(str, ')');

	if (ctx->cmd->uid)
		str_append(str, " UID");

	if ((ctx->return_options & SEARCH_RETURN_MIN) != 0 && ctx->min_id != 0)
		str_printfa(str, " MIN %u", ctx->min_id);
	if ((ctx->return_options & SEARCH_RETURN_MAX) != 0 &&
	    ctx->max_seq != 0) {
		uint32_t id = ctx->cmd->uid ? ctx->max_uid : ctx->max_seq;
		str_printfa(str, " MAX %u", id);
	}

	if ((ctx->return_options & SEARCH_RETURN_ALL) != 0 &&
	    array_count(&ctx->result) > 0) {
		str_append(str, " ALL ");
		imap_write_seq_range(str, &ctx->result);
	}
	if ((ctx->return_options & SEARCH_RETURN_RELEVANCY) != 0) {
		str_append(str, " RELEVANCY (");
		imap_search_send_relevancy(ctx, str);
		str_append_c(str, ')');
	}

	if ((ctx->return_options & SEARCH_RETURN_PARTIAL) != 0)
		imap_search_send_partial(ctx, str);

	if ((ctx->return_options & SEARCH_RETURN_COUNT) != 0)
		str_printfa(str, " COUNT %u", ctx->result_count);
	if (ctx->highest_seen_modseq != 0) {
		str_printfa(str, " MODSEQ %"PRIu64,
			    ctx->highest_seen_modseq);
	}
	str_append(str, "\r\n");
	o_stream_nsend(client->output, str_data(str), str_len(str));
	str_free(&str);
}

static void
search_update_mail(struct imap_search_context *ctx, struct mail *mail)
{
	uint64_t modseq;

	if (ctx->max_update_seq == mail->seq) {
		/* MIN already handled this mail */
		return;
	}
	ctx->max_update_seq = mail->seq;

	if ((ctx->return_options & SEARCH_RETURN_MODSEQ) != 0) {
		modseq = mail_get_modseq(mail);
		if (ctx->highest_seen_modseq < modseq)
			ctx->highest_seen_modseq = modseq;
	}
	if ((ctx->return_options & SEARCH_RETURN_SAVE) != 0) {
		seq_range_array_add(&ctx->cmd->client->search_saved_uidset,
				    mail->uid);
	}
	if ((ctx->return_options & SEARCH_RETURN_RELEVANCY) != 0) {
		const char *str;
		float score;

		if (mail_get_special(mail, MAIL_FETCH_SEARCH_RELEVANCY, &str) < 0)
			score = 0;
		else
			score = strtod(str, NULL);
		array_push_back(&ctx->relevancy_scores, &score);
		if (ctx->min_relevancy > score)
			ctx->min_relevancy = score;
		if (ctx->max_relevancy < score)
			ctx->max_relevancy = score;
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
	struct mail *mail;
	enum mailbox_sync_flags sync_flags;
	uint32_t id;
	const char *ok_reply;
	bool tryagain, lost_data;

	if (cmd->cancel) {
		(void)imap_search_deinit(ctx);
		return TRUE;
	}

	while (mailbox_search_next_nonblock(ctx->search_ctx,
					    &mail, &tryagain)) {
		id = cmd->uid ? mail->uid : mail->seq;
		ctx->result_count++;

		ctx->max_seq = mail->seq;
		ctx->max_uid = mail->uid;
		if (HAS_ANY_BITS(opts, SEARCH_RETURN_MIN) && ctx->min_id == 0) {
			/* MIN not set yet */
			ctx->min_id = id;
			search_update_mail(ctx, mail);
		}
		if (HAS_ANY_BITS(opts, SEARCH_RETURN_ALL))
			search_add_result_id(ctx, id);
		else if (HAS_ANY_BITS(opts, SEARCH_RETURN_COUNT)) {
			/* with COUNT don't add it to results, but handle
			   SAVE and MODSEQ */
		} else if (HAS_ANY_BITS(opts, SEARCH_RETURN_MIN |
					SEARCH_RETURN_MAX)) {
			/* MIN and/or MAX only requested, but we don't know if
			   this is MAX until the search is finished. */
			continue;
		} else if (HAS_ANY_BITS(opts, SEARCH_RETURN_SAVE)) {
			/* Only SAVE used */
		}
		search_update_mail(ctx, mail);
	}
	if (tryagain)
		return FALSE;

	if ((opts & SEARCH_RETURN_MAX) != 0 && ctx->max_seq != 0 &&
	    ctx->max_update_seq != ctx->max_seq &&
	    HAS_ANY_BITS(opts, SEARCH_RETURN_MODSEQ |
			 SEARCH_RETURN_SAVE | SEARCH_RETURN_RELEVANCY)) {
		/* finish handling MAX */
		mail = mail_alloc(ctx->trans, 0, NULL);
		mail_set_seq(mail, ctx->max_seq);
		search_update_mail(ctx, mail);
		mail_free(&mail);
	}

	lost_data = mailbox_search_seen_lost_data(ctx->search_ctx);
	if (imap_search_deinit(ctx) < 0) {
		client_send_box_error(cmd, cmd->client->mailbox);
		return TRUE;
	}

	sync_flags = MAILBOX_SYNC_FLAG_FAST;
	if (!cmd->uid || ctx->have_seqsets)
		sync_flags |= MAILBOX_SYNC_FLAG_NO_EXPUNGES;
	ok_reply = t_strdup_printf("OK %s%s completed",
		lost_data ? "["IMAP_RESP_CODE_EXPUNGEISSUED"] " : "",
		!ctx->sorting ? "Search"  : "Sort");
	return cmd_sync(cmd, sync_flags, 0, ok_reply);
}

static void cmd_search_more_callback(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	bool finished;

	o_stream_cork(client->output);
	finished = command_exec(cmd);
	o_stream_uncork(client->output);

	if (!finished)
		(void)client_handle_unfinished_cmd(cmd);
	else
		client_command_free(&cmd);
	cmd_sync_delayed(client);

	if (client->disconnected)
		client_destroy(client, NULL);
	else
		client_continue_pending_input(client);
}

int cmd_search_parse_return_if_found(struct imap_search_context *ctx,
				     const struct imap_arg **_args)
{
	const struct imap_arg *list_args, *args = *_args;
	struct client_command_context *cmd = ctx->cmd;

	if (!imap_arg_atom_equals(&args[0], "RETURN") ||
	    !imap_arg_get_list(&args[1], &list_args)) {
		ctx->return_options = SEARCH_RETURN_ALL;
		return 1;
	}

	if (!search_parse_return_options(ctx, list_args)) {
		imap_search_context_free(ctx);
		return -1;
	}

	if ((ctx->return_options & SEARCH_RETURN_SAVE) != 0) {
		/* wait if there is another SEARCH SAVE command running. */
		if (client_handle_search_save_ambiguity(cmd)) {
			imap_search_context_free(ctx);
			return 0;
		}

		cmd->search_save_result = TRUE;
	}

	*_args = args + 2;
	return 1;
}

bool imap_search_start(struct imap_search_context *ctx,
		       struct mail_search_args *sargs,
		       const enum mail_sort_type *sort_program)
{
	struct client_command_context *cmd = ctx->cmd;

	imap_search_args_check(ctx, sargs->args);

	if (ctx->have_modseqs) {
		ctx->return_options |= SEARCH_RETURN_MODSEQ;
		client_enable(cmd->client, imap_feature_condstore);
	}

	ctx->box = cmd->client->mailbox;
	ctx->trans = mailbox_transaction_begin(ctx->box, 0,
					       imap_client_command_get_reason(cmd));
	ctx->sargs = sargs;
	ctx->search_ctx =
		mailbox_search_init(ctx->trans, sargs, sort_program, 0, NULL);
	ctx->sorting = sort_program != NULL;
	i_array_init(&ctx->result, 128);
	if ((ctx->return_options & SEARCH_RETURN_UPDATE) != 0)
		imap_search_result_save(ctx);
	else {
		i_assert(ctx->fetch_ctx == NULL);
	}
	if ((ctx->return_options & SEARCH_RETURN_RELEVANCY) != 0)
		i_array_init(&ctx->relevancy_scores, 128);

	cmd->func = cmd_search_more;
	cmd->context = ctx;

	if (cmd_search_more(cmd))
		return TRUE;

	/* we may have moved onto syncing by now */
	if (cmd->func == cmd_search_more) {
		ctx->to = timeout_add(0, cmd_search_more_callback, cmd);
		cmd->state = CLIENT_COMMAND_STATE_WAIT_EXTERNAL;
	}
	return FALSE;
}

static int imap_search_deinit(struct imap_search_context *ctx)
{
	int ret = 0;

	if (mailbox_search_deinit(&ctx->search_ctx) < 0)
		ret = -1;

	/* Send the result also after failing. It might have something useful,
	   even though it didn't fully succeed. The client should be able to
	   realize that there was some failure because NO is returned. */
	if (!ctx->cmd->cancel &&
	    (ret == 0 || array_count(&ctx->result) > 0))
		imap_search_send_result(ctx);

	if (ret < 0 || ctx->cmd->cancel) {
		/* search failed */
		if ((ctx->return_options & SEARCH_RETURN_SAVE) != 0)
			array_clear(&ctx->cmd->client->search_saved_uidset);
	}

	(void)mailbox_transaction_commit(&ctx->trans);

	timeout_remove(&ctx->to);
	if (array_is_created(&ctx->relevancy_scores))
		array_free(&ctx->relevancy_scores);
	array_free(&ctx->result);
	mail_search_args_deinit(ctx->sargs);
	mail_search_args_unref(&ctx->sargs);
	imap_search_context_free(ctx);

	ctx->cmd->context = NULL;
	return ret;
}

void imap_search_context_free(struct imap_search_context *ctx)
{
	if (ctx->fetch_ctx != NULL) {
		imap_fetch_free(&ctx->fetch_ctx);
		pool_unref(&ctx->fetch_pool);
	}
}

void imap_search_update_free(struct imap_search_update *update)
{
	if (update->fetch_ctx != NULL) {
		imap_fetch_free(&update->fetch_ctx);
		pool_unref(&update->fetch_pool);
	}
	mailbox_search_result_free(&update->result);
	i_free(update->tag);
}
