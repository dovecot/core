/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "seq-range-array.h"
#include "imap-commands.h"
#include "mail-search-build.h"
#include "imap-seqset.h"
#include "imap-fetch.h"
#include "imap-sync.h"

#include <stdlib.h>

struct imap_select_context {
	struct client_command_context *cmd;
	struct mail_namespace *ns;
	struct mailbox *box;

	struct imap_fetch_context *fetch_ctx;

	uint32_t qresync_uid_validity;
	uint64_t qresync_modseq;
	ARRAY_TYPE(seq_range) qresync_known_uids;
	ARRAY_TYPE(uint32_t) qresync_sample_seqset;
	ARRAY_TYPE(uint32_t) qresync_sample_uidset;

	unsigned int condstore:1;
};

static int select_qresync_get_uids(struct imap_select_context *ctx,
				   const ARRAY_TYPE(seq_range) *seqset,
				   const ARRAY_TYPE(seq_range) *uidset)
{
	const struct seq_range *uid_range;
	struct seq_range_iter seq_iter;
	unsigned int i, uid_count, diff, n = 0;
	uint32_t seq;

	/* change all n:m ranges to n,m and store the results */
	uid_range = array_get(uidset, &uid_count);

	seq_range_array_iter_init(&seq_iter, seqset);
	i_array_init(&ctx->qresync_sample_uidset, uid_count);
	i_array_init(&ctx->qresync_sample_seqset, uid_count);
	for (i = 0; i < uid_count; i++) {
		if (!seq_range_array_iter_nth(&seq_iter, n++, &seq))
			return -1;
		array_append(&ctx->qresync_sample_uidset,
			     &uid_range[i].seq1, 1);
		array_append(&ctx->qresync_sample_seqset, &seq, 1);

		diff = uid_range[i].seq2 - uid_range[i].seq1;
		if (diff > 0) {
			n += diff - 1;
			if (!seq_range_array_iter_nth(&seq_iter, n++, &seq))
				return -1;

			array_append(&ctx->qresync_sample_uidset,
				     &uid_range[i].seq2, 1);
			array_append(&ctx->qresync_sample_seqset, &seq, 1);
		}
	}
	if (seq_range_array_iter_nth(&seq_iter, n, &seq))
		return -1;
	return 0;
}

static bool
select_parse_qresync_known_set(struct imap_select_context *ctx,
			       const struct imap_arg *args)
{
	ARRAY_TYPE(seq_range) seqset, uidset;
	const char *str;

	t_array_init(&seqset, 32);
	if (!imap_arg_get_atom(args, &str) ||
	    imap_seq_set_nostar_parse(str, &seqset) < 0) {
		client_send_command_error(ctx->cmd,
			"Invalid QRESYNC known-sequence-set");
		return FALSE;
	}
	args++;

	t_array_init(&uidset, 32);
	if (!imap_arg_get_atom(args, &str) ||
	    imap_seq_set_nostar_parse(str, &uidset) < 0) {
		client_send_command_error(ctx->cmd,
			"Invalid QRESYNC known-uid-set");
		return FALSE;
	}
	args++;

	if (select_qresync_get_uids(ctx, &seqset, &uidset) < 0) {
		client_send_command_error(ctx->cmd, "Invalid QRESYNC sets");
		return FALSE;
	}
	if (!IMAP_ARG_IS_EOL(args)) {
		client_send_command_error(ctx->cmd,
			"Too many parameters to QRESYNC known set");
		return FALSE;
	}
	return TRUE;
}

static bool
select_parse_qresync(struct imap_select_context *ctx,
		     const struct imap_arg *args)
{
	const struct imap_arg *list_args;
	const char *str;
	unsigned int count;

	if ((ctx->cmd->client->enabled_features &
	     MAILBOX_FEATURE_QRESYNC) == 0) {
		client_send_command_error(ctx->cmd, "QRESYNC not enabled");
		return FALSE;
	}
	if (!imap_arg_get_list_full(args, &args, &count)) {
		client_send_command_error(ctx->cmd,
					  "QRESYNC parameters missing");
		return FALSE;
	}

	if (!imap_arg_get_atom(&args[0], &str) ||
	    str_to_uint32(str, &ctx->qresync_uid_validity) < 0 ||
	    !imap_arg_get_atom(&args[1], &str) ||
	    str_to_uint64(str, &ctx->qresync_modseq) < 0) {
		client_send_command_error(ctx->cmd,
					  "Invalid QRESYNC parameters");
		return FALSE;
	}
	args += 2;

	i_array_init(&ctx->qresync_known_uids, 64);
	if (imap_arg_get_atom(args, &str)) {
		if (imap_seq_set_nostar_parse(str, &ctx->qresync_known_uids) < 0) {
			client_send_command_error(ctx->cmd,
						  "Invalid QRESYNC known-uids");
			return FALSE;
		}
		args++;
	} else {
		seq_range_array_add_range(&ctx->qresync_known_uids,
					  1, (uint32_t)-1);
	}
	if (imap_arg_get_list(args, &list_args)) {
		if (!select_parse_qresync_known_set(ctx, list_args))
			return FALSE;
		args++;
	}
	if (!IMAP_ARG_IS_EOL(args)) {
		client_send_command_error(ctx->cmd,
					  "Invalid QRESYNC parameters");
		return FALSE;
	}
	return TRUE;
}

static bool
select_parse_options(struct imap_select_context *ctx,
		     const struct imap_arg *args)
{
	const char *name;

	while (!IMAP_ARG_IS_EOL(args)) {
		if (!imap_arg_get_atom(args, &name)) {
			client_send_command_error(ctx->cmd,
				"SELECT options contain non-atoms.");
			return FALSE;
		}
		name = t_str_ucase(name);
		args++;

		if (strcmp(name, "CONDSTORE") == 0)
			ctx->condstore = TRUE;
		else if (strcmp(name, "QRESYNC") == 0) {
			if (!select_parse_qresync(ctx, args))
				return FALSE;
			args++;
		} else {
			client_send_command_error(ctx->cmd,
						  "Unknown FETCH modifier");
			return FALSE;
		}
	}
	return TRUE;
}

static void select_context_free(struct imap_select_context *ctx)
{
	if (array_is_created(&ctx->qresync_known_uids))
		array_free(&ctx->qresync_known_uids);
	if (array_is_created(&ctx->qresync_sample_seqset))
		array_free(&ctx->qresync_sample_seqset);
	if (array_is_created(&ctx->qresync_sample_uidset))
		array_free(&ctx->qresync_sample_uidset);
}

static void cmd_select_finish(struct imap_select_context *ctx, int ret)
{
	if (ret < 0) {
		if (ctx->box != NULL)
			mailbox_free(&ctx->box);
		ctx->cmd->client->mailbox = NULL;
	} else {
		client_send_tagline(ctx->cmd, mailbox_is_readonly(ctx->box) ?
				    "OK [READ-ONLY] Select completed." :
				    "OK [READ-WRITE] Select completed.");
	}
	select_context_free(ctx);
}

static bool cmd_select_continue(struct client_command_context *cmd)
{
        struct imap_select_context *ctx = cmd->context;
	int ret;

	if (imap_fetch_more(ctx->fetch_ctx) == 0) {
		/* unfinished */
		return FALSE;
	}

	ret = imap_fetch_deinit(ctx->fetch_ctx);
	if (ret < 0) {
		client_send_storage_error(ctx->cmd,
					  mailbox_get_storage(ctx->box));
	}
	cmd_select_finish(ctx, ret);
	return TRUE;
}

static int select_qresync(struct imap_select_context *ctx)
{
	struct imap_fetch_context *fetch_ctx;
	struct mail_search_args *search_args;

	search_args = mail_search_build_init();
	search_args->args = p_new(search_args->pool, struct mail_search_arg, 1);
	search_args->args->type = SEARCH_UIDSET;
	search_args->args->value.seqset = ctx->qresync_known_uids;

	fetch_ctx = imap_fetch_init(ctx->cmd, ctx->box);
	if (fetch_ctx == NULL)
		return -1;

	fetch_ctx->search_args = search_args;
	fetch_ctx->send_vanished = TRUE;
	fetch_ctx->qresync_sample_seqset = &ctx->qresync_sample_seqset;
	fetch_ctx->qresync_sample_uidset = &ctx->qresync_sample_uidset;

	if (!imap_fetch_add_changed_since(fetch_ctx, ctx->qresync_modseq) ||
	    !imap_fetch_init_handler(fetch_ctx, "UID", NULL) ||
	    !imap_fetch_init_handler(fetch_ctx, "FLAGS", NULL) ||
	    !imap_fetch_init_handler(fetch_ctx, "MODSEQ", NULL)) {
		(void)imap_fetch_deinit(fetch_ctx);
		return -1;
	}

	if (imap_fetch_begin(fetch_ctx) == 0) {
		if (imap_fetch_more(fetch_ctx) == 0) {
			/* unfinished */
			ctx->fetch_ctx = fetch_ctx;
			ctx->cmd->state = CLIENT_COMMAND_STATE_WAIT_OUTPUT;

			ctx->cmd->func = cmd_select_continue;
			ctx->cmd->context = ctx;
			return 0;
		}
	}

	return imap_fetch_deinit(fetch_ctx) < 0 ? -1 : 1;
}

static int
select_open(struct imap_select_context *ctx, const char *mailbox, bool readonly)
{
	struct client *client = ctx->cmd->client;
	struct mailbox_status status;
	enum mailbox_flags flags = 0;
	int ret = 0;

	if (readonly)
		flags |= MAILBOX_FLAG_READONLY | MAILBOX_FLAG_KEEP_RECENT;
	ctx->box = mailbox_alloc(ctx->ns->list, mailbox, flags);
	if (mailbox_open(ctx->box) < 0) {
		client_send_storage_error(ctx->cmd,
					  mailbox_get_storage(ctx->box));
		mailbox_free(&ctx->box);
		return -1;
	}

	if (client->enabled_features != 0)
		ret = mailbox_enable(ctx->box, client->enabled_features);
	if (ret < 0 ||
	    mailbox_sync(ctx->box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		client_send_storage_error(ctx->cmd,
					  mailbox_get_storage(ctx->box));
		return -1;
	}
	mailbox_get_open_status(ctx->box, STATUS_MESSAGES | STATUS_RECENT |
				STATUS_FIRST_UNSEEN_SEQ | STATUS_UIDVALIDITY |
				STATUS_UIDNEXT | STATUS_KEYWORDS |
				STATUS_HIGHESTMODSEQ, &status);

	client->mailbox = ctx->box;
	client->select_counter++;
	client->mailbox_examined = readonly;
	client->messages_count = status.messages;
	client->recent_count = status.recent;
	client->uidvalidity = status.uidvalidity;

	client_update_mailbox_flags(client, status.keywords);
	client_send_mailbox_flags(client, TRUE);

	client_send_line(client,
		t_strdup_printf("* %u EXISTS", status.messages));
	client_send_line(client,
		t_strdup_printf("* %u RECENT", status.recent));

	if (status.first_unseen_seq != 0) {
		client_send_line(client,
			t_strdup_printf("* OK [UNSEEN %u] First unseen.",
					status.first_unseen_seq));
	}

	client_send_line(client,
			 t_strdup_printf("* OK [UIDVALIDITY %u] UIDs valid",
					 status.uidvalidity));

	client_send_line(client,
			 t_strdup_printf("* OK [UIDNEXT %u] Predicted next UID",
					 status.uidnext));

	if (status.nonpermanent_modseqs) {
		client_send_line(client,
				 "* OK [NOMODSEQ] No permanent modsequences");
	} else {
		client_send_line(client,
			t_strdup_printf("* OK [HIGHESTMODSEQ %llu] Highest",
				(unsigned long long)status.highest_modseq));
		client->sync_last_full_modseq = status.highest_modseq;
	}

	if (ctx->qresync_uid_validity == status.uidvalidity &&
	    status.uidvalidity != 0) {
		if ((ret = select_qresync(ctx)) < 0) {
			client_send_storage_error(ctx->cmd,
				mailbox_get_storage(ctx->box));
			return -1;
		}
	} else {
		ret = 1;
	}
	return ret;
}

static void close_selected_mailbox(struct client *client)
{
	struct mailbox *box;

	if (client->mailbox == NULL)
		return;

	client_search_updates_free(client);
	box = client->mailbox;
	client->mailbox = NULL;

	mailbox_free(&box);
	/* CLOSED response is required by QRESYNC */
	client_send_line(client, "* OK [CLOSED] Previous mailbox closed.");
}

bool cmd_select_full(struct client_command_context *cmd, bool readonly)
{
	struct client *client = cmd->client;
	struct imap_select_context *ctx;
	const struct imap_arg *args, *list_args;
	const char *mailbox;
	int ret;

	/* <mailbox> [(optional parameters)] */
	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (!imap_arg_get_astring(args, &mailbox)) {
		client_send_command_error(cmd, "Invalid arguments.");
		close_selected_mailbox(client);
		return FALSE;
	}

	ctx = p_new(cmd->pool, struct imap_select_context, 1);
	ctx->cmd = cmd;
	ctx->ns = client_find_namespace(cmd, &mailbox);
	if (ctx->ns == NULL) {
		close_selected_mailbox(client);
		return TRUE;
	}

	if (imap_arg_get_list(&args[1], &list_args)) {
		if (!select_parse_options(ctx, list_args)) {
			select_context_free(ctx);
			close_selected_mailbox(client);
			return TRUE;
		}
	}

	i_assert(client->mailbox_change_lock == NULL);
	client->mailbox_change_lock = cmd;

	close_selected_mailbox(client);

	if (ctx->condstore) {
		/* Enable while no mailbox is opened to avoid sending
		   HIGHESTMODSEQ for previously opened mailbox */
		(void)client_enable(client, MAILBOX_FEATURE_CONDSTORE);
	}

	ret = select_open(ctx, mailbox, readonly);
	if (ret == 0)
		return FALSE;
	cmd_select_finish(ctx, ret);
	return TRUE;
}

bool cmd_select(struct client_command_context *cmd)
{
	return cmd_select_full(cmd, FALSE);
}
