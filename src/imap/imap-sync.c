/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "str.h"
#include "ostream.h"
#include "mail-storage.h"
#include "imap-util.h"
#include "imap-sync.h"
#include "commands.h"

struct client_sync_context {
	/* if multiple commands are in progress, we may need to wait for them
	   to finish before syncing mailbox. */
	unsigned int counter;
	enum mailbox_sync_flags flags;
	enum imap_sync_flags imap_flags;
	const char *tagline;
	imap_sync_callback_t *callback;
};

struct imap_sync_context {
	struct client *client;
	struct mailbox *box;
        enum imap_sync_flags imap_flags;

	struct mailbox_transaction_context *t;
	struct mailbox_sync_context *sync_ctx;
	struct mail *mail;

	struct mailbox_sync_rec sync_rec;
	ARRAY_TYPE(keywords) tmp_keywords;
	ARRAY_TYPE(seq_range) expunges;
	uint32_t seq;

	unsigned int messages_count;

	unsigned int failed:1;
	unsigned int no_newmail:1;
};

struct imap_sync_context *
imap_sync_init(struct client *client, struct mailbox *box,
	       enum imap_sync_flags imap_flags, enum mailbox_sync_flags flags)
{
	struct imap_sync_context *ctx;

	i_assert(client->mailbox == box);

	ctx = i_new(struct imap_sync_context, 1);
	ctx->client = client;
	ctx->box = box;
	ctx->imap_flags = imap_flags;

	ctx->sync_ctx = mailbox_sync_init(box, flags);
	ctx->t = mailbox_transaction_begin(box, 0);
	ctx->mail = mail_alloc(ctx->t, MAIL_FETCH_FLAGS, 0);
	ctx->messages_count = client->messages_count;
	i_array_init(&ctx->tmp_keywords, client->keywords.announce_count + 8);

	if ((client->enabled_features & MAILBOX_FEATURE_QRESYNC) != 0)
		i_array_init(&ctx->expunges, 128);

	client_send_mailbox_flags(client, FALSE);
	return ctx;
}

int imap_sync_deinit(struct imap_sync_context *ctx)
{
	struct mailbox_status status;
	int ret;

	mail_free(&ctx->mail);
	if (array_is_created(&ctx->expunges))
		array_free(&ctx->expunges);

	if (mailbox_sync_deinit(&ctx->sync_ctx, STATUS_UIDVALIDITY |
				STATUS_MESSAGES | STATUS_RECENT, &status) < 0 ||
	    ctx->failed) {
		mailbox_transaction_rollback(&ctx->t);
		i_free(ctx);
		return -1;
	}

	ret = mailbox_transaction_commit(&ctx->t);

	if (status.uidvalidity != ctx->client->uidvalidity) {
		/* most clients would get confused by this. disconnect them. */
		client_disconnect_with_error(ctx->client,
					     "Mailbox UIDVALIDITY changed");
	}
	if (!ctx->no_newmail) {
		if (status.messages < ctx->messages_count)
			i_panic("Message count decreased");
		ctx->client->messages_count = status.messages;
		if (status.messages != ctx->messages_count) {
			client_send_line(ctx->client,
				t_strdup_printf("* %u EXISTS", status.messages));
		}
		if (status.recent != ctx->client->recent_count &&
		    !ctx->no_newmail) {
			ctx->client->recent_count = status.recent;
			client_send_line(ctx->client,
				t_strdup_printf("* %u RECENT", status.recent));
		}
	}

	array_free(&ctx->tmp_keywords);
	i_free(ctx);
	return ret;
}

static int imap_sync_send_flags(struct imap_sync_context *ctx, string_t *str)
{
	enum mail_flags flags;
	const char *const *keywords;

	mail_set_seq(ctx->mail, ctx->seq);
	flags = mail_get_flags(ctx->mail);
	keywords = client_get_keyword_names(ctx->client, &ctx->tmp_keywords,
			mail_get_keyword_indexes(ctx->mail));

	if ((flags & MAIL_DELETED) != 0)
		ctx->client->sync_seen_deletes = TRUE;

	str_truncate(str, 0);
	str_printfa(str, "* %u FETCH (", ctx->seq);
	if (ctx->imap_flags & IMAP_SYNC_FLAG_SEND_UID)
		str_printfa(str, "UID %u ", ctx->mail->uid);
	if ((mailbox_get_enabled_features(ctx->box) &
	     MAILBOX_FEATURE_CONDSTORE) != 0) {
		str_printfa(str, "MODSEQ %llu ",
			    (unsigned long long)mail_get_modseq(ctx->mail));
	}
	str_append(str, "FLAGS (");
	imap_write_flags(str, flags, keywords);
	str_append(str, "))");
	return client_send_line(ctx->client, str_c(str));
}

static int imap_sync_send_modseq(struct imap_sync_context *ctx, string_t *str)
{
	mail_set_seq(ctx->mail, ctx->seq);

	str_truncate(str, 0);
	str_printfa(str, "* %u FETCH (", ctx->seq);
	if (ctx->imap_flags & IMAP_SYNC_FLAG_SEND_UID)
		str_printfa(str, "UID %u ", ctx->mail->uid);
	str_printfa(str, "MODSEQ %llu)",
		    (unsigned long long)mail_get_modseq(ctx->mail));
	return client_send_line(ctx->client, str_c(str));
}

static void imap_sync_vanished(struct imap_sync_context *ctx)
{
	const struct seq_range *seqs;
	unsigned int i, count;
	string_t *line;
	uint32_t seq, prev_uid, start_uid;
	bool comma = FALSE;

	/* Convert expunge sequences to UIDs and send them in VANISHED line. */
	seqs = array_get(&ctx->expunges, &count);
	if (count == 0)
		return;

	line = t_str_new(256);
	str_append(line, "* VANISHED ");
	for (i = 0; i < count; i++) {
		prev_uid = start_uid = 0;
		for (seq = seqs[i].seq1; seq <= seqs[i].seq2; seq++) {
			mail_set_seq(ctx->mail, seq);
			if (prev_uid + 1 != ctx->mail->uid) {
				if (start_uid != 0) {
					if (!comma)
						comma = TRUE;
					else
						str_append_c(line, ',');
					str_printfa(line, "%u", start_uid);
					if (start_uid != prev_uid) {
						str_printfa(line, ":%u",
							    prev_uid);
					}
				}
				start_uid = ctx->mail->uid;
			}
			prev_uid = ctx->mail->uid;
		}
		if (!comma)
			comma = TRUE;
		else
			str_append_c(line, ',');
		str_printfa(line, "%u", start_uid);
		if (start_uid != prev_uid)
			str_printfa(line, ":%u", prev_uid);
	}
	str_append(line, "\r\n");
	o_stream_send(ctx->client->output, str_data(line), str_len(line));
}

int imap_sync_more(struct imap_sync_context *ctx)
{
	string_t *str;
	int ret = 1;

	str = t_str_new(256);
	for (;;) {
		if (ctx->seq == 0) {
			/* get next one */
			if (!mailbox_sync_next(ctx->sync_ctx, &ctx->sync_rec)) {
				/* finished */
				ret = 1;
				break;
			}
		}

		if (ctx->sync_rec.seq2 > ctx->messages_count) {
			/* don't send change notifications of messages we
			   haven't even announced to client yet */
			if (ctx->sync_rec.seq1 > ctx->messages_count) {
				ctx->seq = 0;
				continue;
			}
			ctx->sync_rec.seq2 = ctx->messages_count;
		}

		/* EXPUNGEs must come last */
		i_assert(!array_is_created(&ctx->expunges) ||
			 array_count(&ctx->expunges) == 0 ||
			 ctx->sync_rec.type == MAILBOX_SYNC_TYPE_EXPUNGE);
		switch (ctx->sync_rec.type) {
		case MAILBOX_SYNC_TYPE_FLAGS:
			if (ctx->seq == 0)
				ctx->seq = ctx->sync_rec.seq1;

			ret = 1;
			for (; ctx->seq <= ctx->sync_rec.seq2; ctx->seq++) {
				if (ret <= 0)
					break;

				ret = imap_sync_send_flags(ctx, str);
			}
			break;
		case MAILBOX_SYNC_TYPE_EXPUNGE:
			ctx->client->sync_seen_expunges = TRUE;
			if (array_is_created(&ctx->expunges)) {
				/* Use a single VANISHED line */
				seq_range_array_add_range(&ctx->expunges,
							  ctx->sync_rec.seq1,
							  ctx->sync_rec.seq2);
				ctx->messages_count -=
					ctx->sync_rec.seq2 -
					ctx->sync_rec.seq1 + 1;
				break;
			}
			if (ctx->seq == 0)
				ctx->seq = ctx->sync_rec.seq2;
			ret = 1;
			for (; ctx->seq >= ctx->sync_rec.seq1; ctx->seq--) {
				if (ret <= 0)
					break;

				str_truncate(str, 0);
				str_printfa(str, "* %u EXPUNGE", ctx->seq);
				ret = client_send_line(ctx->client, str_c(str));
			}
			if (ctx->seq < ctx->sync_rec.seq1) {
				/* update only after we're finished, so that
				   the seq2 > messages_count check above
				   doesn't break */
				ctx->messages_count -=
					ctx->sync_rec.seq2 -
					ctx->sync_rec.seq1 + 1;
			}
			break;
		case MAILBOX_SYNC_TYPE_MODSEQ:
			if ((ctx->client->enabled_features &
			     MAILBOX_FEATURE_CONDSTORE) == 0)
				break;

			if (ctx->seq == 0)
				ctx->seq = ctx->sync_rec.seq1;

			ret = 1;
			for (; ctx->seq <= ctx->sync_rec.seq2; ctx->seq++) {
				if (ret <= 0)
					break;

				ret = imap_sync_send_modseq(ctx, str);
			}
			break;
		}
		if (ret <= 0) {
			/* failure / buffer full */
			break;
		}

		ctx->seq = 0;
	}
	if (array_is_created(&ctx->expunges))
		imap_sync_vanished(ctx);
	return ret;
}

static bool cmd_finish_sync(struct client_command_context *cmd)
{
	if (cmd->sync->callback != NULL)
		return cmd->sync->callback(cmd);
	else {
		client_send_tagline(cmd, cmd->sync->tagline);
		return TRUE;
	}
}

static bool cmd_sync_continue(struct client_command_context *sync_cmd)
{
	struct client_command_context *cmd;
	struct client *client = sync_cmd->client;
	struct imap_sync_context *ctx = sync_cmd->context;
	int ret;

	i_assert(ctx->client == client);

	if ((ret = imap_sync_more(ctx)) == 0)
		return FALSE;
	if (ret < 0)
		ctx->failed = TRUE;

	client->syncing = FALSE;
	if (imap_sync_deinit(ctx) < 0) {
		client_send_untagged_storage_error(client,
			mailbox_get_storage(client->mailbox));
	}
	sync_cmd->context = NULL;

	/* finish all commands that waited for this sync */
	for (cmd = client->command_queue; cmd != NULL; cmd = cmd->next) {
		if (cmd->state == CLIENT_COMMAND_STATE_WAIT_SYNC &&
		    cmd != sync_cmd &&
		    cmd->sync->counter+1 == client->sync_counter) {
			if (cmd_finish_sync(cmd))
				client_command_free(cmd);
		}
	}
	return cmd_finish_sync(sync_cmd);
}

static void get_common_sync_flags(struct client *client,
				  enum mailbox_sync_flags *flags_r,
				  enum imap_sync_flags *imap_flags_r)
{
	struct client_command_context *cmd;
	unsigned int count = 0, fast_count = 0, noexpunges_count = 0;

	*flags_r = 0;
	*imap_flags_r = 0;

	for (cmd = client->command_queue; cmd != NULL; cmd = cmd->next) {
		if (cmd->sync != NULL &&
		    cmd->sync->counter == client->sync_counter) {
			if ((cmd->sync->flags & MAILBOX_SYNC_FLAG_FAST) != 0)
				fast_count++;
			if (cmd->sync->flags & MAILBOX_SYNC_FLAG_NO_EXPUNGES)
				noexpunges_count++;
			*flags_r |= cmd->sync->flags;
			*imap_flags_r |= cmd->sync->imap_flags;
			count++;
		}
	}
	if (fast_count != count)
		*flags_r &= ~MAILBOX_SYNC_FLAG_FAST;
	if (noexpunges_count != count)
		*flags_r &= ~MAILBOX_SYNC_FLAG_NO_EXPUNGES;

	i_assert((*flags_r & (MAILBOX_SYNC_AUTO_STOP |
			      MAILBOX_SYNC_FLAG_FIX_INCONSISTENT)) == 0);
}

static bool cmd_sync_client(struct client_command_context *sync_cmd)
{
	struct client *client = sync_cmd->client;
	struct imap_sync_context *ctx;
	enum mailbox_sync_flags flags;
	enum imap_sync_flags imap_flags;
	bool no_newmail;

	/* there may be multiple commands waiting. use their combined flags */
	get_common_sync_flags(client, &flags, &imap_flags);
	client->sync_counter++;

	no_newmail = (client_workarounds & WORKAROUND_DELAY_NEWMAIL) != 0 &&
		(imap_flags & IMAP_SYNC_FLAG_SAFE) == 0;
	if (no_newmail) {
		/* expunges might break the client just as badly as new mail
		   notifications. */
		flags |= MAILBOX_SYNC_FLAG_NO_EXPUNGES;
	}

	client->syncing = TRUE;

	ctx = imap_sync_init(client, client->mailbox, imap_flags, flags);
	ctx->no_newmail = no_newmail;

	/* handle the syncing using sync_cmd. it doesn't actually matter which
	   one of the pending commands it is. */
	sync_cmd->func = cmd_sync_continue;
	sync_cmd->context = ctx;
	sync_cmd->state = CLIENT_COMMAND_STATE_WAIT_OUTPUT;
	if (!cmd_sync_continue(sync_cmd)) {
		o_stream_set_flush_pending(client->output, TRUE);
		return FALSE;
	}

	client_command_free(sync_cmd);
	(void)cmd_sync_delayed(client);
	return TRUE;
}

static bool
cmd_sync_full(struct client_command_context *cmd, enum mailbox_sync_flags flags,
	      enum imap_sync_flags imap_flags, const char *tagline,
	      imap_sync_callback_t *callback)
{
	struct client *client = cmd->client;

	i_assert(client->output_lock == cmd || client->output_lock == NULL);

	if (cmd->cancel)
		return TRUE;

	if (client->mailbox == NULL) {
		/* no mailbox selected, no point in delaying the sync */
		i_assert(callback == NULL);
		client_send_tagline(cmd, tagline);
		return TRUE;
	}

	cmd->sync = p_new(cmd->pool, struct client_sync_context, 1);
	cmd->sync->counter = client->sync_counter;
	cmd->sync->flags = flags;
	cmd->sync->imap_flags = imap_flags;
	cmd->sync->tagline = p_strdup(cmd->pool, tagline);
	cmd->sync->callback = callback;
	cmd->state = CLIENT_COMMAND_STATE_WAIT_SYNC;

	cmd->func = NULL;
	cmd->context = NULL;

	client->output_lock = NULL;
	if (client->input_lock == cmd)
		client->input_lock = NULL;
	return FALSE;
}

bool cmd_sync(struct client_command_context *cmd, enum mailbox_sync_flags flags,
	      enum imap_sync_flags imap_flags, const char *tagline)
{
	return cmd_sync_full(cmd, flags, imap_flags, tagline, NULL);
}

bool cmd_sync_callback(struct client_command_context *cmd,
		       enum mailbox_sync_flags flags,
		       enum imap_sync_flags imap_flags,
		       imap_sync_callback_t *callback)
{
	return cmd_sync_full(cmd, flags, imap_flags, NULL, callback);
}

static bool cmd_sync_drop_fast(struct client *client)
{
	struct client_command_context *cmd, *next;
	bool ret = FALSE;

	for (cmd = client->command_queue; cmd != NULL; cmd = next) {
		next = cmd->next;

		if (cmd->state == CLIENT_COMMAND_STATE_WAIT_SYNC &&
		    (cmd->sync->flags & MAILBOX_SYNC_FLAG_FAST) != 0) {
			if (cmd_finish_sync(cmd)) {
				client_command_free(cmd);
				ret = TRUE;
			}
		}
	}
	return ret;
}

bool cmd_sync_delayed(struct client *client)
{
	struct client_command_context *cmd;

	if (client->output_lock != NULL) {
		/* wait until we can send output to client */
		return FALSE;
	}

	if (client->syncing ||
	    (client->mailbox != NULL &&
	     mailbox_transaction_get_count(client->mailbox) > 0)) {
		/* wait until mailbox can be synced */
		return cmd_sync_drop_fast(client);
	}

	/* find a command that we can sync */
	for (cmd = client->command_queue; cmd != NULL; cmd = cmd->next) {
		if (cmd->state == CLIENT_COMMAND_STATE_WAIT_SYNC) {
			if (cmd->sync->counter == client->sync_counter)
				break;
		}
	}

	if (cmd == NULL)
		return cmd_sync_drop_fast(client);
	i_assert(client->mailbox != NULL);
	return cmd_sync_client(cmd);
}
