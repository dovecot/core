/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "ostream.h"
#include "mail-storage.h"
#include "mail-user.h"
#include "imap-quote.h"
#include "imap-util.h"
#include "imap-sync.h"
#include "imap-commands.h"

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

	ARRAY_TYPE(seq_range) search_adds, search_removes;

	unsigned int messages_count;

	unsigned int failed:1;
	unsigned int no_newmail:1;
};

static void uids_to_seqs(struct mailbox *box, ARRAY_TYPE(seq_range) *uids)
{
	T_BEGIN {
		ARRAY_TYPE(seq_range) seqs;
		const struct seq_range *range;
		uint32_t seq1, seq2;

		t_array_init(&seqs, array_count(uids));
		array_foreach(uids, range) {
			mailbox_get_seq_range(box, range->seq1, range->seq2,
					      &seq1, &seq2);
			/* since we have to notify about expunged messages,
			   we expect that all the referenced UIDs exist */
			i_assert(seq1 != 0);
			i_assert(seq2 - seq1 == range->seq2 - range->seq1);

			seq_range_array_add_range(&seqs, seq1, seq2);
		}
		/* replace uids with seqs */
		array_clear(uids);
		array_append_array(uids, &seqs);

	} T_END;
}

static void
imap_sync_send_search_update(struct imap_sync_context *ctx,
			     const struct imap_search_update *update)
{
	string_t *cmd;

	mailbox_search_result_sync(update->result, &ctx->search_removes,
				   &ctx->search_adds);
	if (array_count(&ctx->search_adds) == 0 &&
	    array_count(&ctx->search_removes) == 0)
		return;

	cmd = t_str_new(256);
	str_append(cmd, "* ESEARCH (TAG ");
	imap_quote_append_string(cmd, update->tag, FALSE);
	str_append_c(cmd, ')');
	if (update->return_uids)
		str_append(cmd, " UID");
	else {
		/* convert to sequences */
		uids_to_seqs(ctx->client->mailbox, &ctx->search_removes);
		uids_to_seqs(ctx->client->mailbox, &ctx->search_adds);
	}

	if (array_count(&ctx->search_removes) != 0) {
		str_printfa(cmd, " REMOVEFROM (0 ");
		imap_write_seq_range(cmd, &ctx->search_removes);
		str_append_c(cmd, ')');
	}
	if (array_count(&ctx->search_adds) != 0) {
		str_printfa(cmd, " ADDTO (0 ");
		imap_write_seq_range(cmd, &ctx->search_adds);
		str_append_c(cmd, ')');
	}
	str_append(cmd, "\r\n");
	o_stream_send(ctx->client->output, str_data(cmd), str_len(cmd));
}

static void imap_sync_send_search_updates(struct imap_sync_context *ctx)
{
	const struct imap_search_update *update;

	if (!array_is_created(&ctx->client->search_updates))
		return;

	if (!array_is_created(&ctx->search_removes)) {
		i_array_init(&ctx->search_removes, 64);
		i_array_init(&ctx->search_adds, 128);
	}

	array_foreach(&ctx->client->search_updates, update) T_BEGIN {
		imap_sync_send_search_update(ctx, update);
	} T_END;
}

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

	/* make sure user can't DoS the system by causing Dovecot to create
	   tons of useless namespaces. */
	mail_user_drop_useless_namespaces(client->user);

	ctx->sync_ctx = mailbox_sync_init(box, flags);
	ctx->t = mailbox_transaction_begin(box, 0);
	ctx->mail = mail_alloc(ctx->t, MAIL_FETCH_FLAGS, 0);
	ctx->messages_count = client->messages_count;
	i_array_init(&ctx->tmp_keywords, client->keywords.announce_count + 8);

	if ((client->enabled_features & MAILBOX_FEATURE_QRESYNC) != 0) {
		i_array_init(&ctx->expunges, 128);
		/* always send UIDs in FETCH replies */
		ctx->imap_flags |= IMAP_SYNC_FLAG_SEND_UID;
	}

	client_send_mailbox_flags(client, FALSE);
	/* send search updates the first time after sync is initialized.
	   it now contains expunged messages that must be sent before
	   EXPUNGE replies. */
	imap_sync_send_search_updates(ctx);
	return ctx;
}

static void
imap_sync_send_highestmodseq(struct imap_sync_context *ctx,
			     const struct mailbox_status *status,
			     const struct mailbox_sync_status *sync_status,
			     struct client_command_context *sync_cmd)
{
	struct client *client = ctx->client;
	uint64_t send_modseq = 0;

	if (sync_status->sync_delayed_expunges &&
	    client->highest_fetch_modseq > client->sync_last_full_modseq) {
		/* if client updates highest-modseq using returned MODSEQs
		   it loses expunges. try to avoid this by sending it a lower
		   pre-expunge HIGHESTMODSEQ reply. */
		send_modseq = client->sync_last_full_modseq;
	} else if (!sync_status->sync_delayed_expunges &&
		   status->highest_modseq > client->sync_last_full_modseq &&
		   status->highest_modseq > client->highest_fetch_modseq) {
		/* we've probably sent some VANISHED or EXISTS replies which
		   increased the highest-modseq. notify the client about
		   this. */
		send_modseq = status->highest_modseq;
	}

	if (send_modseq == 0) {
		/* no sending */
	} else if (sync_cmd->sync != NULL && /* IDLE doesn't have ->sync */
		   strncmp(sync_cmd->sync->tagline, "OK ", 3) == 0 &&
		   sync_cmd->sync->tagline[3] != '[') {
		/* modify the tagged reply directly */
		sync_cmd->sync->tagline = p_strdup_printf(sync_cmd->pool,
			"OK [HIGHESTMODSEQ %llu] %s",
			(unsigned long long)send_modseq,
			sync_cmd->sync->tagline + 3);
	} else {
		/* send an untagged OK reply */
		client_send_line(client, t_strdup_printf(
			"* OK [HIGHESTMODSEQ %llu] Highest",
			(unsigned long long)send_modseq));
	}

	if (!sync_status->sync_delayed_expunges) {
		/* no delayed expunges, remember this for future */
		client->sync_last_full_modseq = status->highest_modseq;
	}
	client->highest_fetch_modseq = 0;
}

int imap_sync_deinit(struct imap_sync_context *ctx,
		     struct client_command_context *sync_cmd)
{
	struct client *client = ctx->client;
	struct mailbox_status status;
	struct mailbox_sync_status sync_status;
	int ret;

	mail_free(&ctx->mail);
	if (array_is_created(&ctx->expunges))
		array_free(&ctx->expunges);

	if (mailbox_sync_deinit(&ctx->sync_ctx, &sync_status) < 0 ||
	    ctx->failed) {
		mailbox_transaction_rollback(&ctx->t);
		array_free(&ctx->tmp_keywords);
		i_free(ctx);
		return -1;
	}
	mailbox_get_status(ctx->box, STATUS_UIDVALIDITY |
			   STATUS_MESSAGES | STATUS_RECENT |
			   STATUS_HIGHESTMODSEQ, &status);

	ret = mailbox_transaction_commit(&ctx->t);

	if (status.uidvalidity != client->uidvalidity) {
		/* most clients would get confused by this. disconnect them. */
		client_disconnect_with_error(client,
					     "Mailbox UIDVALIDITY changed");
	}
	if (!ctx->no_newmail) {
		if (status.messages < ctx->messages_count)
			i_panic("Message count decreased");
		client->messages_count = status.messages;
		if (status.messages != ctx->messages_count) {
			client_send_line(client,
				t_strdup_printf("* %u EXISTS", status.messages));
		}
		if (status.recent != client->recent_count &&
		    !ctx->no_newmail) {
			client->recent_count = status.recent;
			client_send_line(client,
				t_strdup_printf("* %u RECENT", status.recent));
		}
	}
	/* send search updates the second time after syncing in done.
	   now it contains added/removed messages. */
	imap_sync_send_search_updates(ctx);

	if ((client->enabled_features & MAILBOX_FEATURE_QRESYNC) != 0) {
		imap_sync_send_highestmodseq(ctx, &status, &sync_status,
					     sync_cmd);
	}

	if (array_is_created(&ctx->search_removes)) {
		array_free(&ctx->search_removes);
		array_free(&ctx->search_adds);
	}

	array_free(&ctx->tmp_keywords);
	i_free(ctx);
	return ret;
}

static void imap_sync_add_modseq(struct imap_sync_context *ctx, string_t *str)
{
	uint64_t modseq;

	modseq = mail_get_modseq(ctx->mail);
	if (ctx->client->highest_fetch_modseq < modseq)
		ctx->client->highest_fetch_modseq = modseq;
	str_printfa(str, "MODSEQ (%llu)", (unsigned long long)modseq);
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
		imap_sync_add_modseq(ctx, str);
		str_append_c(str, ' ');
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
	imap_sync_add_modseq(ctx, str);
	str_append_c(str, ')');
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
		start_uid = 0; prev_uid = (uint32_t)-1;
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

	/* finish syncing even when client has disconnected. otherwise our
	   internal state (ctx->messages_count) can get messed up and unless
	   we immediately stop handling all commands and syncs we could end up
	   assert-crashing. */
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
				if (ret == 0)
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
				if (ret == 0)
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
				if (ret == 0)
					break;

				ret = imap_sync_send_modseq(ctx, str);
			}
			break;
		}
		if (ret == 0) {
			/* buffer full */
			break;
		}

		ctx->seq = 0;
	}
	if (array_is_created(&ctx->expunges))
		imap_sync_vanished(ctx);
	return ret;
}

bool imap_sync_is_allowed(struct client *client)
{
	if (client->syncing)
		return FALSE;

	if (client->mailbox != NULL &&
	    mailbox_transaction_get_count(client->mailbox) > 0)
		return FALSE;

	return TRUE;
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
	struct client_command_context *cmd, *prev;
	struct client *client = sync_cmd->client;
	struct imap_sync_context *ctx = sync_cmd->context;
	int ret;

	i_assert(ctx->client == client);

	if ((ret = imap_sync_more(ctx)) == 0)
		return FALSE;
	if (ret < 0)
		ctx->failed = TRUE;

	client->syncing = FALSE;
	if (imap_sync_deinit(ctx, sync_cmd) < 0) {
		client_send_untagged_storage_error(client,
			mailbox_get_storage(client->mailbox));
	}
	sync_cmd->context = NULL;

	/* Finish all commands that waited for this sync. Go through the queue
	   backwards, so that tagged replies are sent in the same order as
	   they were received. This fixes problems with clients that rely on
	   this (Apple Mail 3.2) */
	for (cmd = client->command_queue; cmd->next != NULL; cmd = cmd->next) ;
	for (; cmd != NULL; cmd = prev) {
		prev = cmd->prev;

		if (cmd->state == CLIENT_COMMAND_STATE_WAIT_SYNC &&
		    cmd != sync_cmd &&
		    cmd->sync->counter+1 == client->sync_counter) {
			if (cmd_finish_sync(cmd))
				client_command_free(&cmd);
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
	i_assert(noexpunges_count == 0 || noexpunges_count == count);
	if (fast_count != count)
		*flags_r &= ~MAILBOX_SYNC_FLAG_FAST;

	i_assert((*flags_r & MAILBOX_SYNC_FLAG_FIX_INCONSISTENT) == 0);
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

	no_newmail = (client->set->parsed_workarounds & WORKAROUND_DELAY_NEWMAIL) != 0 &&
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

	client_command_free(&sync_cmd);
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
	struct client_command_context *cmd, *prev;
	bool ret = FALSE;

	if (client->command_queue == NULL)
		return FALSE;

	for (cmd = client->command_queue; cmd->next != NULL; cmd = cmd->next) ;
	for (; cmd != NULL; cmd = prev) {
		prev = cmd->next;

		if (cmd->state == CLIENT_COMMAND_STATE_WAIT_SYNC &&
		    (cmd->sync->flags & MAILBOX_SYNC_FLAG_FAST) != 0) {
			if (cmd_finish_sync(cmd)) {
				client_command_free(&cmd);
				ret = TRUE;
			}
		}
	}
	return ret;
}

bool cmd_sync_delayed(struct client *client)
{
	struct client_command_context *cmd, *first_expunge, *first_nonexpunge;

	if (client->output_lock != NULL) {
		/* wait until we can send output to client */
		return FALSE;
	}

	if (!imap_sync_is_allowed(client)) {
		/* wait until mailbox can be synced */
		return cmd_sync_drop_fast(client);
	}

	/* separate syncs that can send expunges from those that can't */
	first_expunge = first_nonexpunge = NULL;
	for (cmd = client->command_queue; cmd != NULL; cmd = cmd->next) {
		if (cmd->sync != NULL &&
		    cmd->sync->counter == client->sync_counter) {
			if (cmd->sync->flags & MAILBOX_SYNC_FLAG_NO_EXPUNGES) {
				if (first_nonexpunge == NULL)
					first_nonexpunge = cmd;
			} else {
				if (first_expunge == NULL)
					first_expunge = cmd;
			}
		}
	}
	if (first_expunge != NULL && first_nonexpunge != NULL) {
		/* sync expunges after nonexpunges */
		for (cmd = first_expunge; cmd != NULL; cmd = cmd->next) {
			if (cmd->sync != NULL &&
			    cmd->sync->counter == client->sync_counter &&
			    (cmd->sync->flags &
			     MAILBOX_SYNC_FLAG_NO_EXPUNGES) == 0)
				cmd->sync->counter++;
		}
		first_expunge = NULL;
	}
	cmd = first_nonexpunge != NULL ? first_nonexpunge : first_expunge;

	if (cmd == NULL)
		return cmd_sync_drop_fast(client);
	i_assert(client->mailbox != NULL);
	return cmd_sync_client(cmd);
}
