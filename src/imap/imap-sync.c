/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "str.h"
#include "mail-storage.h"
#include "imap-util.h"
#include "imap-sync.h"
#include "commands.h"

struct cmd_sync_context {
	const char *tagline;
	struct imap_sync_context *sync_ctx;
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

	client_send_mailbox_flags(client, FALSE);
	return ctx;
}

int imap_sync_deinit(struct imap_sync_context *ctx)
{
	struct mailbox_status status;
	int ret;

	mail_free(&ctx->mail);

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

	str_truncate(str, 0);
	str_printfa(str, "* %u FETCH (", ctx->seq);
	if (ctx->imap_flags & IMAP_SYNC_FLAG_SEND_UID)
		str_printfa(str, "UID %u ", ctx->mail->uid);

	str_append(str, "FLAGS (");
	imap_write_flags(str, flags, keywords);
	str_append(str, "))");
	return client_send_line(ctx->client, str_c(str));
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

		switch (ctx->sync_rec.type) {
		case MAILBOX_SYNC_TYPE_FLAGS:
		case MAILBOX_SYNC_TYPE_KEYWORDS:
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
		}
		if (ret <= 0) {
			/* failure / buffer full */
			break;
		}

		ctx->seq = 0;
	}
	return ret;
}

static bool cmd_sync_continue(struct client_command_context *cmd)
{
	struct cmd_sync_context *ctx = cmd->context;
	int ret;

	if (cmd->cancel)
		ret = 0;
	else {
		if ((ret = imap_sync_more(ctx->sync_ctx)) == 0)
			return FALSE;
	}

	if (ret < 0)
		ctx->sync_ctx->failed = TRUE;

	cmd->client->syncing = FALSE;
	if (imap_sync_deinit(ctx->sync_ctx) < 0) {
		client_send_untagged_storage_error(cmd->client,
			mailbox_get_storage(cmd->client->mailbox));
	}

	if (!cmd->cancel)
		client_send_tagline(cmd, ctx->tagline);
	return TRUE;
}

bool cmd_sync(struct client_command_context *cmd, enum mailbox_sync_flags flags,
	      enum imap_sync_flags imap_flags, const char *tagline)
{
	struct client *client = cmd->client;
	struct cmd_sync_context *ctx;
	bool no_newmail;

	i_assert(client->output_lock == cmd || client->output_lock == NULL);

	if (client->mailbox == NULL ||
	    mailbox_transaction_get_count(client->mailbox) > 0) {
		client_send_tagline(cmd, tagline);
		return TRUE;
	}

	no_newmail = (client_workarounds & WORKAROUND_DELAY_NEWMAIL) != 0 &&
		(imap_flags & IMAP_SYNC_FLAG_SAFE) == 0;
	if (no_newmail) {
		/* expunges might break the client just as badly as new mail
		   notifications. */
		flags |= MAILBOX_SYNC_FLAG_NO_EXPUNGES;
	}

	ctx = p_new(cmd->pool, struct cmd_sync_context, 1);
	ctx->tagline = p_strdup(cmd->pool, tagline);
	ctx->sync_ctx = imap_sync_init(client, client->mailbox,
				       imap_flags, flags);
	ctx->sync_ctx->no_newmail = no_newmail;

	cmd->func = cmd_sync_continue;
	cmd->context = ctx;
	cmd->output_pending = TRUE;
	if (client->input_lock == cmd)
		client->input_lock = NULL;
	client->output_lock = NULL;
	client->syncing = TRUE;
	return cmd_sync_continue(cmd);
}
