/* Copyright (C) 2002-2004 Timo Sirainen */

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

	struct mailbox_transaction_context *t;
	struct mailbox_sync_context *sync_ctx;

	struct mailbox_sync_rec sync_rec;
	uint32_t seq;

	unsigned int messages_count;

	int failed;
};

struct imap_sync_context *
imap_sync_init(struct client *client, struct mailbox *box,
	       enum mailbox_sync_flags flags)
{
	struct imap_sync_context *ctx;

	i_assert(client->mailbox == box);

	ctx = i_new(struct imap_sync_context, 1);
	ctx->client = client;
	ctx->box = box;

	ctx->sync_ctx = mailbox_sync_init(box, flags);
	ctx->t = mailbox_transaction_begin(box, FALSE);
	ctx->messages_count = client->messages_count;
	return ctx;
}

int imap_sync_deinit(struct imap_sync_context *ctx)
{
	struct mailbox_status status;

	if (mailbox_sync_deinit(ctx->sync_ctx, &status) < 0 || ctx->failed) {
		mailbox_transaction_rollback(ctx->t);
		i_free(ctx);
		return -1;
	}

	mailbox_transaction_commit(ctx->t, 0);

	t_push();

	ctx->client->messages_count = status.messages;
	if (status.messages != ctx->messages_count) {
		client_send_line(ctx->client,
			t_strdup_printf("* %u EXISTS", status.messages));
	}
	if (status.recent != ctx->client->recent_count) {
                ctx->client->recent_count = status.recent;
		client_send_line(ctx->client,
			t_strdup_printf("* %u RECENT", status.recent));
	}

	/*FIXME:client_save_keywords(&client->keywords, keywords, keywords_count);
	client_send_mailbox_flags(client, mailbox, keywords, keywords_count);*/

	t_pop();
	i_free(ctx);
	return 0;
}

int imap_sync_more(struct imap_sync_context *ctx)
{
	struct mail *mail;
	enum mail_flags flags;
	const char *const *keywords;
	string_t *str;
	int ret = 1;

	t_push();
	str = t_str_new(256);

	for (;;) {
		if (ctx->seq == 0) {
			/* get next one */
			ret = mailbox_sync_next(ctx->sync_ctx,
						&ctx->sync_rec);
			if (ret <= 0) {
				if (ret == 0) {
					/* all finished ok */
					ret = 1;
				}
				break;
			}
		}

		switch (ctx->sync_rec.type) {
		case MAILBOX_SYNC_TYPE_FLAGS:
		case MAILBOX_SYNC_TYPE_KEYWORDS:
			if (ctx->seq == 0)
				ctx->seq = ctx->sync_rec.seq1;

			for (; ctx->seq <= ctx->sync_rec.seq2; ctx->seq++) {
				mail = mailbox_fetch(ctx->t, ctx->seq,
						     MAIL_FETCH_FLAGS);

				flags = mail->get_flags(mail);
				keywords = mail->get_keywords(mail);

				str_truncate(str, 0);
				str_printfa(str, "* %u FETCH (FLAGS (",
					    ctx->seq);
				imap_write_flags(str, flags, keywords);
				str_append(str, "))");
				ret = client_send_line(ctx->client, str_c(str));
				if (ret <= 0) {
					t_pop();
					return ret;
				}
			}
			break;
		case MAILBOX_SYNC_TYPE_EXPUNGE:
			if (ctx->seq == 0) {
				ctx->seq = ctx->sync_rec.seq2;
				ctx->messages_count -=
					ctx->sync_rec.seq2 -
					ctx->sync_rec.seq1 + 1;
			}
			for (; ctx->seq >= ctx->sync_rec.seq1; ctx->seq--) {
				str_truncate(str, 0);
				str_printfa(str, "* %u EXPUNGE", ctx->seq);
				ret = client_send_line(ctx->client, str_c(str));
				if (ret <= 0) {
					t_pop();
					return ret;
				}
			}
			break;
		}
		ctx->seq = 0;
	}
	t_pop();
	return ret;
}

int imap_sync_nonselected(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct mailbox_sync_context *ctx;
        struct mailbox_sync_rec sync_rec;
	struct mailbox_status status;

	ctx = mailbox_sync_init(box, flags);
	while (mailbox_sync_next(ctx, &sync_rec) > 0)
		;
	return mailbox_sync_deinit(ctx, &status);
}

static int cmd_sync_continue(struct client_command_context *cmd)
{
	struct cmd_sync_context *ctx = cmd->context;

	if (imap_sync_more(ctx->sync_ctx) == 0)
		return FALSE;

	if (imap_sync_deinit(ctx->sync_ctx) < 0) {
		client_send_untagged_storage_error(cmd->client,
			mailbox_get_storage(cmd->client->mailbox));
	}

	client_send_tagline(cmd, ctx->tagline);
	return TRUE;
}

int cmd_sync(struct client_command_context *cmd, enum mailbox_sync_flags flags,
	     const char *tagline)
{
        struct cmd_sync_context *ctx;

	if (cmd->client->mailbox == NULL) {
		client_send_tagline(cmd, tagline);
		return TRUE;
	}

	if ((client_workarounds & WORKAROUND_DELAY_NEWMAIL) != 0 &&
	    (flags & MAILBOX_SYNC_FLAG_FAST) != 0)
		flags |= MAILBOX_SYNC_FLAG_NO_NEWMAIL;

	ctx = p_new(cmd->pool, struct cmd_sync_context, 1);
	ctx->tagline = p_strdup(cmd->pool, tagline);
	ctx->sync_ctx = imap_sync_init(cmd->client, cmd->client->mailbox,
				       flags);

	cmd->func = cmd_sync_continue;
	cmd->context = ctx;
	cmd->client->command_pending = TRUE;
	return cmd_sync_continue(cmd);
}
