/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-modifylog.h"
#include "index-storage.h"
#include "index-messageset.h"

struct messageset_context {
	struct index_mailbox *ibox;
	struct mail_index *index;

	const struct modify_log_expunge *expunges;
	int expunges_found;

	struct messageset_mail mail;
	unsigned int messages_count;
	unsigned int num1, num2;

	const char *messageset, *p;
	int uidset, skip_expunged;

	int first, ret;
	const char *error;
};

static int uidset_init(struct messageset_context *ctx);
static int seqset_init(struct messageset_context *ctx);

struct messageset_context *
index_messageset_init(struct index_mailbox *ibox,
		      const char *messageset, int uidset, int skip_expunged)
{
	struct messageset_context *ctx;

	i_assert(ibox->index->lock_type != MAIL_LOCK_UNLOCK);

	ctx = i_new(struct messageset_context, 1);
	ctx->ibox = ibox;
	ctx->index = ibox->index;
	ctx->messages_count = ibox->synced_messages_count;
	ctx->p = ctx->messageset = messageset;
	ctx->uidset = uidset;
	ctx->skip_expunged = skip_expunged;

	/* Reset index errors, we rely on it to check for failures */
	index_reset_error(ctx->index);

	return ctx;
}

struct messageset_context *
index_messageset_init_range(struct index_mailbox *ibox,
			    unsigned int num1, unsigned int num2, int uidset)
{
	struct messageset_context *ctx;

	ctx = index_messageset_init(ibox, NULL, uidset, TRUE);
	if (num1 <= num2) {
		ctx->num1 = num1;
		ctx->num2 = num2;
	} else {
		ctx->num1 = num2;
		ctx->num2 = num1;
	}
	return ctx;
}

int index_messageset_deinit(struct messageset_context *ctx)
{
	int ret = ctx->ret;

	if (ret == 0) {
		/* we just didn't go through all of them */
		ret = 1;
	}

	if (ret == 1 && ctx->expunges_found) {
		/* some of the messages weren't found */
		ret = 0;
	}

	if (ret == -1)
		mail_storage_set_index_error(ctx->ibox);
	else if (ret == -2) {
		/* user error */
		mail_storage_set_syntax_error(ctx->ibox->box.storage,
					      "%s", ctx->error);
	}

	i_free(ctx);
	return ret;
}

static unsigned int get_next_number(const char **str)
{
	unsigned int num;

	num = 0;
	while (**str != '\0') {
		if (**str < '0' || **str > '9')
			break;

		num = num*10 + (**str - '0');
		(*str)++;
	}

	return num;
}

static int messageset_parse_next(struct messageset_context *ctx)
{
	if (ctx->p == NULL) {
		/* num1..num2 already set.  */
		ctx->p = "";
		return TRUE;
	}

	if (*ctx->p == '*') {
		/* last message */
		ctx->num1 = (unsigned int)-1;
		ctx->p++;
	} else {
		ctx->num1 = get_next_number(&ctx->p);
		if (ctx->num1 == 0) {
			ctx->error = t_strconcat("Invalid messageset: ",
						 ctx->messageset, NULL);
			return FALSE;
		}
	}

	if (*ctx->p != ':')
		ctx->num2 = ctx->num1;
	else {
		/* first:last range */
		ctx->p++;

		if (*ctx->p == '*') {
			ctx->num2 = (unsigned int)-1;
			ctx->p++;
		} else {
			ctx->num2 = get_next_number(&ctx->p);
			if (ctx->num2 == 0) {
				ctx->error = t_strconcat("Invalid messageset: ",
							 ctx->messageset, NULL);
				return FALSE;
			}
		}
	}

	if (*ctx->p == ',')
		ctx->p++;
	else if (*ctx->p != '\0') {
		ctx->error = t_strdup_printf("Unexpected char '%c' "
					     "with messageset: %s",
					     *ctx->p, ctx->messageset);
		return FALSE;
	}

	if (ctx->num1 > ctx->num2) {
		/* swap, as specified by latest IMAP4rev1 draft */
		unsigned int temp = ctx->num1;
		ctx->num1 = ctx->num2;
		ctx->num2 = temp;
	}

	return TRUE;
}

static int uidset_init(struct messageset_context *ctx)
{
	unsigned int expunges_before;

	if (ctx->num1 == (unsigned int)-1) {
		struct mail_index_record *rec;

		rec = ctx->index->lookup(ctx->index, ctx->messages_count);
		ctx->num1 = rec == NULL ? 0 : rec->uid;
	}

	if (ctx->num2 == (unsigned int)-1) {
		ctx->num2 = ctx->index->header->next_uid-1;

		/* num1 might actually be larger, check */
		if (ctx->num1 > ctx->num2) {
			unsigned int temp = ctx->num1;
			ctx->num1 = ctx->num2;
			ctx->num2 = temp;
		}
	}

	/* get list of expunged messages in our range. */
	ctx->expunges = mail_modifylog_uid_get_expunges(ctx->index->modifylog,
							ctx->num1, ctx->num2,
							&expunges_before);
	if (ctx->expunges == NULL)
		return -1;

	if (ctx->expunges->uid1 != 0)
		ctx->expunges_found = TRUE;

	/* get the first message */
	ctx->mail.rec = ctx->index->lookup_uid_range(ctx->index,
						     ctx->num1, ctx->num2,
						     &ctx->mail.idx_seq);
	if (ctx->mail.rec == NULL) {
		return ctx->index->get_last_error(ctx->index) ==
			MAIL_INDEX_ERROR_NONE ? 1 : -1;
	}

	ctx->mail.client_seq = ctx->mail.idx_seq + expunges_before;
	return 0;
}

static int seqset_init(struct messageset_context *ctx)
{
	unsigned int expunges_before;

	if (ctx->num1 == (unsigned int)-1)
		ctx->num1 = ctx->messages_count;

	if (ctx->num2 == (unsigned int)-1)
		ctx->num2 = ctx->messages_count;

	/* get list of expunged messages in our range. the expunges_before
	   can be used to calculate the current real sequence position */
	ctx->expunges = mail_modifylog_seq_get_expunges(ctx->index->modifylog,
							ctx->num1, ctx->num2,
							&expunges_before);
	if (ctx->expunges == NULL)
		return -1;

	i_assert(expunges_before < ctx->num1);
	if (ctx->expunges->uid1 != 0)
		ctx->expunges_found = TRUE;

	/* get the first non-expunged message. note that if all messages
	   were expunged in the range, this points outside wanted range. */
	ctx->mail.idx_seq = ctx->num1 - expunges_before;
	ctx->mail.rec = ctx->index->lookup(ctx->index, ctx->mail.idx_seq);
	if (ctx->mail.rec == NULL) {
		return ctx->index->get_last_error(ctx->index) ==
			MAIL_INDEX_ERROR_NONE ? 1 : -1;
	}

	ctx->mail.client_seq = ctx->num1;
	return 0;
}

const struct messageset_mail *
index_messageset_next(struct messageset_context *ctx)
{
	struct messageset_mail *mail = &ctx->mail;
	int last;

	if (ctx->ret != 0)
		return NULL;

	if (!ctx->uidset)
		last = mail->rec == NULL || mail->client_seq >= ctx->num2;
	else
		last = mail->rec == NULL || mail->rec->uid >= ctx->num2;

	if (!last) {
		mail->rec = ctx->index->next(ctx->index, mail->rec);
		mail->client_seq++;
		mail->idx_seq++;

		if (mail->rec == NULL) {
			/* finished early (high UID larger than exists) */
			ctx->ret = 1;
			return NULL;
		}
	} else {
		do {
			if (ctx->p != NULL && *ctx->p == '\0') {
				/* finished */
				ctx->ret = 1;
				return NULL;
			}

			if (!messageset_parse_next(ctx)) {
				ctx->ret = -2;
				return NULL;
			}

			if (ctx->uidset)
				ctx->ret = uidset_init(ctx);
			else
				ctx->ret = seqset_init(ctx);

			if (ctx->expunges_found && !ctx->skip_expunged) {
				/* we wish to abort if there's any
				   expunged messages */
				ctx->ret = 1;
				return NULL;
			}
		} while (ctx->ret == 1);

		if (ctx->ret != 0)
			return NULL;
	}

	/* fix client_seq */
	while (ctx->expunges->uid1 != 0 &&
	       ctx->expunges->uid1 < mail->rec->uid) {
		i_assert(ctx->expunges->uid2 < mail->rec->uid);

		mail->client_seq += ctx->expunges->seq_count;
		ctx->expunges++;
	}

	i_assert(!(ctx->expunges->uid1 <= mail->rec->uid &&
		   ctx->expunges->uid2 >= mail->rec->uid));

	if (!ctx->uidset && mail->client_seq > ctx->num2) {
		/* finished this set - see if there's more */
		return index_messageset_next(ctx);
	}

	return mail;
}
