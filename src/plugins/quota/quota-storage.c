/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "mail-storage-private.h"
#include "quota.h"
#include "quota-plugin.h"

#include <sys/stat.h>

#define QUOTA_CONTEXT(obj) \
	*((void **)array_idx_modifyable(&(obj)->module_contexts, \
					quota_storage_module_id))

struct quota_mail_storage {
	struct mail_storage_vfuncs super;
};

struct quota_mailbox {
	struct mailbox_vfuncs super;

	unsigned int save_hack:1;
};

struct quota_mail {
	struct mail_vfuncs super;
};

static unsigned int quota_storage_module_id = 0;
static bool quota_storage_module_id_set = FALSE;

static int quota_mail_expunge(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct quota_mail *qmail = QUOTA_CONTEXT(mail);
	struct quota_transaction_context *qt =
		QUOTA_CONTEXT(_mail->transaction);

	if (qmail->super.expunge(_mail) < 0)
		return -1;

	quota_free(qt, _mail);
	return 0;
}

static struct mailbox_transaction_context *
quota_mailbox_transaction_begin(struct mailbox *box,
				enum mailbox_transaction_flags flags)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(box);
	struct mailbox_transaction_context *t;
	struct quota_transaction_context *qt;

	t = qbox->super.transaction_begin(box, flags);
	qt = quota_transaction_begin(quota);

	array_idx_set(&t->module_contexts, quota_storage_module_id, &qt);
	return t;
}

static int
quota_mailbox_transaction_commit(struct mailbox_transaction_context *ctx,
				 enum mailbox_sync_flags flags)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(ctx->box);
	struct quota_transaction_context *qt = QUOTA_CONTEXT(ctx);

	if (qbox->super.transaction_commit(ctx, flags) < 0) {
		quota_transaction_rollback(qt);
		return -1;
	} else {
		(void)quota_transaction_commit(qt);
		return 0;
	}
}

static void
quota_mailbox_transaction_rollback(struct mailbox_transaction_context *ctx)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(ctx->box);
	struct quota_transaction_context *qt = QUOTA_CONTEXT(ctx);

	qbox->super.transaction_rollback(ctx);
	quota_transaction_rollback(qt);
}

static struct mail *
quota_mail_alloc(struct mailbox_transaction_context *t,
		 enum mail_fetch_field wanted_fields,
		 struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(t->box);
	struct quota_mail *qmail;
	struct mail *_mail;
	struct mail_private *mail;

	_mail = qbox->super.mail_alloc(t, wanted_fields, wanted_headers);
	mail = (struct mail_private *)_mail;

	qmail = p_new(mail->pool, struct quota_mail, 1);
	qmail->super = mail->v;

	mail->v.expunge = quota_mail_expunge;
	array_idx_set(&mail->module_contexts, quota_storage_module_id, &qmail);
	return _mail;
}

static int quota_check(struct mailbox_transaction_context *t, struct mail *mail)
{
	struct quota_transaction_context *qt = QUOTA_CONTEXT(t);
	int ret;
	bool too_large;

	ret = quota_try_alloc(qt, mail, &too_large);
	if (ret > 0)
		return 0;
	else if (ret == 0) {
		mail_storage_set_error(t->box->storage, "Quota exceeded");
		return -1;
	} else {
		mail_storage_set_error(t->box->storage,  "%s",
				       quota_last_error(quota));
		return -1;
	}
}

static int
quota_copy(struct mailbox_transaction_context *t, struct mail *mail,
	   enum mail_flags flags, struct mail_keywords *keywords,
	   struct mail *dest_mail)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(t->box);
	struct mail *copy_dest_mail;
	int ret;

	if (dest_mail != NULL)
		copy_dest_mail = dest_mail;
	else
                copy_dest_mail = mail_alloc(t, MAIL_FETCH_PHYSICAL_SIZE, NULL);

	qbox->save_hack = FALSE;
	if (qbox->super.copy(t, mail, flags, keywords, copy_dest_mail) < 0)
		return -1;

	/* if copying used saving internally, we already checked the quota
	   and set qbox->save_hack = TRUE. */
	ret = qbox->save_hack ? 0 : quota_check(t, copy_dest_mail);

	if (copy_dest_mail != dest_mail)
		mail_free(&copy_dest_mail);
	return ret;
}

static struct mail_save_context *
quota_save_init(struct mailbox_transaction_context *t,
		enum mail_flags flags, struct mail_keywords *keywords,
		time_t received_date, int timezone_offset,
		const char *from_envelope, struct istream *input,
		bool want_mail __attr_unused__)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(t->box);
	const struct stat *st;

	st = i_stream_stat(input, TRUE);
	if (st != NULL && st->st_size != -1) {
		/* FIXME: input size is known, check for quota.
		   the API needs changing however to do this, we'd need to
		   return failure before "+ OK".. */
	}

	/* note that we set want_mail = TRUE in here. */
	return qbox->super.save_init(t, flags, keywords, received_date,
				     timezone_offset, from_envelope,
				     input, TRUE);
}

static int quota_save_finish(struct mail_save_context *ctx,
			     struct mail *dest_mail)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(ctx->transaction->box);
	struct mail *save_dest_mail;
	int ret;

	if (dest_mail != NULL)
		save_dest_mail = dest_mail;
	else {
		save_dest_mail = mail_alloc(ctx->transaction,
					    MAIL_FETCH_PHYSICAL_SIZE, NULL);
	}

	if (qbox->super.save_finish(ctx, save_dest_mail) < 0)
		return -1;

	qbox->save_hack = TRUE;
	ret = quota_check(ctx->transaction, save_dest_mail);

	if (save_dest_mail != dest_mail)
		mail_free(&save_dest_mail);
	return ret;
}

static struct mailbox *
quota_mailbox_open(struct mail_storage *storage, const char *name,
		   struct istream *input, enum mailbox_open_flags flags)
{
	struct quota_mail_storage *qstorage = QUOTA_CONTEXT(storage);
	struct mailbox *box;
	struct quota_mailbox *qbox;

	box = qstorage->super.mailbox_open(storage, name, input, flags);
	if (box == NULL)
		return NULL;

	qbox = p_new(box->pool, struct quota_mailbox, 1);
	qbox->super = box->v;

	box->v.transaction_begin = quota_mailbox_transaction_begin;
	box->v.transaction_commit = quota_mailbox_transaction_commit;
	box->v.transaction_rollback = quota_mailbox_transaction_rollback;
	box->v.mail_alloc = quota_mail_alloc;
	box->v.save_init = quota_save_init;
	box->v.save_finish = quota_save_finish;
	box->v.copy = quota_copy;
	array_idx_set(&box->module_contexts, quota_storage_module_id, &qbox);
	return box;
}

void quota_mail_storage_created(struct mail_storage *storage)
{
	struct quota_mail_storage *qstorage;

	if (quota_next_hook_mail_storage_created != NULL)
		quota_next_hook_mail_storage_created(storage);

	qstorage = p_new(storage->pool, struct quota_mail_storage, 1);
	qstorage->super = storage->v;
	storage->v.mailbox_open = quota_mailbox_open;

	if (!quota_storage_module_id_set) {
		quota_storage_module_id = mail_storage_module_id++;
		quota_storage_module_id_set = TRUE;
	}

	array_idx_set(&storage->module_contexts,
		      quota_storage_module_id, &qstorage);
}
