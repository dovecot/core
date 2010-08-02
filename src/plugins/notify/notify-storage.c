#include "lib.h"
#include "array.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "notify-plugin-private.h"

#define NOTIFY_CONTEXT(obj) \
	MODULE_CONTEXT(obj, notify_storage_module)
#define NOTIFY_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, notify_mail_module)

struct notify_transaction_context {
	union mailbox_transaction_module_context module_ctx;
	struct mail *tmp_mail;
};

static MODULE_CONTEXT_DEFINE_INIT(notify_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(notify_mail_module,
				  &mail_module_register);

static void
notify_mail_expunge(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *lmail = NOTIFY_MAIL_CONTEXT(mail);
	
	notify_contexts_mail_expunge(_mail);
	lmail->super.expunge(_mail);
}

static void
notify_mail_update_flags(struct mail *_mail, enum modify_type modify_type,
			 enum mail_flags flags)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *lmail = NOTIFY_MAIL_CONTEXT(mail);
	enum mail_flags old_flags, new_flags;

	old_flags = mail_get_flags(_mail);
	lmail->super.update_flags(_mail, modify_type, flags);
	new_flags = mail_get_flags(_mail);

	if ((old_flags ^ new_flags) == 0) 
		return;
	
	notify_contexts_mail_update_flags(_mail, old_flags);
}

static void
notify_mail_update_keywords(struct mail *_mail, enum modify_type modify_type,
			    struct mail_keywords *keywords)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *lmail = NOTIFY_MAIL_CONTEXT(mail);
	const char *const *old_keywords, *const *new_keywords;
	unsigned int i;

	old_keywords = mail_get_keywords(_mail);
	lmail->super.update_keywords(_mail, modify_type, keywords);
	new_keywords = mail_get_keywords(_mail);

	for (i = 0; old_keywords[i] != NULL && new_keywords[i] != NULL; i++) {
		if (strcmp(old_keywords[i], new_keywords[i]) != 0)
			break;
	}

	if (old_keywords[i] == NULL && new_keywords[i] == NULL) 
		return;

	notify_contexts_mail_update_keywords(_mail, old_keywords);
}

static void notify_mail_allocated(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_vfuncs *v = mail->vlast;
	union mail_module_context *lmail;

	lmail = p_new(mail->pool, union mail_module_context, 1);
	lmail->super = *v;
	mail->vlast = &lmail->super;

	v->expunge = notify_mail_expunge;
	v->update_flags = notify_mail_update_flags;
	v->update_keywords = notify_mail_update_keywords;
	MODULE_CONTEXT_SET_SELF(mail, notify_mail_module, lmail);
}

static int
notify_copy(struct mail_save_context *ctx, struct mail *mail)
{
	struct notify_transaction_context *lt =
		NOTIFY_CONTEXT(ctx->transaction);
	union mailbox_module_context *lbox =
		NOTIFY_CONTEXT(ctx->transaction->box);
	int ret;

	if (ctx->dest_mail == NULL) {
		if (lt->tmp_mail == NULL)
			lt->tmp_mail = mail_alloc(ctx->transaction, 0, NULL);
		ctx->dest_mail = lt->tmp_mail;
	}

	if ((ret = lbox->super.copy(ctx, mail)) == 0)
		notify_contexts_mail_copy(mail, ctx->dest_mail);
	return ret;
}

static int
notify_save_begin(struct mail_save_context *ctx, struct istream *input)
{
	struct notify_transaction_context *lt =
		NOTIFY_CONTEXT(ctx->transaction);
	union mailbox_module_context *lbox =
		NOTIFY_CONTEXT(ctx->transaction->box);

	if (ctx->dest_mail == NULL) {
		if (lt->tmp_mail == NULL)
			lt->tmp_mail = mail_alloc(ctx->transaction, 0, NULL);
		ctx->dest_mail = lt->tmp_mail;
	}
	return lbox->super.save_begin(ctx, input);
}

static int
notify_save_finish(struct mail_save_context *ctx)
{
	union mailbox_module_context *lbox =
		NOTIFY_CONTEXT(ctx->transaction->box);
	struct mail *dest_mail = ctx->copying ? NULL : ctx->dest_mail;

	if (lbox->super.save_finish(ctx) < 0)
		return -1;
	if (dest_mail != NULL)
		notify_contexts_mail_save(dest_mail);
	return 0;
}

static struct mailbox_transaction_context *
notify_transaction_begin(struct mailbox *box,
			 enum mailbox_transaction_flags flags)
{
	union mailbox_module_context *lbox = NOTIFY_CONTEXT(box);
	struct mailbox_transaction_context *t;
	struct notify_transaction_context *lt;
	
	t = lbox->super.transaction_begin(box, flags);

	lt = i_new(struct notify_transaction_context, 1);
	MODULE_CONTEXT_SET(t, notify_storage_module, lt);

	notify_contexts_mail_transaction_begin(t);
	return t;
}

static int
notify_transaction_commit(struct mailbox_transaction_context *t,
			  struct mail_transaction_commit_changes *changes_r)
{
	struct notify_transaction_context *lt = NOTIFY_CONTEXT(t);
	union mailbox_module_context *lbox = NOTIFY_CONTEXT(t->box);

	if (lt->tmp_mail != NULL)
		mail_free(&lt->tmp_mail);
	i_free(lt);

	if ((lbox->super.transaction_commit(t, changes_r)) < 0) {
		notify_contexts_mail_transaction_rollback(t);
		return -1;
	}

	notify_contexts_mail_transaction_commit(t, changes_r);
	return 0;
}

static void
notify_transaction_rollback(struct mailbox_transaction_context *t)
{
	struct notify_transaction_context *lt = NOTIFY_CONTEXT(t);
	union mailbox_module_context *lbox = NOTIFY_CONTEXT(t->box);

	if (lt->tmp_mail != NULL)
		mail_free(&lt->tmp_mail);
	i_free(lt);
	
	notify_contexts_mail_transaction_rollback(t);
	lbox->super.transaction_rollback(t);
}

static int
notify_mailbox_create(struct mailbox *box, const struct mailbox_update *update,
		      bool directory)
{
	union mailbox_module_context *lbox = NOTIFY_CONTEXT(box);

	if (lbox->super.create(box, update, directory) < 0)
		return -1;

	notify_contexts_mailbox_create(box);
	return 0;
}

static int
notify_mailbox_delete(struct mailbox *box)
{
	union mailbox_module_context *lbox = NOTIFY_CONTEXT(box);

	notify_contexts_mailbox_delete_begin(box);
	if (lbox->super.delete(box) < 0) {
		notify_contexts_mailbox_delete_rollback();
		return -1;
	}
	notify_contexts_mailbox_delete_commit(box);
	return 0;
}

static int
notify_mailbox_rename(struct mailbox *src, struct mailbox *dest,
		      bool rename_children)
{
	union mailbox_module_context *lbox = NOTIFY_CONTEXT(src);

	if (lbox->super.rename(src, dest, rename_children) < 0)
		return -1;

	notify_contexts_mailbox_rename(src, dest, rename_children);
	return 0;
}

static void notify_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	union mailbox_module_context *lbox;

	lbox = p_new(box->pool, union mailbox_module_context, 1);
	lbox->super = *v;
	box->vlast = &lbox->super;

	v->copy = notify_copy;
	v->save_begin = notify_save_begin;
	v->save_finish = notify_save_finish;
	v->transaction_begin = notify_transaction_begin;
	v->transaction_commit = notify_transaction_commit;
	v->transaction_rollback = notify_transaction_rollback;
	v->create = notify_mailbox_create;
	v->delete = notify_mailbox_delete;
	v->rename = notify_mailbox_rename;
	MODULE_CONTEXT_SET_SELF(box, notify_storage_module, lbox);
}

static struct mail_storage_hooks notify_mail_storage_hooks = {
	.mailbox_allocated = notify_mailbox_allocated,
	.mail_allocated = notify_mail_allocated
};

void notify_plugin_init_storage(struct module *module)
{
	mail_storage_hooks_add(module, &notify_mail_storage_hooks);
}

void notify_plugin_deinit_storage(void)
{
	mail_storage_hooks_remove(&notify_mail_storage_hooks);
}
