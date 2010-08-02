#include "lib.h"
#include "llist.h"
#include "mail-storage.h"
#include "notify-plugin-private.h"

#include <stdlib.h>

struct notify_mail_txn {
	struct notify_mail_txn *prev, *next;
	struct mailbox_transaction_context *parent_mailbox_txn;
	struct mail *tmp_mail;
	void *txn;
};

struct notify_context {
	struct notify_context *prev, *next;
	struct notify_vfuncs v;
	struct notify_mail_txn *mail_txn_list;
	void *mailbox_delete_txn;
};

const char *notify_plugin_version = DOVECOT_VERSION;
static struct notify_context *ctx_list = NULL;

static struct notify_mail_txn *
notify_context_find_mail_txn(struct notify_context *ctx,
			     struct mailbox_transaction_context *t)
{
	struct notify_mail_txn *mail_txn = ctx->mail_txn_list;

	for (; mail_txn != NULL; mail_txn = mail_txn->next) {
		if (mail_txn->parent_mailbox_txn == t)
			return mail_txn;
	}
	i_panic("no notify_mail_txn found");
}

void notify_contexts_mail_transaction_begin(struct mailbox_transaction_context *t)
{
	struct notify_context *ctx;
	struct notify_mail_txn *mail_txn;
	
	for (ctx = ctx_list; ctx != NULL; ctx = ctx->next) {
		mail_txn = i_new(struct notify_mail_txn, 1);
		mail_txn->parent_mailbox_txn = t;
		mail_txn->txn = ctx->v.mail_transaction_begin == NULL ? NULL :
			ctx->v.mail_transaction_begin(t);
		DLLIST_PREPEND(&ctx->mail_txn_list, mail_txn);
	}
}

void notify_contexts_mail_save(struct mail *mail)
{
	struct notify_context *ctx;
	struct notify_mail_txn *mail_txn;

	for (ctx = ctx_list; ctx != NULL; ctx = ctx->next) {
		if (ctx->v.mail_save == NULL)
			continue;
		mail_txn = notify_context_find_mail_txn(ctx, mail->transaction);
		ctx->v.mail_save(mail_txn->txn, mail);
	}
}

void notify_contexts_mail_copy(struct mail *src, struct mail *dst)
{
	struct notify_context *ctx;
	struct notify_mail_txn *mail_txn;

	for (ctx = ctx_list; ctx != NULL; ctx = ctx->next) {
		if (ctx->v.mail_copy == NULL)
			continue;
		mail_txn = notify_context_find_mail_txn(ctx, dst->transaction);
		ctx->v.mail_copy(mail_txn->txn, src, dst);
	}
}

void notify_contexts_mail_expunge(struct mail *mail)
{
	struct notify_context *ctx;
	struct notify_mail_txn *mail_txn;

	for (ctx = ctx_list; ctx != NULL; ctx = ctx->next) {
		if (ctx->v.mail_expunge == NULL)
			continue;
		mail_txn = notify_context_find_mail_txn(ctx, mail->transaction);
		ctx->v.mail_expunge(mail_txn->txn, mail);
	}
}

void notify_contexts_mail_update_flags(struct mail *mail,
				       enum mail_flags old_flags)
{
	struct notify_context *ctx;
	struct notify_mail_txn *mail_txn;

	for (ctx = ctx_list; ctx != NULL; ctx = ctx->next) {
		if (ctx->v.mail_update_flags == NULL)
			continue;
		mail_txn = notify_context_find_mail_txn(ctx, mail->transaction);
		ctx->v.mail_update_flags(mail_txn->txn, mail, old_flags);
	}
}

void notify_contexts_mail_update_keywords(struct mail *mail,
					  const char *const *old_keywords)
{
	struct notify_context *ctx;
	struct notify_mail_txn *mail_txn;

	for (ctx = ctx_list; ctx != NULL; ctx = ctx->next) {
		if (ctx->v.mail_update_keywords == NULL)
			continue;
		mail_txn = notify_context_find_mail_txn(ctx, mail->transaction);
		ctx->v.mail_update_keywords(mail_txn->txn, mail, old_keywords);
	}
}

void notify_contexts_mail_transaction_commit(struct mailbox_transaction_context *t,
					     struct mail_transaction_commit_changes *changes)
{
	struct notify_context *ctx;
	struct notify_mail_txn *mail_txn;

	for (ctx = ctx_list; ctx != NULL; ctx = ctx->next) {
		if (ctx->v.mail_transaction_commit == NULL)
			continue;
		mail_txn = notify_context_find_mail_txn(ctx, t);
		if (ctx->v.mail_transaction_commit != NULL)
			ctx->v.mail_transaction_commit(mail_txn->txn, changes);
		DLLIST_REMOVE(&ctx->mail_txn_list, mail_txn);
		i_free(mail_txn);
	}
}

void notify_contexts_mail_transaction_rollback(struct mailbox_transaction_context *t)
{
	struct notify_context *ctx;
	struct notify_mail_txn *mail_txn;

	for (ctx = ctx_list; ctx != NULL; ctx = ctx->next) {
		mail_txn = notify_context_find_mail_txn(ctx, t);
		if (ctx->v.mail_transaction_rollback != NULL)
			ctx->v.mail_transaction_rollback(mail_txn->txn);
		DLLIST_REMOVE(&ctx->mail_txn_list, mail_txn);
		i_free(mail_txn);
	}
}

void notify_contexts_mailbox_create(struct mailbox *box)
{
	struct notify_context *ctx;

	for (ctx = ctx_list; ctx != NULL; ctx = ctx->next) {
		if (ctx->v.mailbox_create != NULL)
			ctx->v.mailbox_create(box);
	}
}

void notify_contexts_mailbox_delete_begin(struct mailbox *box)
{
	struct notify_context *ctx;

	for (ctx = ctx_list; ctx != NULL; ctx = ctx->next) {
		ctx->mailbox_delete_txn =
			ctx->v.mailbox_delete_begin == NULL ? NULL :
			ctx->v.mailbox_delete_begin(box);
	}
}

void notify_contexts_mailbox_delete_commit(struct mailbox *box)
{
	struct notify_context *ctx;

	for (ctx = ctx_list; ctx != NULL; ctx = ctx->next) {
		if (ctx->v.mailbox_delete_commit != NULL) {
			ctx->v.mailbox_delete_commit(ctx->mailbox_delete_txn,
						     box);
		}
		ctx->mailbox_delete_txn = NULL;
	}
}

void notify_contexts_mailbox_delete_rollback(void)
{
	struct notify_context *ctx;

	for (ctx = ctx_list; ctx != NULL; ctx = ctx->next) {
		if (ctx->v.mailbox_delete_rollback != NULL)
			ctx->v.mailbox_delete_rollback(ctx->mailbox_delete_txn);
		ctx->mailbox_delete_txn = NULL;
	}
}

void notify_contexts_mailbox_rename(struct mailbox *src, struct mailbox *dest,
				    bool rename_children)
{
	struct notify_context *ctx;

	for (ctx = ctx_list; ctx != NULL; ctx = ctx->next)
		ctx->v.mailbox_rename(src, dest, rename_children);
}

struct notify_context *
notify_register(const struct notify_vfuncs *v)
{
	struct notify_context *ctx;

	ctx = i_new(struct notify_context, 1);
	ctx->v = *v;
	DLLIST_PREPEND(&ctx_list, ctx);
	return ctx;
}

void notify_unregister(struct notify_context *ctx)
{
	struct notify_mail_txn *mail_txn = ctx->mail_txn_list;

	for (; mail_txn != NULL; mail_txn = mail_txn->next) {
		if (ctx->v.mail_transaction_rollback != NULL)
			ctx->v.mail_transaction_rollback(mail_txn->txn);
	}
	if (ctx->mailbox_delete_txn != NULL &&
	    ctx->v.mailbox_delete_rollback != NULL)
		ctx->v.mailbox_delete_rollback(ctx->mailbox_delete_txn);
	DLLIST_REMOVE(&ctx_list, ctx);
	i_free(ctx);
}

void notify_plugin_init(struct module *module)
{
	notify_plugin_init_storage(module);
}

void notify_plugin_deinit(void)
{
	notify_plugin_deinit_storage();
}
