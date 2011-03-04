/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "mail-search-build.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "maildir-storage.h"
#include "quota-private.h"
#include "quota-plugin.h"

#include <sys/stat.h>

#define QUOTA_CONTEXT(obj) \
	MODULE_CONTEXT(obj, quota_storage_module)
#define QUOTA_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, quota_mail_module)
#define QUOTA_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, quota_mailbox_list_module)

struct quota_mailbox_list {
	union mailbox_list_module_context module_ctx;
};

struct quota_mailbox {
	union mailbox_module_context module_ctx;

	struct mailbox_transaction_context *expunge_trans;
	struct quota_transaction_context *expunge_qt;
	ARRAY_DEFINE(expunge_uids, uint32_t);
	ARRAY_DEFINE(expunge_sizes, uoff_t);

	unsigned int recalculate:1;
};

struct quota_user_module quota_user_module =
	MODULE_CONTEXT_INIT(&mail_user_module_register);

static MODULE_CONTEXT_DEFINE_INIT(quota_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(quota_mail_module, &mail_module_register);
static MODULE_CONTEXT_DEFINE_INIT(quota_mailbox_list_module,
				  &mailbox_list_module_register);

static void quota_mail_expunge(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct quota_mailbox *qbox = QUOTA_CONTEXT(_mail->box);
	union mail_module_context *qmail = QUOTA_MAIL_CONTEXT(mail);
	uoff_t size;

	/* We need to handle the situation where multiple transactions expunged
	   the mail at the same time. In here we'll just save the message's
	   physical size and do the quota freeing later when the message was
	   known to be expunged. */
	if (mail_get_physical_size(_mail, &size) == 0) {
		if (!array_is_created(&qbox->expunge_uids)) {
			i_array_init(&qbox->expunge_uids, 64);
			i_array_init(&qbox->expunge_sizes, 64);
		}
		array_append(&qbox->expunge_uids, &_mail->uid, 1);
		array_append(&qbox->expunge_sizes, &size, 1);
	}

	qmail->super.expunge(_mail);
}

static struct mailbox_transaction_context *
quota_mailbox_transaction_begin(struct mailbox *box,
				enum mailbox_transaction_flags flags)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(box);
	struct mailbox_transaction_context *t;
	struct quota_transaction_context *qt;

	t = qbox->module_ctx.super.transaction_begin(box, flags);
	qt = quota_transaction_begin(box);

	MODULE_CONTEXT_SET(t, quota_storage_module, qt);
	return t;
}

static int
quota_mailbox_transaction_commit(struct mailbox_transaction_context *ctx,
				 struct mail_transaction_commit_changes *changes_r)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(ctx->box);
	struct quota_transaction_context *qt = QUOTA_CONTEXT(ctx);

	if (qt->tmp_mail != NULL)
		mail_free(&qt->tmp_mail);

	if (qbox->module_ctx.super.transaction_commit(ctx, changes_r) < 0) {
		quota_transaction_rollback(&qt);
		return -1;
	} else {
		(void)quota_transaction_commit(&qt);
		return 0;
	}
}

static void
quota_mailbox_transaction_rollback(struct mailbox_transaction_context *ctx)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(ctx->box);
	struct quota_transaction_context *qt = QUOTA_CONTEXT(ctx);

	if (qt->tmp_mail != NULL)
		mail_free(&qt->tmp_mail);

	qbox->module_ctx.super.transaction_rollback(ctx);
	quota_transaction_rollback(&qt);
}

void quota_mail_allocated(struct mail *_mail)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(_mail->box);
	struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_vfuncs *v = mail->vlast;
	union mail_module_context *qmail;

	if (qbox == NULL)
		return;

	qmail = p_new(mail->pool, union mail_module_context, 1);
	qmail->super = *v;
	mail->vlast = &qmail->super;

	v->expunge = quota_mail_expunge;
	MODULE_CONTEXT_SET_SELF(mail, quota_mail_module, qmail);
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
		mail_storage_set_error(t->box->storage, MAIL_ERROR_NOSPACE,
				       qt->quota->set->quota_exceeded_msg);
		return -1;
	} else {
		mail_storage_set_critical(t->box->storage,
					  "Internal quota calculation error");
		return -1;
	}
}

static int
quota_copy(struct mail_save_context *ctx, struct mail *mail)
{
	struct mailbox_transaction_context *t = ctx->transaction;
	struct quota_transaction_context *qt = QUOTA_CONTEXT(t);
	struct quota_mailbox *qbox = QUOTA_CONTEXT(t->box);

	if (ctx->dest_mail == NULL) {
		/* we always want to know the mail size */
		if (qt->tmp_mail == NULL) {
			qt->tmp_mail = mail_alloc(t, MAIL_FETCH_PHYSICAL_SIZE,
						  NULL);
		}
		ctx->dest_mail = qt->tmp_mail;
	}

	if (qbox->module_ctx.super.copy(ctx, mail) < 0)
		return -1;

	/* if copying used saving internally, we already checked the quota */
	return ctx->copying ? 0 : quota_check(t, ctx->dest_mail);
}

static int
quota_save_begin(struct mail_save_context *ctx, struct istream *input)
{
	struct mailbox_transaction_context *t = ctx->transaction;
	struct quota_transaction_context *qt = QUOTA_CONTEXT(t);
	struct quota_mailbox *qbox = QUOTA_CONTEXT(t->box);
	uoff_t size;
	int ret;

	if (i_stream_get_size(input, TRUE, &size) > 0) {
		/* Input size is known, check for quota immediately. This
		   check isn't perfect, especially because input stream's
		   linefeeds may contain CR+LFs while physical message would
		   only contain LFs. With mbox some headers might be skipped
		   entirely.

		   I think these don't really matter though compared to the
		   benefit of giving "out of quota" error before sending the
		   full mail. */
		bool too_large;

		ret = quota_test_alloc(qt, size, &too_large);
		if (ret == 0) {
			mail_storage_set_error(t->box->storage,
				MAIL_ERROR_NOSPACE,
				qt->quota->set->quota_exceeded_msg);
			return -1;
		} else if (ret < 0) {
			mail_storage_set_critical(t->box->storage,
				"Internal quota calculation error");
			return -1;
		}
	}

	if (ctx->dest_mail == NULL) {
		/* we always want to know the mail size */
		if (qt->tmp_mail == NULL) {
			qt->tmp_mail = mail_alloc(t, MAIL_FETCH_PHYSICAL_SIZE,
						  NULL);
		}
		ctx->dest_mail = qt->tmp_mail;
	}

	return qbox->module_ctx.super.save_begin(ctx, input);
}

static int quota_save_finish(struct mail_save_context *ctx)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(ctx->transaction->box);

	if (qbox->module_ctx.super.save_finish(ctx) < 0)
		return -1;

	return quota_check(ctx->transaction, ctx->dest_mail);
}

static void quota_mailbox_sync_cleanup(struct quota_mailbox *qbox)
{
	if (array_is_created(&qbox->expunge_uids)) {
		array_clear(&qbox->expunge_uids);
		array_clear(&qbox->expunge_sizes);
	}

	if (qbox->expunge_qt != NULL && qbox->expunge_qt->tmp_mail != NULL) {
		mail_free(&qbox->expunge_qt->tmp_mail);
		mailbox_transaction_rollback(&qbox->expunge_trans);
	}
}

static void quota_mailbox_sync_commit(struct quota_mailbox *qbox)
{
	quota_mailbox_sync_cleanup(qbox);
	if (qbox->expunge_qt != NULL)
		(void)quota_transaction_commit(&qbox->expunge_qt);
	qbox->recalculate = FALSE;
}

static void quota_mailbox_sync_notify(struct mailbox *box, uint32_t uid,
				      enum mailbox_sync_type sync_type)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(box);
	const uint32_t *uids;
	const uoff_t *sizep;
	unsigned int i, count;
	uoff_t size;

	if (qbox->module_ctx.super.sync_notify != NULL)
		qbox->module_ctx.super.sync_notify(box, uid, sync_type);

	if (sync_type != MAILBOX_SYNC_TYPE_EXPUNGE || qbox->recalculate) {
		if (uid == 0) {
			/* free the transaction before view syncing begins,
			   otherwise it'll crash. */
			quota_mailbox_sync_cleanup(qbox);
		}
		return;
	}

	/* we're in the middle of syncing the mailbox, so it's a bad idea to
	   try and get the message sizes at this point. Rely on sizes that
	   we saved earlier, or recalculate the whole quota if we don't know
	   the size. */
	if (!array_is_created(&qbox->expunge_uids)) {
		i = count = 0;
	} else {
		uids = array_get(&qbox->expunge_uids, &count);
		for (i = 0; i < count; i++) {
			if (uids[i] == uid)
				break;
		}
	}

	if (qbox->expunge_qt == NULL)
		qbox->expunge_qt = quota_transaction_begin(box);

	if (i != count) {
		/* we already know the size */
		sizep = array_idx(&qbox->expunge_sizes, i);
		quota_free_bytes(qbox->expunge_qt, *sizep);
		return;
	}

	/* try to look up the size. this works only if it's cached. */
	if (qbox->expunge_qt->tmp_mail == NULL) {
		qbox->expunge_trans = mailbox_transaction_begin(box, 0);
		qbox->expunge_qt->tmp_mail =
			mail_alloc(qbox->expunge_trans,
				   MAIL_FETCH_PHYSICAL_SIZE, NULL);
	}
	if (mail_set_uid(qbox->expunge_qt->tmp_mail, uid) &&
	    mail_get_physical_size(qbox->expunge_qt->tmp_mail, &size) == 0)
		quota_free_bytes(qbox->expunge_qt, size);
	else {
		/* there's no way to get the size. recalculate the quota. */
		quota_recalculate(qbox->expunge_qt);
		qbox->recalculate = TRUE;
	}
}

static int quota_mailbox_sync_deinit(struct mailbox_sync_context *ctx,
				     struct mailbox_sync_status *status_r)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(ctx->box);
	int ret;

	ret = qbox->module_ctx.super.sync_deinit(ctx, status_r);
	/* update quota only after syncing is finished. the quota commit may
	   recalculate the quota and cause all mailboxes to be synced,
	   including the one we're already syncing. */
	quota_mailbox_sync_commit(qbox);
	return ret;
}

static void quota_mailbox_close(struct mailbox *box)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(box);

	/* sync_notify() may be called outside sync_begin()..sync_deinit().
	   make sure we apply changes at close time at latest. */
	quota_mailbox_sync_commit(qbox);

	qbox->module_ctx.super.close(box);
}

static int
quota_mailbox_delete_shrink_quota(struct mailbox *box)
{
	struct mail_search_context *ctx;
        struct mailbox_transaction_context *t;
	struct quota_transaction_context *qt;
	struct mail *mail;
	struct mail_search_args *search_args;

	if (mailbox_mark_index_deleted(box, TRUE) < 0)
		return -1;

	t = mailbox_transaction_begin(box, 0);
	qt = quota_transaction_begin(box);

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	ctx = mailbox_search_init(t, search_args, NULL);
	mail_search_args_unref(&search_args);

	mail = mail_alloc(t, 0, NULL);
	while (mailbox_search_next(ctx, mail))
		quota_free(qt, mail);
	mail_free(&mail);

	if (mailbox_search_deinit(&ctx) < 0) {
		/* maybe we missed some mails. */
		quota_recalculate(qt);
	}
	(void)quota_transaction_commit(&qt);
	mailbox_transaction_rollback(&t);
	return 0;
}

static int quota_mailbox_delete(struct mailbox *box)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(box);

	if (box->opened) {
		if (quota_mailbox_delete_shrink_quota(box) < 0)
			return -1;
	}
	return qbox->module_ctx.super.delete(box);
}

static void quota_mailbox_free(struct mailbox *box)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(box);

	if (array_is_created(&qbox->expunge_uids)) {
		array_free(&qbox->expunge_uids);
		array_free(&qbox->expunge_sizes);
	}
	i_assert(qbox->expunge_qt == NULL ||
		 qbox->expunge_qt->tmp_mail == NULL);

	qbox->module_ctx.super.free(box);
}

void quota_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	struct quota_mailbox *qbox;

	if (QUOTA_LIST_CONTEXT(box->list) == NULL)
		return;

	if ((box->storage->class_flags & MAIL_STORAGE_CLASS_FLAG_NOQUOTA) != 0)
		return;

	qbox = p_new(box->pool, struct quota_mailbox, 1);
	qbox->module_ctx.super = *v;
	box->vlast = &qbox->module_ctx.super;

	v->transaction_begin = quota_mailbox_transaction_begin;
	v->transaction_commit = quota_mailbox_transaction_commit;
	v->transaction_rollback = quota_mailbox_transaction_rollback;
	v->save_begin = quota_save_begin;
	v->save_finish = quota_save_finish;
	v->copy = quota_copy;
	v->sync_notify = quota_mailbox_sync_notify;
	v->sync_deinit = quota_mailbox_sync_deinit;
	v->close = quota_mailbox_close;
	v->delete = quota_mailbox_delete;
	v->free = quota_mailbox_free;
	MODULE_CONTEXT_SET(box, quota_storage_module, qbox);
}

static void quota_mailbox_list_deinit(struct mailbox_list *list)
{
	struct quota_mailbox_list *qlist = QUOTA_LIST_CONTEXT(list);

	quota_remove_user_namespace(list->ns);
	qlist->module_ctx.super.deinit(list);
}

struct quota *quota_get_mail_user_quota(struct mail_user *user)
{
	struct quota_user *quser = QUOTA_USER_CONTEXT(user);

	return quser->quota;
}

static void quota_user_deinit(struct mail_user *user)
{
	struct quota_user *quser = QUOTA_USER_CONTEXT(user);
	struct quota_settings *quota_set = quser->quota->set;

	quota_deinit(&quser->quota);
	quser->module_ctx.super.deinit(user);

	quota_settings_deinit(&quota_set);
}

void quota_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct quota_user *quser;
	struct quota_settings *set;
	struct quota *quota;
	const char *error;
	int ret;

	if ((ret = quota_user_read_settings(user, &set, &error)) > 0) {
		if (quota_init(set, user, &quota, &error) < 0) {
			quota_settings_deinit(&set);
			ret = -1;
		}
	}

	if (ret < 0) {
		user->error = p_strdup_printf(user->pool,
			"Failed to initialize quota: %s", error);
		return;
	}
	if (ret > 0) {
		quser = p_new(user->pool, struct quota_user, 1);
		quser->module_ctx.super = *v;
		user->vlast = &quser->module_ctx.super;
		v->deinit = quota_user_deinit;
		quser->quota = quota;

		MODULE_CONTEXT_SET(user, quota_user_module, quser);
	} else if (user->mail_debug) {
		i_debug("quota: No quota setting - plugin disabled");
	}
}

static struct quota_root *
quota_find_root_for_ns(struct quota *quota, struct mail_namespace *ns)
{
	struct quota_root *const *roots;
	unsigned int i, count;

	roots = array_get(&quota->roots, &count);
	for (i = 0; i < count; i++) {
		if (roots[i]->ns_prefix != NULL &&
		    strcmp(roots[i]->ns_prefix, ns->prefix) == 0)
			return roots[i];
	}
	return NULL;
}

void quota_mailbox_list_created(struct mailbox_list *list)
{
	struct quota_mailbox_list *qlist;
	struct quota *quota = NULL;
	struct quota_root *root;
	bool add;

	if (QUOTA_USER_CONTEXT(list->ns->user) == NULL)
		return;

	/* see if we have a quota explicitly defined for this namespace */
	quota = quota_get_mail_user_quota(list->ns->user);
	root = quota_find_root_for_ns(quota, list->ns);
	if (root != NULL)
		root->ns = list->ns;

	if ((list->ns->flags & NAMESPACE_FLAG_NOQUOTA) != 0)
		add = FALSE;
	else if (list->ns->owner == NULL) {
		/* public namespace - add quota only if namespace is
		   explicitly defined for it */
		add = root != NULL;
	} else {
		add = TRUE;
	}

	if (add) {
		struct mailbox_list_vfuncs *v = list->vlast;

		qlist = p_new(list->pool, struct quota_mailbox_list, 1);
		qlist->module_ctx.super = *v;
		list->vlast = &qlist->module_ctx.super;
		v->deinit = quota_mailbox_list_deinit;
		MODULE_CONTEXT_SET(list, quota_mailbox_list_module, qlist);

		/* register to owner's quota roots */
		quota = list->ns->owner != NULL ?
			quota_get_mail_user_quota(list->ns->owner) :
			quota_get_mail_user_quota(list->ns->user);
		quota_add_user_namespace(quota, list->ns);
	}
}

static void quota_root_set_namespace(struct quota_root *root,
				     struct mail_namespace *namespaces)
{
	const struct quota_rule *rule;
	const char *name;

	if (root->ns_prefix != NULL && root->ns == NULL) {
		root->ns = mail_namespace_find_prefix(namespaces,
						      root->ns_prefix);
		if (root->ns == NULL) {
			i_error("quota: Unknown namespace: %s",
				root->ns_prefix);
		}
	}

	array_foreach(&root->set->rules, rule) {
		name = rule->mailbox_name;
		if (mail_namespace_find(namespaces, &name) == NULL)
			i_error("quota: Unknown namespace: %s", name);
	}
}

void quota_mail_namespaces_created(struct mail_namespace *namespaces)
{
	struct quota *quota;
	struct quota_root *const *roots;
	unsigned int i, count;

	if (QUOTA_USER_CONTEXT(namespaces->user) == NULL)
		return;

	quota = quota_get_mail_user_quota(namespaces->user);
	roots = array_get(&quota->roots, &count);
	for (i = 0; i < count; i++)
		quota_root_set_namespace(roots[i], namespaces);
}
