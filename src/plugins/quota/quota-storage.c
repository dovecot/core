/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

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

static struct mail *
quota_mail_alloc(struct mailbox_transaction_context *t,
		 enum mail_fetch_field wanted_fields,
		 struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(t->box);
	union mail_module_context *qmail;
	struct mail *_mail;
	struct mail_private *mail;

	_mail = qbox->module_ctx.super.
		mail_alloc(t, wanted_fields, wanted_headers);
	mail = (struct mail_private *)_mail;

	qmail = p_new(mail->pool, union mail_module_context, 1);
	qmail->super = mail->v;

	mail->v.expunge = quota_mail_expunge;
	MODULE_CONTEXT_SET_SELF(mail, quota_mail_module, qmail);
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
				     enum mailbox_status_items status_items,
				     struct mailbox_status *status_r)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(ctx->box);
	int ret;

	ret = qbox->module_ctx.super.sync_deinit(ctx, status_items, status_r);
	/* update quota only after syncing is finished. the quota commit may
	   recalculate the quota and cause all mailboxes to be synced,
	   including the one we're already syncing. */
	quota_mailbox_sync_commit(qbox);
	return ret;
}

static void quota_mailbox_close(struct mailbox *box)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT(box);

	if (array_is_created(&qbox->expunge_uids)) {
		array_free(&qbox->expunge_uids);
		array_free(&qbox->expunge_sizes);
	}
	i_assert(qbox->expunge_qt == NULL ||
		 qbox->expunge_qt->tmp_mail == NULL);

	qbox->module_ctx.super.close(box);
}

static struct mailbox *
quota_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		    const char *name, struct istream *input,
		    enum mailbox_flags flags)
{
	union mail_storage_module_context *qstorage = QUOTA_CONTEXT(storage);
	struct mailbox *box;
	struct quota_mailbox *qbox;

	box = qstorage->super.mailbox_alloc(storage, list, name, input, flags);
	if (box == NULL || QUOTA_LIST_CONTEXT(list) == NULL)
		return box;

	qbox = p_new(box->pool, struct quota_mailbox, 1);
	qbox->module_ctx.super = box->v;

	box->v.transaction_begin = quota_mailbox_transaction_begin;
	box->v.transaction_commit = quota_mailbox_transaction_commit;
	box->v.transaction_rollback = quota_mailbox_transaction_rollback;
	box->v.mail_alloc = quota_mail_alloc;
	box->v.save_begin = quota_save_begin;
	box->v.save_finish = quota_save_finish;
	box->v.copy = quota_copy;
	box->v.sync_notify = quota_mailbox_sync_notify;
	box->v.sync_deinit = quota_mailbox_sync_deinit;
	box->v.close = quota_mailbox_close;
	MODULE_CONTEXT_SET(box, quota_storage_module, qbox);
	return box;
}

static int
quota_mailbox_delete_shrink_quota(struct mailbox *box)
{
	struct mail_search_context *ctx;
        struct mailbox_transaction_context *t;
	struct quota_transaction_context *qt;
	struct mail *mail;
	struct mail_search_args *search_args;
	int ret;

	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ, 0, NULL) < 0)
		return -1;

	t = mailbox_transaction_begin(box, 0);
	qt = QUOTA_CONTEXT(t);

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	ctx = mailbox_search_init(t, search_args, NULL);
	mail_search_args_unref(&search_args);

	mail = mail_alloc(t, 0, NULL);
	while (mailbox_search_next(ctx, mail))
		quota_free(qt, mail);
	mail_free(&mail);

	ret = mailbox_search_deinit(&ctx);
	if (ret < 0)
		mailbox_transaction_rollback(&t);
	else
		ret = mailbox_transaction_commit(&t);
	return ret;
}

static void quota_mailbox_list_deinit(struct mailbox_list *list)
{
	struct quota_mailbox_list *qlist = QUOTA_LIST_CONTEXT(list);

	quota_remove_user_namespace(list->ns);
	qlist->module_ctx.super.deinit(list);
}

static int
quota_mailbox_list_delete(struct mailbox_list *list, const char *name)
{
	struct quota_mailbox_list *qlist = QUOTA_LIST_CONTEXT(list);
	struct mailbox *box;
	enum mail_error error;
	const char *str;
	int ret;

	/* This is a bit annoying to handle. We'll have to open the mailbox
	   and free the quota for all the messages existing in it. Open the
	   mailbox locked so that other processes can't mess up the quota
	   calculations by adding/removing mails while we're doing this. */
	box = mailbox_alloc(list, name, NULL, MAILBOX_FLAG_KEEP_RECENT |
			    MAILBOX_FLAG_KEEP_LOCKED);
	if (mailbox_open(box) < 0) {
		str = mail_storage_get_last_error(mailbox_get_storage(box),
						  &error);
		if (error != MAIL_ERROR_NOTPOSSIBLE) {
			ret = -1;
		} else {
			/* mailbox isn't selectable */
			ret = 0;
		}
	} else {
		if ((ret = quota_mailbox_delete_shrink_quota(box)) < 0) {
			str = mail_storage_get_last_error(box->storage, &error);
			mailbox_list_set_error(list, error, str);
		}
	}
	if (box != NULL)
		mailbox_close(&box);

	/* FIXME: here's an unfortunate race condition */
	return ret < 0 ? -1 :
		qlist->module_ctx.super.delete_mailbox(list, name);
}

struct quota *quota_get_mail_user_quota(struct mail_user *user)
{
	struct quota_user *quser = QUOTA_USER_CONTEXT(user);

	return quser->quota;
}

static void quota_user_deinit(struct mail_user *user)
{
	struct quota_user *quser = QUOTA_USER_CONTEXT(user);

	quota_deinit(&quser->quota);
	quser->module_ctx.super.deinit(user);
}

void quota_mail_user_created(struct mail_user *user)
{
	struct quota_user *quser;
	struct quota_settings *set;

	set = quota_user_read_settings(user);
	if (set != NULL) {
		quser = p_new(user->pool, struct quota_user, 1);
		quser->module_ctx.super = user->v;
		user->v.deinit = quota_user_deinit;
		quser->quota = quota_init(set, user);

		MODULE_CONTEXT_SET(user, quota_user_module, quser);
	} else if (user->mail_debug) {
		i_debug("quota: No quota setting - plugin disabled");
	}
}

void quota_mail_storage_created(struct mail_storage *storage)
{
	union mail_storage_module_context *qstorage;

	qstorage = p_new(storage->pool, union mail_storage_module_context, 1);
	qstorage->super = storage->v;
	storage->v.mailbox_alloc = quota_mailbox_alloc;

	MODULE_CONTEXT_SET_SELF(storage, quota_storage_module, qstorage);
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

void quota_mail_namespace_storage_added(struct mail_namespace *ns)
{
	struct mailbox_list *list = ns->list;
	struct quota_mailbox_list *qlist;
	struct quota *quota = NULL;
	struct quota_root *root;
	bool add;

	if ((ns->flags & NAMESPACE_FLAG_NOQUOTA) != 0)
		add = FALSE;
	else if (ns->owner == NULL) {
		/* see if we have a quota explicitly defined for
		   this namespace */
		quota = quota_get_mail_user_quota(ns->user);
		root = quota_find_root_for_ns(quota, ns);
		add = root != NULL;
		if (root != NULL)
			root->ns = ns;
	} else {
		add = TRUE;
	}

	if (add) {
		qlist = p_new(list->pool, struct quota_mailbox_list, 1);
		qlist->module_ctx.super = list->v;
		list->v.deinit = quota_mailbox_list_deinit;
		list->v.delete_mailbox = quota_mailbox_list_delete;
		MODULE_CONTEXT_SET(list, quota_mailbox_list_module, qlist);

		/* register to owner's quota roots */
		quota = ns->owner != NULL ?
			quota_get_mail_user_quota(ns->owner) :
			quota_get_mail_user_quota(ns->user);
		quota_add_user_namespace(quota, ns);
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

	quota = quota_get_mail_user_quota(namespaces->user);
	roots = array_get(&quota->roots, &count);
	for (i = 0; i < count; i++)
		quota_root_set_namespace(roots[i], namespaces);
}
