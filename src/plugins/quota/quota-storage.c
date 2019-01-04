/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "mail-search-build.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "maildir-storage.h"
#include "index-mailbox-size.h"
#include "quota-private.h"
#include "quota-plugin.h"

#include <sys/stat.h>

#define QUOTA_CONTEXT(obj) \
	MODULE_CONTEXT(obj, quota_storage_module)
#define QUOTA_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, quota_storage_module)
#define QUOTA_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, quota_mail_module)
#define QUOTA_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, quota_mailbox_list_module)

struct quota_mailbox_list {
	union mailbox_list_module_context module_ctx;
};

struct quota_mailbox {
	union mailbox_module_context module_ctx;

	struct mailbox_transaction_context *expunge_trans;
	struct quota_transaction_context *expunge_qt;
	ARRAY(uint32_t) expunge_uids;
	ARRAY(uoff_t) expunge_sizes;
	unsigned int prev_idx;

	bool recalculate:1;
	bool sync_transaction_expunge:1;
};

struct quota_user_module quota_user_module =
	MODULE_CONTEXT_INIT(&mail_user_module_register);

static MODULE_CONTEXT_DEFINE_INIT(quota_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(quota_mail_module, &mail_module_register);
static MODULE_CONTEXT_DEFINE_INIT(quota_mailbox_list_module,
				  &mailbox_list_module_register);

static void quota_set_storage_error(struct quota_transaction_context *qt,
				    struct mailbox *box,
				    enum quota_alloc_result res,
				    const char *internal_err)
{
	const char *errstr = quota_alloc_result_errstr(res, qt);
	struct mail_storage *storage = box->storage;
	switch (res) {
	case QUOTA_ALLOC_RESULT_OVER_MAXSIZE:
		mail_storage_set_error(storage, MAIL_ERROR_LIMIT, errstr);
		break;
	case QUOTA_ALLOC_RESULT_OVER_QUOTA_LIMIT:
	case QUOTA_ALLOC_RESULT_OVER_QUOTA:
		mail_storage_set_error(storage, MAIL_ERROR_NOQUOTA, errstr);
		break;
	case QUOTA_ALLOC_RESULT_TEMPFAIL:
	case QUOTA_ALLOC_RESULT_BACKGROUND_CALC:
		mailbox_set_critical(box, "quota: %s", internal_err);
		break;
	case QUOTA_ALLOC_RESULT_OK:
		i_unreached();
	}
}

static void quota_mail_expunge(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct quota_mailbox *qbox = QUOTA_CONTEXT_REQUIRE(_mail->box);
	struct quota_user *quser = QUOTA_USER_CONTEXT_REQUIRE(_mail->box->storage->user);
	union mail_module_context *qmail = QUOTA_MAIL_CONTEXT(mail);
	struct quota_transaction_context *qt = QUOTA_CONTEXT_REQUIRE(_mail->transaction);
	uoff_t size;
	int ret;

	if (qt->auto_updating) {
		qmail->super.expunge(_mail);
		return;
	}

	/* We need to handle the situation where multiple transactions expunged
	   the mail at the same time. In here we'll just save the message's
	   physical size and do the quota freeing later when the message was
	   known to be expunged. */
	if (quser->quota->set->vsizes)
		ret = mail_get_virtual_size(_mail, &size);
	else
		ret = mail_get_physical_size(_mail, &size);
	if (ret == 0) {
		if (!array_is_created(&qbox->expunge_uids)) {
			i_array_init(&qbox->expunge_uids, 64);
			i_array_init(&qbox->expunge_sizes, 64);
		}
		array_push_back(&qbox->expunge_uids, &_mail->uid);
		array_push_back(&qbox->expunge_sizes, &size);
		if ((_mail->transaction->flags & MAILBOX_TRANSACTION_FLAG_SYNC) != 0) {
			/* we're running dsync. if this brings the quota below
			   a negative quota warning, don't execute it, because
			   it probably was already executed by the replica. */
			qbox->sync_transaction_expunge = TRUE;
		} else {
			qbox->sync_transaction_expunge = FALSE;
		}
	}

	qmail->super.expunge(_mail);
}

static int
quota_get_status(struct mailbox *box, enum mailbox_status_items items,
		 struct mailbox_status *status_r)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT_REQUIRE(box);
	struct quota_transaction_context *qt;
	int ret = 0;

	if ((items & STATUS_CHECK_OVER_QUOTA) != 0) {
		qt = quota_transaction_begin(box);
		const char *error;
		enum quota_alloc_result qret = quota_test_alloc(qt, 0, &error);
		if (qret != QUOTA_ALLOC_RESULT_OK) {
			quota_set_storage_error(qt, box, qret, error);
			ret = -1;
		}
		quota_transaction_rollback(&qt);

		if ((items & ~STATUS_CHECK_OVER_QUOTA) == 0) {
			/* don't bother calling parent, it may unnecessarily
			   try to open the mailbox */
			return ret < 0 ? -1 : 0;
		}
	}

	if (qbox->module_ctx.super.get_status(box, items, status_r) < 0)
		ret = -1;
	return ret < 0 ? -1 : 0;
}

static struct mailbox_transaction_context *
quota_mailbox_transaction_begin(struct mailbox *box,
				enum mailbox_transaction_flags flags,
				const char *reason)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT_REQUIRE(box);
	struct mailbox_transaction_context *t;
	struct quota_transaction_context *qt;

	t = qbox->module_ctx.super.transaction_begin(box, flags, reason);
	qt = quota_transaction_begin(box);
	qt->sync_transaction = (flags & MAILBOX_TRANSACTION_FLAG_SYNC) != 0;

	MODULE_CONTEXT_SET(t, quota_storage_module, qt);
	return t;
}

static int
quota_mailbox_transaction_commit(struct mailbox_transaction_context *ctx,
				 struct mail_transaction_commit_changes *changes_r)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT_REQUIRE(ctx->box);
	struct quota_transaction_context *qt = QUOTA_CONTEXT_REQUIRE(ctx);

	i_assert(qt->tmp_mail == NULL);

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
	struct quota_mailbox *qbox = QUOTA_CONTEXT_REQUIRE(ctx->box);
	struct quota_transaction_context *qt = QUOTA_CONTEXT_REQUIRE(ctx);

	i_assert(qt->tmp_mail == NULL);

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

static bool
quota_move_requires_check(struct mailbox *dest_box, struct mailbox *src_box)
{
	struct mail_namespace *src_ns = src_box->list->ns;
	struct mail_namespace *dest_ns = dest_box->list->ns;
	struct quota_user *quser = QUOTA_USER_CONTEXT_REQUIRE(src_ns->user);
	struct quota_root *const *rootp;

	array_foreach(&quser->quota->roots, rootp) {
		bool have_src_quota, have_dest_quota;

		have_src_quota = quota_root_is_namespace_visible(*rootp, src_ns);
		have_dest_quota = quota_root_is_namespace_visible(*rootp, dest_ns);
		if (have_src_quota == have_dest_quota) {
			/* Both/neither have this quota */
		} else if (have_dest_quota) {
			/* Destination mailbox has a quota that doesn't exist
			   in source. We'll need to check if it's being
			   exceeded. */
			return TRUE;
		} else {
			/* Source mailbox has a quota root that doesn't exist
			   in destination. We're not increasing the source
			   quota, so ignore it. */
		}
	}
	return FALSE;
}

static int quota_check(struct mail_save_context *ctx, struct mailbox *src_box)
{
	struct mailbox_transaction_context *t = ctx->transaction;
	struct quota_transaction_context *qt = QUOTA_CONTEXT_REQUIRE(t);
	enum quota_alloc_result ret;

	i_assert(!ctx->moving || src_box != NULL);

	if (ctx->moving &&
	     !quota_move_requires_check(ctx->transaction->box, src_box)) {
		/* the mail is being moved. the quota won't increase (after
		   the following expunge), so allow this even if user is
		   currently over quota */
		quota_alloc(qt, ctx->dest_mail);
		return 0;
	} else if (qt->failed) {
		return 0;
	}

	const char *error;
	ret = quota_try_alloc(qt, ctx->dest_mail, &error);
	switch (ret) {
	case QUOTA_ALLOC_RESULT_OK:
		return 0;
	case QUOTA_ALLOC_RESULT_TEMPFAIL:
		/* Log the error, but allow saving anyway. */
		i_error("quota: Failed to check if user is under quota: %s - saving mail anyway", error);
		return 0;
	case QUOTA_ALLOC_RESULT_BACKGROUND_CALC:
		/* Could not determine if there is enough space due to ongoing
		   background quota calculation, allow saving anyway. */
		i_warning("quota: Failed to check if user is under quota: %s - saving mail anyway", error);
		return 0;
	default:
		quota_set_storage_error(qt, t->box, ret, error);
		return -1;
	}
}

static int
quota_copy(struct mail_save_context *ctx, struct mail *mail)
{
	struct mailbox_transaction_context *t = ctx->transaction;
	struct quota_transaction_context *qt = QUOTA_CONTEXT_REQUIRE(t);
	struct quota_mailbox *qbox = QUOTA_CONTEXT_REQUIRE(t->box);

	/* we always want to know the mail size */
	mail_add_temp_wanted_fields(ctx->dest_mail, MAIL_FETCH_PHYSICAL_SIZE, NULL);

	/* get quota before copying any mails. this avoids dovecot-vsize.lock
	   deadlocks with backends that lock mails for expunging/copying. */
	enum quota_get_result error_res;
	const char *error;
	if (quota_transaction_set_limits(qt, &error_res, &error) < 0) {
		if (error_res == QUOTA_GET_RESULT_BACKGROUND_CALC)
			i_warning("quota: %s - copying mail anyway", error);
		else
			i_error("quota: %s - copying mail anyway", error);
	}

	if (qbox->module_ctx.super.copy(ctx, mail) < 0)
		return -1;

	if (ctx->copying_via_save) {
		/* copying used saving internally, we already checked the
		   quota */
		return 0;
	}
	return quota_check(ctx, mail->box);
}

static int
quota_save_begin(struct mail_save_context *ctx, struct istream *input)
{
	struct mailbox_transaction_context *t = ctx->transaction;
	struct quota_transaction_context *qt = QUOTA_CONTEXT_REQUIRE(t);
	struct quota_mailbox *qbox = QUOTA_CONTEXT_REQUIRE(t->box);
	const char *error;
	uoff_t size;

	if (!ctx->moving && i_stream_get_size(input, TRUE, &size) > 0 &&
	    !qt->failed) {
		/* Input size is known, check for quota immediately. This
		   check isn't perfect, especially because input stream's
		   linefeeds may contain CR+LFs while physical message would
		   only contain LFs. With mbox some headers might be skipped
		   entirely.

		   I think these don't really matter though compared to the
		   benefit of giving "out of quota" error before sending the
		   full mail. */

		enum quota_alloc_result qret = quota_test_alloc(qt, size, &error);
		switch (qret) {
		case QUOTA_ALLOC_RESULT_OK:
			/* Great, there is space. */
			break;
		case QUOTA_ALLOC_RESULT_TEMPFAIL:
			/* Log the error, but allow saving anyway. */
			i_error("quota: Failed to check if user is under quota: %s - saving mail anyway", error);
			break;
		case QUOTA_ALLOC_RESULT_BACKGROUND_CALC:
			/* Could not determine if there is enough space due to
			 * ongoing background quota calculation, allow saving
			 * anyway. */
			i_warning("quota: Failed to check if user is under quota: %s - saving mail anyway", error);
			break;
		default:
			quota_set_storage_error(qt, t->box, qret, error);
			return -1;
		}
	}

	/* we always want to know the mail size */
	mail_add_temp_wanted_fields(ctx->dest_mail, MAIL_FETCH_PHYSICAL_SIZE, NULL);

	/* get quota before copying any mails. this avoids dovecot-vsize.lock
	   deadlocks with backends that lock mails for expunging/copying. */
	enum quota_get_result error_res;
	if (quota_transaction_set_limits(qt, &error_res, &error) < 0) {
		if (error_res == QUOTA_GET_RESULT_BACKGROUND_CALC)
			i_warning("quota: %s - saving mail anyway", error);
		else
			i_error("quota: %s - saving mail anyway", error);
	}

	return qbox->module_ctx.super.save_begin(ctx, input);
}

static int quota_save_finish(struct mail_save_context *ctx)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT_REQUIRE(ctx->transaction->box);
	struct mailbox *src_box;

	if (qbox->module_ctx.super.save_finish(ctx) < 0)
		return -1;

	src_box = ctx->copy_src_mail == NULL ? NULL : ctx->copy_src_mail->box;
	return quota_check(ctx, src_box);
}

static void quota_mailbox_sync_cleanup(struct quota_mailbox *qbox)
{
	if (array_is_created(&qbox->expunge_uids)) {
		array_clear(&qbox->expunge_uids);
		array_clear(&qbox->expunge_sizes);
	}

	if (qbox->expunge_qt != NULL && qbox->expunge_qt->tmp_mail != NULL) {
		mail_free(&qbox->expunge_qt->tmp_mail);
		(void)mailbox_transaction_commit(&qbox->expunge_trans);
	}
	qbox->sync_transaction_expunge = FALSE;
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
	struct quota_mailbox *qbox = QUOTA_CONTEXT_REQUIRE(box);
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);
	struct quota_user *quser = QUOTA_USER_CONTEXT_REQUIRE(box->storage->user);
	const uint32_t *uids;
	const uoff_t *sizep;
	unsigned int i, count;
	uoff_t size;

	if (qbox->module_ctx.super.sync_notify != NULL)
		qbox->module_ctx.super.sync_notify(box, uid, sync_type);

	if (sync_type != MAILBOX_SYNC_TYPE_EXPUNGE || qbox->recalculate ||
	    (box->flags & MAILBOX_FLAG_DELETE_UNSAFE) != 0) {
		if (uid == 0) {
			/* free the transaction before view syncing begins,
			   otherwise it'll crash. */
			quota_mailbox_sync_cleanup(qbox);
		}
		return;
	}

	if (qbox->expunge_qt == NULL) {
		qbox->expunge_qt = quota_transaction_begin(box);
		qbox->expunge_qt->sync_transaction =
			qbox->sync_transaction_expunge;
	}
	if (qbox->expunge_qt->auto_updating) {
		/* even though backend doesn't care about size/count changes,
		   make sure count_used changes so quota_warnings are
		   executed */
		quota_free_bytes(qbox->expunge_qt, 0);
		return;
	}

	/* we're in the middle of syncing the mailbox, so it's a bad idea to
	   try and get the message sizes at this point. Rely on sizes that
	   we saved earlier, or recalculate the whole quota if we don't know
	   the size. */
	if (!array_is_created(&qbox->expunge_uids) ||
	    array_is_empty(&qbox->expunge_uids)) {
		i = count = 0;
	} else {
		uids = array_get(&qbox->expunge_uids, &count);
		for (i = qbox->prev_idx; i < count; i++) {
			if (uids[i] == uid)
				break;
		}
		if (i >= count) {
			for (i = 0; i < qbox->prev_idx; i++) {
				if (uids[i] == uid)
					break;
			}
			if (i == qbox->prev_idx)
				i = count;
		}
		qbox->prev_idx = i;
	}

	if (i != count) {
		/* we already know the size */
		sizep = array_idx(&qbox->expunge_sizes, i);
		quota_free_bytes(qbox->expunge_qt, *sizep);
		/* FIXME: it's not ideal that we do the vsize update here, but
		   this is the easiest place for it for now.. maybe the mail
		   size checking code could be moved to lib-storage */
		if (ibox->vsize_update != NULL && quser->quota->set->vsizes)
			index_mailbox_vsize_hdr_expunge(ibox->vsize_update, uid, *sizep);
		return;
	}

	/* try to look up the size. this works only if it's cached. */
	if (qbox->expunge_qt->tmp_mail == NULL) {
		/* FIXME: ugly kludge to open the transaction for sync_view.
		   box->view may not have all the new messages that
		   sync_notify() notifies about, and those messages would
		   cause a quota recalculation. */
		struct mail_index_view *box_view = box->view;
		if (box->tmp_sync_view != NULL)
			box->view = box->tmp_sync_view;
		qbox->expunge_trans = mailbox_transaction_begin(box, 0, "quota");
		box->view = box_view;
		qbox->expunge_qt->tmp_mail =
			mail_alloc(qbox->expunge_trans,
				   MAIL_FETCH_PHYSICAL_SIZE, NULL);
	}
	if (!mail_set_uid(qbox->expunge_qt->tmp_mail, uid))
		;
	else if (!quser->quota->set->vsizes) {
		if (mail_get_physical_size(qbox->expunge_qt->tmp_mail, &size) == 0) {
			quota_free_bytes(qbox->expunge_qt, size);
			return;
		}
	} else if (mail_get_virtual_size(qbox->expunge_qt->tmp_mail, &size) == 0) {
		quota_free_bytes(qbox->expunge_qt, size);
		if (ibox->vsize_update != NULL)
			index_mailbox_vsize_hdr_expunge(ibox->vsize_update, uid, size);
	} else {
		/* there's no way to get the size. recalculate the quota. */
		quota_recalculate(qbox->expunge_qt, QUOTA_RECALCULATE_MISSING_FREES);
		qbox->recalculate = TRUE;
	}
}

static int quota_mailbox_sync_deinit(struct mailbox_sync_context *ctx,
				     struct mailbox_sync_status *status_r)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT_REQUIRE(ctx->box);
	int ret;

	ret = qbox->module_ctx.super.sync_deinit(ctx, status_r);
	/* update quota only after syncing is finished. the quota commit may
	   recalculate the quota and cause all mailboxes to be synced,
	   including the one we're already syncing. */
	quota_mailbox_sync_commit(qbox);
	return ret;
}

static void quota_roots_flush(struct quota *quota)
{
	struct quota_root *const *roots;
	unsigned int i, count;

	roots = array_get(&quota->roots, &count);
	for (i = 0; i < count; i++) {
		if (roots[i]->backend.v.flush != NULL)
			roots[i]->backend.v.flush(roots[i]);
	}
}

static void quota_mailbox_close(struct mailbox *box)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT_REQUIRE(box);
	struct quota_user *quser = QUOTA_USER_CONTEXT_REQUIRE(box->storage->user);

	/* sync_notify() may be called outside sync_begin()..sync_deinit().
	   make sure we apply changes at close time at latest. */
	quota_mailbox_sync_commit(qbox);

	/* make sure quota backend flushes all data. this could also be done
	   somewhat later, but user.deinit() is too late, since the flushing
	   can trigger quota recalculation which isn't safe to do anymore
	   at user.deinit() when most of the loaded plugins have already been
	   deinitialized. */
	quota_roots_flush(quser->quota);

	qbox->module_ctx.super.close(box);
}

static void quota_mailbox_free(struct mailbox *box)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT_REQUIRE(box);

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

	v->get_status = quota_get_status;
	v->transaction_begin = quota_mailbox_transaction_begin;
	v->transaction_commit = quota_mailbox_transaction_commit;
	v->transaction_rollback = quota_mailbox_transaction_rollback;
	v->save_begin = quota_save_begin;
	v->save_finish = quota_save_finish;
	v->copy = quota_copy;
	v->sync_notify = quota_mailbox_sync_notify;
	v->sync_deinit = quota_mailbox_sync_deinit;
	v->close = quota_mailbox_close;
	v->free = quota_mailbox_free;
	MODULE_CONTEXT_SET(box, quota_storage_module, qbox);
}

static void quota_mailbox_list_deinit(struct mailbox_list *list)
{
	struct quota_mailbox_list *qlist = QUOTA_LIST_CONTEXT(list);

	i_assert(qlist != NULL);
	quota_remove_user_namespace(list->ns);
	qlist->module_ctx.super.deinit(list);
}

struct quota *quota_get_mail_user_quota(struct mail_user *user)
{
	struct quota_user *quser = QUOTA_USER_CONTEXT(user);

	return quser == NULL ? NULL : quser->quota;
}

static void quota_user_deinit(struct mail_user *user)
{
	struct quota_user *quser = QUOTA_USER_CONTEXT_REQUIRE(user);
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
	} else {
		e_debug(user->event, "quota: No quota setting - plugin disabled");
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
	struct mail_user *quota_user;
	bool add;

	/* see if we have a quota explicitly defined for this namespace */
	quota = quota_get_mail_user_quota(list->ns->user);
	if (quota == NULL)
		return;
	root = quota_find_root_for_ns(quota, list->ns);
	if (root != NULL) {
		/* explicit quota root */
		root->ns = list->ns;
		quota_user = list->ns->user;
	} else {
		quota_user = list->ns->owner != NULL ?
			list->ns->owner : list->ns->user;
	}

	if ((list->ns->flags & NAMESPACE_FLAG_NOQUOTA) != 0)
		add = FALSE;
	else if (list->ns->owner == NULL) {
		/* public namespace - add quota only if namespace is
		   explicitly defined for it */
		add = root != NULL;
	} else {
		/* for shared namespaces add only if the owner has quota
		   enabled */
		add = QUOTA_USER_CONTEXT(quota_user) != NULL;
	}

	if (add) {
		struct mailbox_list_vfuncs *v = list->vlast;

		qlist = p_new(list->pool, struct quota_mailbox_list, 1);
		qlist->module_ctx.super = *v;
		list->vlast = &qlist->module_ctx.super;
		v->deinit = quota_mailbox_list_deinit;
		MODULE_CONTEXT_SET(list, quota_mailbox_list_module, qlist);

		quota = quota_get_mail_user_quota(quota_user);
		i_assert(quota != NULL);
		quota_add_user_namespace(quota, list->ns);
	}
}

static void quota_root_set_namespace(struct quota_root *root,
				     struct mail_namespace *namespaces)
{
	const struct quota_rule *rule;
	const char *name;
	struct mail_namespace *ns;
	/* silence errors for autocreated (shared) users */
	bool silent_errors = namespaces->user->autocreated;

	if (root->ns_prefix != NULL && root->ns == NULL) {
		root->ns = mail_namespace_find_prefix(namespaces,
						      root->ns_prefix);
		if (root->ns == NULL && !silent_errors) {
			i_error("quota: Unknown namespace: %s",
				root->ns_prefix);
		}
	}

	array_foreach(&root->set->rules, rule) {
		name = rule->mailbox_mask;
		ns = mail_namespace_find(namespaces, name);
		if ((ns->flags & NAMESPACE_FLAG_UNUSABLE) != 0 &&
		    !silent_errors)
			i_error("quota: Unknown namespace: %s", name);
	}
}

void quota_mail_namespaces_created(struct mail_namespace *namespaces)
{
	struct quota *quota;
	struct quota_root *const *roots;
	unsigned int i, count;

	quota = quota_get_mail_user_quota(namespaces->user);
	if (quota == NULL)
		return;
	roots = array_get(&quota->roots, &count);
	for (i = 0; i < count; i++)
		quota_root_set_namespace(roots[i], namespaces);

	quota_over_flag_check_startup(quota);
}
