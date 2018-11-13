/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "settings.h"
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
	case QUOTA_ALLOC_RESULT_OVER_QUOTA_MAILBOX_LIMIT:
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
	if (quser->quota->vsizes)
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
quota_create_box(struct mailbox *box, const struct mailbox_update *update,
		 bool directory)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT_REQUIRE(box);
	const struct quota_settings *set;
	unsigned int mailbox_count;
	const char *error;

	if (settings_get(box->event, &quota_setting_parser_info, 0,
			 &set, &error) < 0) {
		mailbox_set_critical(box, "%s", error);
		return -1;
	}
	unsigned int quota_mailbox_count = set->quota_mailbox_count;
	settings_free(set);

	if (quota_mailbox_count == SET_UINT_UNLIMITED) {
		/* no mailbox count limit */
	} else if (mailbox_is_autocreated(box)) {
		/* Always allow autocreated mailbox to be created.
		   There shouldn't be many of them */
	} else if (mailbox_list_get_count(box->list, &mailbox_count) < 0) {
		mail_storage_copy_list_error(box->storage, box->list);
		return -1;
	} else if (mailbox_count >= quota_mailbox_count) {
		mail_storage_set_error(box->storage, MAIL_ERROR_LIMIT,
				       "Maximum number of mailboxes reached");
		return -1;
	}
	return qbox->module_ctx.super.create_box(box, update, directory);
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
		enum quota_alloc_result qret =
			quota_test_alloc(qt, 0, NULL, 0, NULL, &error);
		if (qret != QUOTA_ALLOC_RESULT_OK) {
			quota_set_storage_error(qt, box, qret, error);
			ret = -1;
		}
		quota_transaction_rollback(&qt);

		if ((items & ENUM_NEGATE(STATUS_CHECK_OVER_QUOTA)) == 0) {
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

static int quota_check(struct mail_save_context *ctx)
{
	struct mailbox_transaction_context *t = ctx->transaction;
	struct quota_transaction_context *qt = QUOTA_CONTEXT_REQUIRE(t);
	enum quota_alloc_result ret;

	if (qt->failed)
		return 0;

	const char *error;
	ret = quota_try_alloc(qt, ctx->dest_mail, ctx->expunged_mail,
			      NULL, &error);
	switch (ret) {
	case QUOTA_ALLOC_RESULT_OK:
		return 0;
	case QUOTA_ALLOC_RESULT_TEMPFAIL:
		/* Log the error, but allow saving anyway. */
		e_error(qt->quota->event,
			"Failed to check if user is under quota: %s - "
			"saving mail anyway", error);
		return 0;
	case QUOTA_ALLOC_RESULT_BACKGROUND_CALC:
		/* Could not determine if there is enough space due to ongoing
		   background quota calculation, allow saving anyway. */
		e_warning(qt->quota->event,
			  "Failed to check if user is under quota: %s - "
			  "saving mail anyway", error);
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
		if (error_res == QUOTA_GET_RESULT_BACKGROUND_CALC) {
			e_warning(qt->quota->event,
				  "%s - copying mail anyway", error);
		} else {
			e_error(qt->quota->event,
				"%s - copying mail anyway", error);
		}
	}

	if (qbox->module_ctx.super.copy(ctx, mail) < 0)
		return -1;

	if (ctx->copying_via_save) {
		/* copying used saving internally, we already checked the
		   quota */
		return 0;
	}
	return quota_check(ctx);
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
		struct mailbox *expunged_box = NULL;
		uoff_t expunged_size = 0;

		/* Input size is known, check for quota immediately. This
		   check isn't perfect, especially because input stream's
		   linefeeds may contain CR+LFs while physical message would
		   only contain LFs. With mbox some headers might be skipped
		   entirely.

		   I think these don't really matter though compared to the
		   benefit of giving "out of quota" error before sending the
		   full mail. */

		if (ctx->expunged_mail != NULL) {
			struct mail *expmail = ctx->expunged_mail;
			if (quota_get_mail_size(qt, expmail,
						&expunged_size) < 0) {
				enum mail_error err;
				error = mailbox_get_last_internal_error(
					expmail->box, &err);

				if (err != MAIL_ERROR_EXPUNGED) {
					e_error(qt->quota->event,
						"Failed to get size for expunged mail"
						"(box=%s, uid=%u): %s",
						expmail->box->vname,
						expmail->uid, error);
				}
			} else {
				expunged_box = expmail->box;
			}
		}

		enum quota_alloc_result qret =
			quota_test_alloc(qt, size, expunged_box, expunged_size,
					 NULL, &error);
		switch (qret) {
		case QUOTA_ALLOC_RESULT_OK:
			/* Great, there is space. */
			break;
		case QUOTA_ALLOC_RESULT_TEMPFAIL:
			/* Log the error, but allow saving anyway. */
			e_error(qt->quota->event,
				"Failed to check if user is under quota: %s - "
				"saving mail anyway", error);
			break;
		case QUOTA_ALLOC_RESULT_BACKGROUND_CALC:
			/* Could not determine if there is enough space due to
			 * ongoing background quota calculation, allow saving
			 * anyway. */
			e_warning(qt->quota->event,
				  "Failed to check if user is under quota: %s - "
				  "saving mail anyway", error);
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
			e_warning(qt->quota->event,
				  "%s - saving mail anyway", error);
		else
			e_error(qt->quota->event,
				"%s - saving mail anyway", error);
	}

	return qbox->module_ctx.super.save_begin(ctx, input);
}

static int quota_save_finish(struct mail_save_context *ctx)
{
	struct quota_mailbox *qbox = QUOTA_CONTEXT_REQUIRE(ctx->transaction->box);

	if (qbox->module_ctx.super.save_finish(ctx) < 0)
		return -1;

	return quota_check(ctx);
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
		if (ibox->vsize_update != NULL && quser->quota->vsizes)
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
	else if (!quser->quota->vsizes) {
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

	roots = array_get(&quota->all_roots, &count);
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

	v->create_box = quota_create_box;
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

	quota_deinit(&quser->quota);
	quser->module_ctx.super.deinit(user);
}

void quota_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct quota_user *quser;
	struct quota *quota;
	const char *error;

	if (quota_init(user, &quota, &error) < 0) {
		user->error = p_strdup_printf(user->pool,
			"Failed to initialize quota: %s", error);
		return;
	}
	quser = p_new(user->pool, struct quota_user, 1);
	quser->module_ctx.super = *v;
	user->vlast = &quser->module_ctx.super;
	v->deinit = quota_user_deinit;
	quser->quota = quota;

	MODULE_CONTEXT_SET(user, quota_user_module, quser);
}

static bool
quota_has_global_private_root(struct quota *quota, const char *root_name)
{
	struct quota_root *root;
	array_foreach_elem(&quota->global_private_roots, root) {
		if (strcmp(root->set->quota_name, root_name) == 0)
			return TRUE;
	}
	return FALSE;
}

void quota_mailbox_list_created(struct mailbox_list *list)
{
	struct quota_mailbox_list *qlist;
	struct quota *quota = NULL;
	struct mail_user *quota_user;
	const struct quota_settings *set;
	const char *root_name, *error;

	quota_user = list->ns->owner != NULL ?
		list->ns->owner : list->ns->user;
	quota = quota_get_mail_user_quota(quota_user);
	if (quota == NULL)
		return;

	if ((list->ns->flags & NAMESPACE_FLAG_NOQUOTA) != 0)
		return;

	if (settings_get(list->event, &quota_setting_parser_info, 0,
			 &set, &error) < 0) {
		e_error(list->event, "%s", error);
		return;
	}

	struct mailbox_list_vfuncs *v = list->vlast;

	qlist = p_new(list->pool, struct quota_mailbox_list, 1);
	qlist->module_ctx.super = *v;
	list->vlast = &qlist->module_ctx.super;
	v->deinit = quota_mailbox_list_deinit;
	MODULE_CONTEXT_SET(list, quota_mailbox_list_module, qlist);

	if (!array_is_created(&set->quota_roots)) {
		/* even without quota roots, the quota plugin still enforces
		   e.g. quota_mail_size, so the quota_mailbox_list must be
		   set. */
		settings_free(set);
		return;
	}

	quota = quota_get_mail_user_quota(quota_user);
	i_assert(quota != NULL);
	array_foreach_elem(&set->quota_roots, root_name) {
		/* All visible quota roots are used for private namespaces.
		   For shared/public namespaces use only quota roots explicitly
		   defined inside the namespace { .. } This means the quota root
		   name is not in the global_private_roots array. */
		if (list->ns->type == MAIL_NAMESPACE_TYPE_PRIVATE ||
		    !quota_has_global_private_root(quota, root_name))
			quota_add_user_namespace(quota, root_name, list->ns);
	}
	settings_free(set);
}

void quota_mail_namespaces_created(struct mail_namespace *namespaces)
{
	struct quota *quota;

	quota = quota_get_mail_user_quota(namespaces->user);
	if (quota == NULL)
		return;

	quota_over_status_check_startup(quota);
}
