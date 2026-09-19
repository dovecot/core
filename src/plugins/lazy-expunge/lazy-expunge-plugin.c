/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "hash.h"
#include "settings.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "lazy-expunge-plugin.h"

#define LAZY_EXPUNGE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lazy_expunge_mail_storage_module)
#define LAZY_EXPUNGE_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, lazy_expunge_mail_storage_module)
#define LAZY_EXPUNGE_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lazy_expunge_mail_module)
#define LAZY_EXPUNGE_MAIL_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, lazy_expunge_mail_module)
#define LAZY_EXPUNGE_USER_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, lazy_expunge_mail_user_module)

struct lazy_expunge_mail_user {
	union mail_user_module_context module_ctx;

	/* refcount ID => number of instances of the mail that the user's
	   currently open transactions are expunging. The storage's refcount
	   isn't updated before the transactions are committed, so the
	   in-flight expunges need to be tracked here. */
	HASH_TABLE(char *, void *) refcount_ids;
};

struct lazy_expunge_mail {
	union mail_module_context module_ctx;
	bool moving;
	bool recursing;
};

struct lazy_expunge_mailbox {
	union mailbox_module_context module_ctx;
	const struct lazy_expunge_settings *set;
};

struct lazy_expunge_transaction {
	union mailbox_transaction_module_context module_ctx;

	struct mailbox *dest_box;
	struct mailbox_transaction_context *dest_trans;

	/* refcount IDs added by this transaction to
	   lazy_expunge_mail_user.refcount_ids */
	ARRAY(char *) refcount_ids;

	char *delayed_errstr;
	char *delayed_internal_errstr;
	enum mail_error delayed_error;
};

const char *lazy_expunge_plugin_version = DOVECOT_ABI_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(lazy_expunge_mail_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(lazy_expunge_mail_module,
				  &mail_module_register);
static MODULE_CONTEXT_DEFINE_INIT(lazy_expunge_mail_user_module,
				  &mail_user_module_register);

static struct mailbox *
mailbox_open_or_create(struct mail_user *user, const char *lazy_expunge_mailbox,
		       const char **error_r)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	enum mail_error error;

	ns = mail_namespace_find(user->namespaces, lazy_expunge_mailbox);
	box = mailbox_alloc(ns->list, lazy_expunge_mailbox,
			    MAILBOX_FLAG_NO_INDEX_FILES |
			    MAILBOX_FLAG_SAVEONLY | MAILBOX_FLAG_IGNORE_ACLS);
	if (mailbox_open(box) == 0) {
		*error_r = NULL;
		return box;
	}

	*error_r = mailbox_get_last_internal_error(box, &error);
	if (error != MAIL_ERROR_NOTFOUND) {
		*error_r = t_strdup_printf("Failed to open mailbox %s: %s",
					   lazy_expunge_mailbox, *error_r);
		mailbox_free(&box);
		return NULL;
	}

	/* try creating and re-opening it. */
	if (mailbox_create(box, NULL, FALSE) < 0 &&
	    mailbox_get_last_mail_error(box) != MAIL_ERROR_EXISTS) {
		*error_r = t_strdup_printf("Failed to create mailbox %s: %s",
					   lazy_expunge_mailbox,
					   mailbox_get_last_internal_error(box, NULL));
		mailbox_free(&box);
		return NULL;
	}
	if (mailbox_open(box) < 0) {
		*error_r = t_strdup_printf("Failed to open created mailbox %s: %s",
					   lazy_expunge_mailbox,
					   mailbox_get_last_internal_error(box, NULL));
		mailbox_free(&box);
		return NULL;
	}
	return box;
}

static unsigned int
lazy_expunge_refcount_id_add(struct mail_user *user,
			     struct lazy_expunge_transaction *lt,
			     const char *refcount_id)
{
	struct lazy_expunge_mail_user *luser =
		LAZY_EXPUNGE_USER_CONTEXT_REQUIRE(user);
	char *key;
	void *value;
	unsigned int count;

	if (!hash_table_is_created(luser->refcount_ids)) {
		hash_table_create(&luser->refcount_ids, default_pool, 0,
				  str_hash, strcmp);
	}
	if (hash_table_lookup_full(luser->refcount_ids, refcount_id,
				   &key, &value)) {
		count = POINTER_CAST_TO(value, unsigned int);
		hash_table_update(luser->refcount_ids, key,
				  POINTER_CAST(count + 1));
	} else {
		count = 0;
		key = i_strdup(refcount_id);
		hash_table_insert(luser->refcount_ids, key, POINTER_CAST(1U));
	}

	/* The key stays valid until the last transaction using it removes
	   it, so it can be used directly here. */
	if (!array_is_created(&lt->refcount_ids))
		i_array_init(&lt->refcount_ids, 4);
	array_push_back(&lt->refcount_ids, &key);
	return count;
}

static void
lazy_expunge_refcount_ids_remove(struct mail_user *user,
				 struct lazy_expunge_transaction *lt)
{
	struct lazy_expunge_mail_user *luser =
		LAZY_EXPUNGE_USER_CONTEXT_REQUIRE(user);
	char *key;

	if (!array_is_created(&lt->refcount_ids))
		return;

	array_foreach_elem(&lt->refcount_ids, key) {
		unsigned int count = POINTER_CAST_TO(
			hash_table_lookup(luser->refcount_ids, key),
			unsigned int);

		i_assert(count > 0);
		if (--count > 0) {
			hash_table_update(luser->refcount_ids, key,
					  POINTER_CAST(count));
		} else {
			hash_table_remove(luser->refcount_ids, key);
			i_free(key);
		}
	}
	array_free(&lt->refcount_ids);
}

static int lazy_expunge_mail_is_last_instance(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct lazy_expunge_transaction *lt =
		LAZY_EXPUNGE_CONTEXT_REQUIRE(_mail->transaction);
	const char *value, *errstr;
	unsigned long refcount;
	enum mail_error error;

	/* mail is reused by the search query, so the next mail_prefetch() on
	   it will try to prefetch the refcount */
	mail->wanted_fields |= MAIL_FETCH_REFCOUNT;

	if (mail_get_special(_mail, MAIL_FETCH_REFCOUNT, &value) < 0) {
		errstr = mailbox_get_last_internal_error(_mail->box, &error);
		if (error == MAIL_ERROR_EXPUNGED) {
			/* already expunged - just ignore it */
			return 0;
		}
		if (_mail->box->mailbox_deleted)
			return 0;
		mail_set_critical(_mail,
			"lazy_expunge: Couldn't lookup message's refcount: %s",
			errstr);
		return -1;
	}
	if (*value == '\0') {
		/* refcounts not supported by backend. assume all mails are
		   the last instance. */
		return 1;
	}
	if (str_to_ulong(value, &refcount) < 0)
		i_panic("Invalid mail refcount number: %s", value);
	if (refcount > 1) {
		/* this probably isn't the last instance of the mail, but
		   it's possible that the same mail was copied to this mailbox
		   multiple times and we're deleting more than one instance
		   within this transaction. in those cases each expunge will
		   see the same refcount, so we need to adjust the refcount
		   by tracking the expunged message's refcount IDs. */
		if (mail_get_special(_mail, MAIL_FETCH_REFCOUNT_ID, &value) < 0) {
			errstr = mailbox_get_last_internal_error(_mail->box, &error);
			if (error == MAIL_ERROR_EXPUNGED) {
				/* already expunged - just ignore it */
				return 0;
			}
			mail_set_critical(_mail,
				"lazy_expunge: Couldn't lookup message's refcount ID: %s", errstr);
			return -1;
		}
		if (*value == '\0') {
			/* refcount IDs not supported by backend, but refcounts
			   are? not with our current backends. */
			mail_set_critical(_mail,
				"lazy_expunge: Message unexpectedly has no refcount ID");
			return -1;
		}
		refcount -= lazy_expunge_refcount_id_add(
			_mail->box->storage->user, lt, value);
	}
	return refcount <= 1 ? 1 : 0;
}

static void lazy_expunge_set_error(struct lazy_expunge_transaction *lt,
				   struct mail_storage *storage)
{
	const char *errstr;
	enum mail_error error;

	errstr = mail_storage_get_last_error(storage, &error);
	if (error == MAIL_ERROR_EXPUNGED) {
		/* expunging failed because the mail was already expunged.
		   we don't want to fail because of that. */
		return;
	}

	if (lt->delayed_error != MAIL_ERROR_NONE)
		return;
	lt->delayed_error = error;
	lt->delayed_errstr = i_strdup(errstr);
	lt->delayed_internal_errstr =
		i_strdup(mail_storage_get_last_internal_error(storage, NULL));
}

static void lazy_expunge_mail_expunge_move(struct mail *_mail,
					   const char *lazy_expunge_mailbox)
{
	struct mail_namespace *ns = _mail->box->list->ns;
	struct mail_private *mail = (struct mail_private *)_mail;
	struct lazy_expunge_mail *mmail =
		LAZY_EXPUNGE_MAIL_CONTEXT_REQUIRE(mail);
	struct lazy_expunge_transaction *lt =
		LAZY_EXPUNGE_CONTEXT_REQUIRE(_mail->transaction);
	struct mail_save_context *save_ctx;
	const char *error;

	if (lt->dest_box == NULL) {
		lt->dest_box = mailbox_open_or_create(ns->user,
					lazy_expunge_mailbox, &error);
		if (lt->dest_box == NULL) {
			mail_set_critical(_mail,
				"lazy_expunge: Couldn't open expunge mailbox: "
				"%s", error);
			lazy_expunge_set_error(lt, _mail->box->storage);
			return;
		}
		if (mailbox_sync(lt->dest_box, 0) < 0) {
			mail_set_critical(_mail,
				"lazy_expunge: Couldn't sync expunge mailbox");
			lazy_expunge_set_error(lt, lt->dest_box->storage);
			mailbox_free(&lt->dest_box);
			return;
		}

		lt->dest_trans = mailbox_transaction_begin(lt->dest_box,
					  MAILBOX_TRANSACTION_FLAG_EXTERNAL,
					  __func__);
	}

	save_ctx = mailbox_save_alloc(lt->dest_trans);
	mailbox_save_copy_flags(save_ctx, _mail);
	save_ctx->data.flags &= ENUM_NEGATE(MAIL_DELETED);

	mmail->recursing = TRUE;
	if (mailbox_move(&save_ctx, _mail) < 0 && !_mail->expunged)
		lazy_expunge_set_error(lt, lt->dest_box->storage);
	mmail->recursing = FALSE;
	/* The destination mailbox's copy hook may have set this. Clear it, so
	   the next mail using this struct mail isn't treated as being moved
	   and expunged without being copied. */
	mmail->moving = FALSE;
}

static void lazy_expunge_mail_expunge(struct mail *_mail)
{
	struct lazy_expunge_transaction *lt =
		LAZY_EXPUNGE_CONTEXT_REQUIRE(_mail->transaction);
	struct mail_private *mail = (struct mail_private *)_mail;
	struct lazy_expunge_mail *mmail =
		LAZY_EXPUNGE_MAIL_CONTEXT_REQUIRE(mail);
	struct mail *real_mail;
	bool moving = mmail->moving;
	int ret;

	if (lt->delayed_error != MAIL_ERROR_NONE)
		return;
	if (mmail->recursing) {
		mmail->module_ctx.super.expunge(_mail);
		return;
	}

	/* Clear this in case the mail is used for non-move later on. */
	mmail->moving = FALSE;

	/* don't copy the mail if we're expunging from lazy_expunge
	   mailbox (even if it's via a virtual mailbox) */
	if (mail_get_backend_mail(_mail, &real_mail) < 0) {
		lazy_expunge_set_error(lt, _mail->box->storage);
		return;
	}
	struct lazy_expunge_mailbox *real_lbox =
		LAZY_EXPUNGE_CONTEXT_REQUIRE(real_mail->box);

	if (real_lbox->set->lazy_expunge_mailbox[0] == '\0' ||
	    strcmp(real_mail->box->vname, real_lbox->set->lazy_expunge_mailbox) == 0) {
		mmail->module_ctx.super.expunge(_mail);
		return;
	}

	struct event_reason *reason =
		event_reason_begin("lazy_expunge:expunge");
	if (!real_lbox->set->lazy_expunge_only_last_instance)
		ret = 1;
	else {
		/* we want to copy only the last instance of the mail to
		   lazy_expunge mailbox. other instances will be expunged
		   immediately. */
		if (moving)
			ret = 0;
		else {
			ret = lazy_expunge_mail_is_last_instance(_mail);
			if (ret < 0)
				lazy_expunge_set_error(lt, _mail->box->storage);
		}
	}
	if (ret > 0)
		lazy_expunge_mail_expunge_move(_mail, real_lbox->set->lazy_expunge_mailbox);
	event_reason_end(&reason);

	if (ret == 0) {
		/* Not the last instance of the mail - expunge it normally.
		   Since this is a normal expunge, do it without the
		   reason_code. */
		mmail->module_ctx.super.expunge(_mail);
	}
}

static void lazy_expunge_mailbox_free(struct mailbox *box)
{
	struct lazy_expunge_mailbox *lbox = LAZY_EXPUNGE_CONTEXT_REQUIRE(box);

	settings_free(lbox->set);
	lbox->module_ctx.super.free(box);
}

static int lazy_expunge_copy(struct mail_save_context *ctx, struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct lazy_expunge_mailbox *lbox =
		LAZY_EXPUNGE_CONTEXT_REQUIRE(ctx->transaction->box);
	struct lazy_expunge_mail *mmail = LAZY_EXPUNGE_MAIL_CONTEXT(mail);

	if (mmail != NULL)
		mmail->moving = ctx->moving;
	return lbox->module_ctx.super.copy(ctx, _mail);
}

static struct mailbox_transaction_context *
lazy_expunge_transaction_begin(struct mailbox *box,
			       enum mailbox_transaction_flags flags,
			       const char *reason)
{
	struct lazy_expunge_mailbox *lbox = LAZY_EXPUNGE_CONTEXT_REQUIRE(box);
	struct mailbox_transaction_context *t;
	struct lazy_expunge_transaction *lt;

	t = lbox->module_ctx.super.transaction_begin(box, flags, reason);
	lt = i_new(struct lazy_expunge_transaction, 1);

	MODULE_CONTEXT_SET(t, lazy_expunge_mail_storage_module, lt);
	return t;
}

static void lazy_expunge_transaction_free(struct mail_user *user,
					  struct lazy_expunge_transaction *lt)
{
	if (lt->dest_trans != NULL)
		mailbox_transaction_rollback(&lt->dest_trans);
	if (lt->dest_box != NULL)
		mailbox_free(&lt->dest_box);
	lazy_expunge_refcount_ids_remove(user, lt);
	i_free(lt->delayed_errstr);
	i_free(lt->delayed_internal_errstr);
	i_free(lt);
}

static int
lazy_expunge_transaction_commit(struct mailbox_transaction_context *ctx,
				struct mail_transaction_commit_changes *changes_r)
{
	struct lazy_expunge_mailbox *lbox =
		LAZY_EXPUNGE_CONTEXT_REQUIRE(ctx->box);
	struct lazy_expunge_transaction *lt = LAZY_EXPUNGE_CONTEXT_REQUIRE(ctx);
	struct mail_user *user = ctx->box->storage->user;
	int ret;

	if (lt->dest_trans != NULL && lt->delayed_error == MAIL_ERROR_NONE) {
		if (mailbox_transaction_commit(&lt->dest_trans) < 0) {
			lazy_expunge_set_error(lt, ctx->box->storage);
		}
	}

	if (lt->delayed_error == MAIL_ERROR_NONE)
		ret = lbox->module_ctx.super.transaction_commit(ctx, changes_r);
	else if (lt->delayed_error != MAIL_ERROR_TEMP) {
		mail_storage_set_error(ctx->box->storage, lt->delayed_error,
				       lt->delayed_errstr);
		lbox->module_ctx.super.transaction_rollback(ctx);
		ret = -1;
	} else {
		mailbox_set_critical(ctx->box,
			"Lazy-expunge transaction failed: %s",
			lt->delayed_internal_errstr);
		lbox->module_ctx.super.transaction_rollback(ctx);
		ret = -1;
	}
	lazy_expunge_transaction_free(user, lt);
	return ret;
}

static void
lazy_expunge_transaction_rollback(struct mailbox_transaction_context *ctx)
{
	struct lazy_expunge_mailbox *lbox =
		LAZY_EXPUNGE_CONTEXT_REQUIRE(ctx->box);
	struct lazy_expunge_transaction *lt = LAZY_EXPUNGE_CONTEXT_REQUIRE(ctx);
	struct mail_user *user = ctx->box->storage->user;

	lbox->module_ctx.super.transaction_rollback(ctx);
	lazy_expunge_transaction_free(user, lt);
}

static void lazy_expunge_mail_allocated(struct mail *_mail)
{
	struct lazy_expunge_transaction *lt =
		LAZY_EXPUNGE_CONTEXT(_mail->transaction);
	struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_vfuncs *v = mail->vlast;
	struct lazy_expunge_mail *mmail;

	if (lt == NULL)
		return;

	mmail = p_new(mail->pool, struct lazy_expunge_mail, 1);
	mmail->module_ctx.super = *v;
	mail->vlast = &mmail->module_ctx.super;

	v->expunge = lazy_expunge_mail_expunge;
	MODULE_CONTEXT_SET(mail, lazy_expunge_mail_module, mmail);
}

static void lazy_expunge_mailbox_allocated(struct mailbox *box)
{
	struct lazy_expunge_mailbox *lbox;
	struct mailbox_vfuncs *v = box->vlast;
	const char *error;

	if (box->list->ns->type != MAIL_NAMESPACE_TYPE_PRIVATE ||
	    (box->flags & MAILBOX_FLAG_DELETE_UNSAFE) != 0)
		return;
	if (box->virtual_vfuncs != NULL) {
		/* Virtual mailbox - the expunges are handled by the backend
		   mailboxes. Handling them here as well would process each
		   mail twice. */
		return;
	}

	lbox = p_new(box->pool, struct lazy_expunge_mailbox, 1);
	lbox->module_ctx.super = *v;
	box->vlast = &lbox->module_ctx.super;
	MODULE_CONTEXT_SET(box, lazy_expunge_mail_storage_module, lbox);

	if (settings_get(box->event, &lazy_expunge_setting_parser_info, 0,
			 &lbox->set, &error) < 0) {
		mailbox_set_critical(box, "%s", error);
		box->open_error = box->storage->error;
		return;
	}
	v->free = lazy_expunge_mailbox_free;

	if (strcmp(box->vname, lbox->set->lazy_expunge_mailbox) != 0) {
		v->copy = lazy_expunge_copy;
		v->transaction_begin = lazy_expunge_transaction_begin;
		v->transaction_commit = lazy_expunge_transaction_commit;
		v->transaction_rollback = lazy_expunge_transaction_rollback;
	} else {
		/* internal mailbox - don't add any unnecessary restrictions
		   to it. if it's not wanted, just use the ACL plugin. */
	}
}

static void lazy_expunge_mail_user_deinit(struct mail_user *user)
{
	struct lazy_expunge_mail_user *luser =
		LAZY_EXPUNGE_USER_CONTEXT_REQUIRE(user);

	if (hash_table_is_created(luser->refcount_ids)) {
		i_assert(hash_table_count(luser->refcount_ids) == 0);
		hash_table_destroy(&luser->refcount_ids);
	}
	luser->module_ctx.super.deinit(user);
}

static void lazy_expunge_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct lazy_expunge_mail_user *luser;

	luser = p_new(user->pool, struct lazy_expunge_mail_user, 1);
	luser->module_ctx.super = *v;
	user->vlast = &luser->module_ctx.super;
	v->deinit = lazy_expunge_mail_user_deinit;
	MODULE_CONTEXT_SET(user, lazy_expunge_mail_user_module, luser);
}

static struct mail_storage_hooks lazy_expunge_mail_storage_hooks = {
	.mail_user_created = lazy_expunge_mail_user_created,
	.mailbox_allocated = lazy_expunge_mailbox_allocated,
	.mail_allocated = lazy_expunge_mail_allocated
};

void lazy_expunge_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &lazy_expunge_mail_storage_hooks);
}

void lazy_expunge_plugin_deinit(void)
{
	mail_storage_hooks_remove(&lazy_expunge_mail_storage_hooks);
}
