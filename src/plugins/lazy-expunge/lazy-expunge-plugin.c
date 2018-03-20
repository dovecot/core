/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "hash.h"
#include "seq-range-array.h"
#include "mkdir-parents.h"
#include "mail-storage-private.h"
#include "mail-search-build.h"
#include "mailbox-list-private.h"
#include "mail-namespace.h"
#include "lazy-expunge-plugin.h"

#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>

#define LAZY_EXPUNGE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lazy_expunge_mail_storage_module)
#define LAZY_EXPUNGE_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, lazy_expunge_mail_storage_module)
#define LAZY_EXPUNGE_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lazy_expunge_mailbox_list_module)
#define LAZY_EXPUNGE_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lazy_expunge_mail_user_module)
#define LAZY_EXPUNGE_USER_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, lazy_expunge_mail_user_module)
#define LAZY_EXPUNGE_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lazy_expunge_mail_module)
#define LAZY_EXPUNGE_MAIL_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, lazy_expunge_mail_module)

struct lazy_expunge_mail {
	union mail_module_context module_ctx;
	bool moving;
	bool recursing;
};

struct lazy_expunge_mail_user {
	union mail_user_module_context module_ctx;

	struct mail_namespace *lazy_ns;
	const char *lazy_mailbox_vname;
	const char *env;
	bool copy_only_last_instance;
};

struct lazy_expunge_mailbox_list {
	union mailbox_list_module_context module_ctx;

	bool allow_rename:1;
	bool internal_namespace:1;
};

struct lazy_expunge_transaction {
	union mailbox_transaction_module_context module_ctx;

	struct mailbox *dest_box;
	struct mailbox_transaction_context *dest_trans;

	pool_t pool;
	HASH_TABLE(const char *, void *) guids;

	char *delayed_errstr;
	char *delayed_internal_errstr;
	enum mail_error delayed_error;

	bool copy_only_last_instance;
};

const char *lazy_expunge_plugin_version = DOVECOT_ABI_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(lazy_expunge_mail_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(lazy_expunge_mail_module,
				  &mail_module_register);
static MODULE_CONTEXT_DEFINE_INIT(lazy_expunge_mailbox_list_module,
				  &mailbox_list_module_register);
static MODULE_CONTEXT_DEFINE_INIT(lazy_expunge_mail_user_module,
				  &mail_user_module_register);

static const char *
get_dest_vname(struct mailbox_list *list, struct mailbox *src_box)
{
	struct lazy_expunge_mail_user *luser =
		LAZY_EXPUNGE_USER_CONTEXT_REQUIRE(list->ns->user);
	const char *name;
	char src_sep, dest_sep;

	if (luser->lazy_mailbox_vname != NULL)
		return luser->lazy_mailbox_vname;

	/* use the (canonical / unaliased) storage name */
	name = src_box->name;
	/* replace hierarchy separators with destination virtual separator */
	src_sep = mailbox_list_get_hierarchy_sep(src_box->list);
	dest_sep = mail_namespace_get_sep(list->ns);
	if (src_sep != dest_sep) {
		string_t *str = t_str_new(128);
		unsigned int i;

		for (i = 0; name[i] != '\0'; i++) {
			if (name[i] == src_sep)
				str_append_c(str, dest_sep);
			else
				str_append_c(str, name[i]);
		}
		name = str_c(str);
	}
	/* add expunge namespace prefix. the name is now a proper vname */
	return t_strconcat(list->ns->prefix, name, NULL);
}

static struct mailbox *
mailbox_open_or_create(struct mailbox_list *list, struct mailbox *src_box,
		       const char **error_r)
{
	struct mailbox *box;
	enum mail_error error;
	const char *name;

	name = get_dest_vname(list, src_box);

	box = mailbox_alloc(list, name, MAILBOX_FLAG_NO_INDEX_FILES |
			    MAILBOX_FLAG_SAVEONLY | MAILBOX_FLAG_IGNORE_ACLS);
	mailbox_set_reason(box, "lazy_expunge");
	if (mailbox_open(box) == 0) {
		*error_r = NULL;
		return box;
	}

	*error_r = mailbox_get_last_internal_error(box, &error);
	if (error != MAIL_ERROR_NOTFOUND) {
		*error_r = t_strdup_printf("Failed to open mailbox %s: %s",
					   name, *error_r);
		mailbox_free(&box);
		return NULL;
	}

	/* try creating and re-opening it. */
	if (mailbox_create(box, NULL, FALSE) < 0 &&
	    mailbox_get_last_mail_error(box) != MAIL_ERROR_EXISTS) {
		*error_r = t_strdup_printf("Failed to create mailbox %s: %s", name,
					   mailbox_get_last_internal_error(box, NULL));
		mailbox_free(&box);
		return NULL;
	}
	if (mailbox_open(box) < 0) {
		*error_r = t_strdup_printf("Failed to open created mailbox %s: %s", name,
					   mailbox_get_last_internal_error(box, NULL));
		mailbox_free(&box);
		return NULL;
	}
	return box;
}

static unsigned int
lazy_expunge_count_in_transaction(struct lazy_expunge_transaction *lt,
				  const char *guid)
{
	void *refcountp;
	unsigned int refcount;

	if (lt->pool == NULL) {
		lt->pool = pool_alloconly_create("lazy expunge transaction",
						 1024);
		hash_table_create(&lt->guids, lt->pool, 0, str_hash, strcmp);
	}

	refcountp = hash_table_lookup(lt->guids, guid);
	refcount = POINTER_CAST_TO(refcountp, unsigned int) + 1;
	refcountp = POINTER_CAST(refcount);
	if (refcount == 1) {
		guid = p_strdup(lt->pool, guid);
		hash_table_insert(lt->guids, guid, refcountp);
	} else {
		hash_table_update(lt->guids, guid, refcountp);
	}
	return refcount-1;
}

static int lazy_expunge_mail_is_last_instance(struct mail *_mail)
{
	struct lazy_expunge_transaction *lt =
		LAZY_EXPUNGE_CONTEXT_REQUIRE(_mail->transaction);
	const char *value, *errstr;
	unsigned long refcount;
	enum mail_error error;

	if (mail_get_special(_mail, MAIL_FETCH_REFCOUNT, &value) < 0) {
		errstr = mailbox_get_last_internal_error(_mail->box, &error);
		if (error == MAIL_ERROR_EXPUNGED) {
			/* already expunged - just ignore it */
			return 0;
		}
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
		   by tracking the expunged message GUIDs. */
		if (mail_get_special(_mail, MAIL_FETCH_GUID, &value) < 0) {
			errstr = mailbox_get_last_internal_error(_mail->box, &error);
			if (error == MAIL_ERROR_EXPUNGED) {
				/* already expunged - just ignore it */
				return 0;
			}
			mail_set_critical(_mail,
				"lazy_expunge: Couldn't lookup message's GUID: %s", errstr);
			return -1;
		}
		if (*value == '\0') {
			/* GUIDs not supported by backend, but refcounts are?
			   not with our current backends. */
			mail_set_critical(_mail,
				"lazy_expunge: Message unexpectedly has no GUID");
			return -1;
		}
		refcount -= lazy_expunge_count_in_transaction(lt, value);
	}
	return refcount <= 1 ? 1 : 0;
}

static bool lazy_expunge_is_internal_mailbox(struct mailbox *box)
{
	struct mail_namespace *ns = box->list->ns;
	struct lazy_expunge_mail_user *luser =
		LAZY_EXPUNGE_USER_CONTEXT(ns->user);
	struct lazy_expunge_mailbox_list *llist =
		LAZY_EXPUNGE_LIST_CONTEXT(box->list);

	if (luser == NULL || llist == NULL) {
		/* lazy_expunge not enabled at all */
		return FALSE;
	}
	if (llist->internal_namespace) {
		/* lazy-expunge namespace */
		return TRUE;
	}
	if (luser->lazy_mailbox_vname != NULL &&
	    strcmp(luser->lazy_mailbox_vname, box->vname) == 0) {
		/* lazy-expunge mailbox */
		return TRUE;
	}
	return FALSE;
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

static void lazy_expunge_mail_expunge(struct mail *_mail)
{
	struct mail_namespace *ns = _mail->box->list->ns;
	struct lazy_expunge_mail_user *luser =
		LAZY_EXPUNGE_USER_CONTEXT_REQUIRE(ns->user);
	struct mail_private *mail = (struct mail_private *)_mail;
	struct lazy_expunge_mail *mmail = LAZY_EXPUNGE_MAIL_CONTEXT_REQUIRE(mail);
	struct lazy_expunge_transaction *lt =
		LAZY_EXPUNGE_CONTEXT_REQUIRE(_mail->transaction);
	struct mail *real_mail;
	struct mail_save_context *save_ctx;
	const char *error;
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
	   namespace (even if it's via a virtual mailbox) */
	if (mail_get_backend_mail(_mail, &real_mail) < 0) {
		lazy_expunge_set_error(lt, _mail->box->storage);
		return;
	}
	if (lazy_expunge_is_internal_mailbox(real_mail->box)) {
		mmail->module_ctx.super.expunge(_mail);
		return;
	}

	if (lt->copy_only_last_instance) {
		/* we want to copy only the last instance of the mail to
		   lazy_expunge namespace. other instances will be expunged
		   immediately. */
		if (moving)
			ret = 0;
		else if ((ret = lazy_expunge_mail_is_last_instance(_mail)) < 0) {
			lazy_expunge_set_error(lt, _mail->box->storage);
			return;
		}
		if (ret == 0) {
			mmail->module_ctx.super.expunge(_mail);
			return;
		}
	}

	if (lt->dest_box == NULL) {
		lt->dest_box = mailbox_open_or_create(luser->lazy_ns->list,
						      _mail->box, &error);
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
	save_ctx->data.flags &= ~MAIL_DELETED;

	mmail->recursing = TRUE;
	if (mailbox_move(&save_ctx, _mail) < 0 && !_mail->expunged)
		lazy_expunge_set_error(lt, lt->dest_box->storage);
	mmail->recursing = FALSE;
}

static int lazy_expunge_copy(struct mail_save_context *ctx, struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mailbox_module_context *mbox =
		LAZY_EXPUNGE_CONTEXT_REQUIRE(ctx->transaction->box);
	struct lazy_expunge_mail *mmail = LAZY_EXPUNGE_MAIL_CONTEXT(mail);

	if (mmail != NULL)
		mmail->moving = ctx->moving;
	return mbox->super.copy(ctx, _mail);
}

static struct mailbox_transaction_context *
lazy_expunge_transaction_begin(struct mailbox *box,
			       enum mailbox_transaction_flags flags,
			       const char *reason)
{
	struct lazy_expunge_mail_user *luser =
		LAZY_EXPUNGE_USER_CONTEXT_REQUIRE(box->list->ns->user);
	union mailbox_module_context *mbox = LAZY_EXPUNGE_CONTEXT_REQUIRE(box);
	struct mailbox_transaction_context *t;
	struct lazy_expunge_transaction *lt;

	t = mbox->super.transaction_begin(box, flags, reason);
	lt = i_new(struct lazy_expunge_transaction, 1);
	lt->copy_only_last_instance = luser->copy_only_last_instance;

	MODULE_CONTEXT_SET(t, lazy_expunge_mail_storage_module, lt);
	return t;
}

static void lazy_expunge_transaction_free(struct lazy_expunge_transaction *lt)
{
	if (lt->dest_trans != NULL)
		mailbox_transaction_rollback(&lt->dest_trans);
	if (lt->dest_box != NULL)
		mailbox_free(&lt->dest_box);
	if (hash_table_is_created(lt->guids))
		hash_table_destroy(&lt->guids);
	pool_unref(&lt->pool);
	i_free(lt->delayed_errstr);
	i_free(lt->delayed_internal_errstr);
	i_free(lt);
}

static int
lazy_expunge_transaction_commit(struct mailbox_transaction_context *ctx,
				struct mail_transaction_commit_changes *changes_r)
{
	union mailbox_module_context *mbox = LAZY_EXPUNGE_CONTEXT_REQUIRE(ctx->box);
	struct lazy_expunge_transaction *lt = LAZY_EXPUNGE_CONTEXT_REQUIRE(ctx);
	int ret;

	if (lt->dest_trans != NULL && lt->delayed_error == MAIL_ERROR_NONE) {
		if (mailbox_transaction_commit(&lt->dest_trans) < 0) {
			lazy_expunge_set_error(lt, ctx->box->storage);
		}
	}

	if (lt->delayed_error == MAIL_ERROR_NONE)
		ret = mbox->super.transaction_commit(ctx, changes_r);
	else if (lt->delayed_error != MAIL_ERROR_TEMP) {
		mail_storage_set_error(ctx->box->storage, lt->delayed_error,
				       lt->delayed_errstr);
		mbox->super.transaction_rollback(ctx);
		ret = -1;
	} else {
		mailbox_set_critical(ctx->box,
			"Lazy-expunge transaction failed: %s",
			lt->delayed_internal_errstr);
		mbox->super.transaction_rollback(ctx);
		ret = -1;
	}
	lazy_expunge_transaction_free(lt);
	return ret;
}

static void
lazy_expunge_transaction_rollback(struct mailbox_transaction_context *ctx)
{
	union mailbox_module_context *mbox = LAZY_EXPUNGE_CONTEXT_REQUIRE(ctx->box);
	struct lazy_expunge_transaction *lt = LAZY_EXPUNGE_CONTEXT_REQUIRE(ctx);

	mbox->super.transaction_rollback(ctx);
	lazy_expunge_transaction_free(lt);
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

static int
lazy_expunge_mailbox_rename(struct mailbox *src, struct mailbox *dest)
{
	union mailbox_module_context *lbox = LAZY_EXPUNGE_CONTEXT_REQUIRE(src);
	struct lazy_expunge_mailbox_list *src_llist =
		LAZY_EXPUNGE_LIST_CONTEXT(src->list);
	struct lazy_expunge_mailbox_list *dest_llist =
		LAZY_EXPUNGE_LIST_CONTEXT(dest->list);

	i_assert(src_llist != NULL && dest_llist != NULL);

	if (!src_llist->allow_rename &&
	    (src_llist->internal_namespace ||
	     dest_llist->internal_namespace)) {
		mail_storage_set_error(src->storage, MAIL_ERROR_NOTPOSSIBLE,
			"Can't rename mailboxes to/from expunge namespace.");
		return -1;
	}
	return lbox->super.rename_box(src, dest);
}

static void lazy_expunge_mailbox_allocated(struct mailbox *box)
{
	struct lazy_expunge_mailbox_list *llist =
		LAZY_EXPUNGE_LIST_CONTEXT(box->list);
	union mailbox_module_context *mbox;
	struct mailbox_vfuncs *v = box->vlast;

	if (llist == NULL || (box->flags & MAILBOX_FLAG_DELETE_UNSAFE) != 0)
		return;

	mbox = p_new(box->pool, union mailbox_module_context, 1);
	mbox->super = *v;
	box->vlast = &mbox->super;
	MODULE_CONTEXT_SET_SELF(box, lazy_expunge_mail_storage_module, mbox);

	if (!lazy_expunge_is_internal_mailbox(box)) {
		v->copy = lazy_expunge_copy;
		v->transaction_begin = lazy_expunge_transaction_begin;
		v->transaction_commit = lazy_expunge_transaction_commit;
		v->transaction_rollback = lazy_expunge_transaction_rollback;
		v->rename_box = lazy_expunge_mailbox_rename;
	} else if (llist->internal_namespace) {
		v->rename_box = lazy_expunge_mailbox_rename;
	} else {
		/* internal mailbox in a non-internal namespace -
		   don't add any unnecessary restrictions to it. if it's not
		   wanted, just use the ACL plugin. */
	}
}

static void lazy_expunge_mailbox_list_created(struct mailbox_list *list)
{
	struct lazy_expunge_mail_user *luser =
		LAZY_EXPUNGE_USER_CONTEXT(list->ns->user);
	struct lazy_expunge_mailbox_list *llist;

	if (luser == NULL)
		return;

	/* if this is one of our internal namespaces, mark it as such before
	   quota plugin sees it */
	if (strcmp(list->ns->prefix, luser->env) == 0)
		list->ns->flags |= NAMESPACE_FLAG_NOQUOTA;

	if (list->ns->type == MAIL_NAMESPACE_TYPE_PRIVATE) {
		llist = p_new(list->pool, struct lazy_expunge_mailbox_list, 1);
		MODULE_CONTEXT_SET(list, lazy_expunge_mailbox_list_module,
				   llist);
	}
}

static void
lazy_expunge_mail_namespaces_created(struct mail_namespace *namespaces)
{
	struct lazy_expunge_mail_user *luser =
		LAZY_EXPUNGE_USER_CONTEXT(namespaces->user);
	struct lazy_expunge_mailbox_list *llist;

	if (luser == NULL)
		return;

	luser->lazy_ns = mail_namespace_find_prefix(namespaces, luser->env);
	if (luser->lazy_ns != NULL) {
		/* we don't want to override this namespace's expunge operation. */
		llist = LAZY_EXPUNGE_LIST_CONTEXT(luser->lazy_ns->list);
		i_assert(llist != NULL);
		llist->internal_namespace = TRUE;
	} else {
		/* store the the expunged mails to the specified mailbox. */
		luser->lazy_ns = mail_namespace_find(namespaces, luser->env);
		luser->lazy_mailbox_vname = luser->env;
	}
	mail_namespace_ref(luser->lazy_ns);
}

static void lazy_expunge_user_deinit(struct mail_user *user)
{
	struct lazy_expunge_mail_user *luser = LAZY_EXPUNGE_USER_CONTEXT_REQUIRE(user);

	/* mail_namespaces_created hook isn't necessarily ever called */
	if (luser->lazy_ns != NULL)
		mail_namespace_unref(&luser->lazy_ns);
	luser->module_ctx.super.deinit(user);
}

static void lazy_expunge_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct lazy_expunge_mail_user *luser;
	const char *env;

	env = mail_user_plugin_getenv(user, "lazy_expunge");
	if (env != NULL && env[0] != '\0') {
		luser = p_new(user->pool, struct lazy_expunge_mail_user, 1);
		luser->module_ctx.super = *v;
		user->vlast = &luser->module_ctx.super;
		v->deinit = lazy_expunge_user_deinit;
		luser->env = env;
		luser->copy_only_last_instance =
			mail_user_plugin_getenv_bool(user, "lazy_expunge_only_last_instance");

		MODULE_CONTEXT_SET(user, lazy_expunge_mail_user_module, luser);
	} else {
		e_debug(user->event, "lazy_expunge: No lazy_expunge setting - "
			"plugin disabled");
	}
}

static struct mail_storage_hooks lazy_expunge_mail_storage_hooks = {
	.mail_user_created = lazy_expunge_mail_user_created,
	.mail_namespaces_created = lazy_expunge_mail_namespaces_created,
	.mailbox_list_created = lazy_expunge_mailbox_list_created,
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
