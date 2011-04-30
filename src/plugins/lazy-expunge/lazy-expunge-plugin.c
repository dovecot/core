/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "seq-range-array.h"
#include "mkdir-parents.h"
#include "mail-storage-private.h"
#include "mail-search-build.h"
#include "mailbox-list-private.h"
#include "mail-namespace.h"
#include "lazy-expunge-plugin.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>

#define LAZY_EXPUNGE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lazy_expunge_mail_storage_module)
#define LAZY_EXPUNGE_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lazy_expunge_mailbox_list_module)
#define LAZY_EXPUNGE_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lazy_expunge_mail_user_module)
#define LAZY_EXPUNGE_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, lazy_expunge_mail_module)

struct lazy_expunge_mail_user {
	union mail_user_module_context module_ctx;

	struct mail_namespace *lazy_ns;
	const char *env;
};

struct lazy_expunge_mailbox_list {
	union mailbox_list_module_context module_ctx;

	unsigned int allow_rename:1;
	unsigned int internal_namespace:1;
};

struct lazy_expunge_transaction {
	union mailbox_transaction_module_context module_ctx;

	struct mailbox *dest_box;
	struct mailbox_transaction_context *dest_trans;

	bool failed;
};

const char *lazy_expunge_plugin_version = DOVECOT_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(lazy_expunge_mail_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(lazy_expunge_mail_module,
				  &mail_module_register);
static MODULE_CONTEXT_DEFINE_INIT(lazy_expunge_mailbox_list_module,
				  &mailbox_list_module_register);
static MODULE_CONTEXT_DEFINE_INIT(lazy_expunge_mail_user_module,
				  &mail_user_module_register);

static struct mailbox *
mailbox_open_or_create(struct mailbox_list *list, const char *name,
		       const char **error_r)
{
	struct mailbox *box;
	enum mail_error error;

	box = mailbox_alloc(list, name, MAILBOX_FLAG_KEEP_RECENT |
			    MAILBOX_FLAG_NO_INDEX_FILES);
	if (mailbox_open(box) == 0) {
		*error_r = NULL;
		return box;
	}

	*error_r = mailbox_get_last_error(box, &error);
	if (error != MAIL_ERROR_NOTFOUND) {
		mailbox_free(&box);
		return NULL;
	}

	/* try creating and re-opening it. */
	if (mailbox_create(box, NULL, FALSE) < 0 ||
	    mailbox_open(box) < 0) {
		*error_r = mailbox_get_last_error(box, NULL);
		mailbox_free(&box);
		return NULL;
	}
	return box;
}

static void lazy_expunge_mail_expunge(struct mail *_mail)
{
	struct mail_namespace *ns = _mail->box->list->ns;
	struct lazy_expunge_mail_user *luser =
		LAZY_EXPUNGE_USER_CONTEXT(ns->user);
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *mmail = LAZY_EXPUNGE_MAIL_CONTEXT(mail);
	struct lazy_expunge_transaction *lt =
		LAZY_EXPUNGE_CONTEXT(_mail->transaction);
	struct mail_save_context *save_ctx;
	const char *error;

	if (lt->dest_box == NULL) {
		lt->dest_box = mailbox_open_or_create(luser->lazy_ns->list,
						      _mail->box->name, &error);
		if (lt->dest_box == NULL) {
			mail_storage_set_critical(_mail->box->storage,
				"lazy_expunge: Couldn't open expunge mailbox: "
				"%s", error);
			lt->failed = TRUE;
			return;
		}
		if (mailbox_sync(lt->dest_box, 0) < 0) {
			mail_storage_set_critical(_mail->box->storage,
				"lazy_expunge: Couldn't sync expunge mailbox");
			mailbox_free(&lt->dest_box);
			lt->failed = TRUE;
			return;
		}

		lt->dest_trans = mailbox_transaction_begin(lt->dest_box,
					  MAILBOX_TRANSACTION_FLAG_EXTERNAL);
	}

	save_ctx = mailbox_save_alloc(lt->dest_trans);
	mailbox_save_copy_flags(save_ctx, _mail);
	save_ctx->flags &= ~MAIL_DELETED;
	if (mailbox_copy(&save_ctx, _mail) < 0 && !_mail->expunged)
		lt->failed = TRUE;
	mmail->super.expunge(_mail);
}

static struct mailbox_transaction_context *
lazy_expunge_transaction_begin(struct mailbox *box,
			       enum mailbox_transaction_flags flags)
{
	union mailbox_module_context *mbox = LAZY_EXPUNGE_CONTEXT(box);
	struct mailbox_transaction_context *t;
	struct lazy_expunge_transaction *lt;

	t = mbox->super.transaction_begin(box, flags);
	lt = i_new(struct lazy_expunge_transaction, 1);

	MODULE_CONTEXT_SET(t, lazy_expunge_mail_storage_module, lt);
	return t;
}

static void lazy_expunge_transaction_free(struct lazy_expunge_transaction *lt)
{
	if (lt->dest_trans != NULL)
		mailbox_transaction_rollback(&lt->dest_trans);
	if (lt->dest_box != NULL)
		mailbox_free(&lt->dest_box);
	i_free(lt);
}

static int
lazy_expunge_transaction_commit(struct mailbox_transaction_context *ctx,
				struct mail_transaction_commit_changes *changes_r)
{
	union mailbox_module_context *mbox = LAZY_EXPUNGE_CONTEXT(ctx->box);
	struct lazy_expunge_transaction *lt = LAZY_EXPUNGE_CONTEXT(ctx);
	int ret;

	if (lt->dest_trans != NULL && !lt->failed) {
		if (mailbox_transaction_commit(&lt->dest_trans) < 0)
			lt->failed = TRUE;
	}

	if (lt->failed) {
		mbox->super.transaction_rollback(ctx);
		ret = -1;
	} else {
		ret = mbox->super.transaction_commit(ctx, changes_r);
	}
	lazy_expunge_transaction_free(lt);
	return ret;
}

static void
lazy_expunge_transaction_rollback(struct mailbox_transaction_context *ctx)
{
	union mailbox_module_context *mbox = LAZY_EXPUNGE_CONTEXT(ctx->box);
	struct lazy_expunge_transaction *lt = LAZY_EXPUNGE_CONTEXT(ctx);

	mbox->super.transaction_rollback(ctx);
	lazy_expunge_transaction_free(lt);
}

static void lazy_expunge_mail_allocated(struct mail *_mail)
{
	struct lazy_expunge_transaction *lt =
		LAZY_EXPUNGE_CONTEXT(_mail->transaction);
	struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_vfuncs *v = mail->vlast;
	union mail_module_context *mmail;

	if (lt == NULL)
		return;

	mmail = p_new(mail->pool, union mail_module_context, 1);
	mmail->super = *v;
	mail->vlast = &mmail->super;

	v->expunge = lazy_expunge_mail_expunge;
	MODULE_CONTEXT_SET_SELF(mail, lazy_expunge_mail_module, mmail);
}

static int
lazy_expunge_mailbox_rename(struct mailbox *src, struct mailbox *dest,
			    bool rename_children)
{
	union mailbox_module_context *lbox = LAZY_EXPUNGE_CONTEXT(src);
	struct lazy_expunge_mailbox_list *src_llist =
		LAZY_EXPUNGE_LIST_CONTEXT(src->list);
	struct lazy_expunge_mailbox_list *dest_llist =
		LAZY_EXPUNGE_LIST_CONTEXT(dest->list);

	if (!src_llist->allow_rename &&
	    (src_llist->internal_namespace ||
	     dest_llist->internal_namespace)) {
		mail_storage_set_error(src->storage, MAIL_ERROR_NOTPOSSIBLE,
			"Can't rename mailboxes to/from expunge namespace.");
		return -1;
	}
	return lbox->super.rename(src, dest, rename_children);
}

static void lazy_expunge_mailbox_allocated(struct mailbox *box)
{
	struct lazy_expunge_mailbox_list *llist =
		LAZY_EXPUNGE_LIST_CONTEXT(box->list);
	union mailbox_module_context *mbox;
	struct mailbox_vfuncs *v = box->vlast;

	if (llist == NULL)
		return;

	mbox = p_new(box->pool, union mailbox_module_context, 1);
	mbox->super = *v;
	box->vlast = &mbox->super;
	MODULE_CONTEXT_SET_SELF(box, lazy_expunge_mail_storage_module, mbox);

	if (!llist->internal_namespace) {
		v->transaction_begin = lazy_expunge_transaction_begin;
		v->transaction_commit = lazy_expunge_transaction_commit;
		v->transaction_rollback = lazy_expunge_transaction_rollback;
		v->rename = lazy_expunge_mailbox_rename;
	} else {
		v->rename = lazy_expunge_mailbox_rename;
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

	if (list->ns->type == NAMESPACE_PRIVATE) {
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
	if (luser->lazy_ns == NULL)
		i_fatal("lazy_expunge: Unknown namespace: '%s'", luser->env);
	mail_namespace_ref(luser->lazy_ns);

	/* we don't want to override this namespace's expunge operation. */
	llist = LAZY_EXPUNGE_LIST_CONTEXT(luser->lazy_ns->list);
	llist->internal_namespace = TRUE;
}

static void lazy_expunge_user_deinit(struct mail_user *user)
{
	struct lazy_expunge_mail_user *luser = LAZY_EXPUNGE_USER_CONTEXT(user);

	mail_namespace_unref(&luser->lazy_ns);
	luser->module_ctx.super.deinit(user);
}

static void lazy_expunge_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct lazy_expunge_mail_user *luser;
	const char *env;

	env = mail_user_plugin_getenv(user, "lazy_expunge");
	if (env != NULL) {
		luser = p_new(user->pool, struct lazy_expunge_mail_user, 1);
		luser->module_ctx.super = *v;
		user->vlast = &luser->module_ctx.super;
		v->deinit = lazy_expunge_user_deinit;
		luser->env = env;

		MODULE_CONTEXT_SET(user, lazy_expunge_mail_user_module, luser);
	} else if (user->mail_debug) {
		i_debug("lazy_expunge: No lazy_expunge setting - "
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
