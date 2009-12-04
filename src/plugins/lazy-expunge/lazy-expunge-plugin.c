/* Copyright (c) 2006-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "seq-range-array.h"
#include "mkdir-parents.h"
#include "mail-storage-private.h"
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

enum lazy_namespace {
	LAZY_NAMESPACE_EXPUNGE,
	LAZY_NAMESPACE_DELETE,
	LAZY_NAMESPACE_DELETE_EXPUNGE,

	LAZY_NAMESPACE_COUNT
};

struct lazy_expunge_mail_user {
	union mail_user_module_context module_ctx;

	struct mail_namespace *lazy_ns[LAZY_NAMESPACE_COUNT];
	const char *env;
};

struct lazy_expunge_mailbox_list {
	union mailbox_list_module_context module_ctx;

	struct mailbox_list *expunge_list;
	bool internal_namespace;
};

struct lazy_expunge_transaction {
	union mailbox_transaction_module_context module_ctx;

	struct mailbox *dest_box;
	struct mailbox_transaction_context *dest_trans;

	bool failed;
};

const char *lazy_expunge_plugin_version = PACKAGE_VERSION;

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
	struct mail_storage *storage;
	enum mail_error error;

	box = mailbox_alloc(list, name, NULL, MAILBOX_FLAG_KEEP_RECENT |
			    MAILBOX_FLAG_NO_INDEX_FILES);
	if (mailbox_open(box) == 0) {
		*error_r = NULL;
		return box;
	}

	*error_r = mail_storage_get_last_error(mailbox_get_storage(box),
					       &error);
	if (error != MAIL_ERROR_NOTFOUND) {
		mailbox_close(&box);
		return NULL;
	}

	/* try creating and re-opening it. */
	storage = mail_namespace_get_default_storage(list->ns);
	if (mailbox_create(box, NULL, FALSE) < 0 ||
	    mailbox_open(box) < 0) {
		*error_r = mail_storage_get_last_error(mailbox_get_storage(box),
						       NULL);
		mailbox_close(&box);
		return NULL;
	}
	return box;
}

static struct mail_namespace *
get_lazy_ns(struct mail_user *user, enum lazy_namespace type)
{
	struct lazy_expunge_mail_user *luser = LAZY_EXPUNGE_USER_CONTEXT(user);

	return luser->lazy_ns[type];
}

static void lazy_expunge_mail_expunge(struct mail *_mail)
{
	struct mail_namespace *ns = _mail->box->list->ns;
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *mmail = LAZY_EXPUNGE_MAIL_CONTEXT(mail);
	struct lazy_expunge_transaction *lt =
		LAZY_EXPUNGE_CONTEXT(_mail->transaction);
	struct mail_namespace *dest_ns;
	struct mail_save_context *save_ctx;
	const char *error;

	dest_ns = get_lazy_ns(ns->user, LAZY_NAMESPACE_EXPUNGE);
	if (lt->dest_box == NULL) {
		lt->dest_box = mailbox_open_or_create(dest_ns->list,
						      _mail->box->name, &error);
		if (lt->dest_box == NULL) {
			mail_storage_set_critical(_mail->box->storage,
				"lazy_expunge: Couldn't open expunge mailbox: "
				"%s", error);
			lt->failed = TRUE;
			return;
		}
		if (mailbox_sync(lt->dest_box, 0, 0, NULL) < 0) {
			mail_storage_set_critical(_mail->box->storage,
				"lazy_expunge: Couldn't sync expunge mailbox");
			mailbox_close(&lt->dest_box);
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
		mailbox_close(&lt->dest_box);
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

static struct mail *
lazy_expunge_mail_alloc(struct mailbox_transaction_context *t,
			enum mail_fetch_field wanted_fields,
			struct mailbox_header_lookup_ctx *wanted_headers)
{
	union mailbox_module_context *mbox = LAZY_EXPUNGE_CONTEXT(t->box);
	union mail_module_context *mmail;
	struct mail *_mail;
	struct mail_private *mail;

	_mail = mbox->super.mail_alloc(t, wanted_fields, wanted_headers);
	mail = (struct mail_private *)_mail;

	mmail = p_new(mail->pool, union mail_module_context, 1);
	mmail->super = mail->v;

	mail->v.expunge = lazy_expunge_mail_expunge;
	MODULE_CONTEXT_SET_SELF(mail, lazy_expunge_mail_module, mmail);
	return _mail;
}

static void lazy_expunge_mailbox_allocated(struct mailbox *box)
{
	struct lazy_expunge_mailbox_list *llist =
		LAZY_EXPUNGE_LIST_CONTEXT(box->list);
	union mailbox_module_context *mbox;

	if (llist != NULL && !llist->internal_namespace) {
		mbox = p_new(box->pool, union mailbox_module_context, 1);
		mbox->super = box->v;

		box->v.transaction_begin = lazy_expunge_transaction_begin;
		box->v.transaction_commit = lazy_expunge_transaction_commit;
		box->v.transaction_rollback = lazy_expunge_transaction_rollback;
		box->v.mail_alloc = lazy_expunge_mail_alloc;
		MODULE_CONTEXT_SET_SELF(box, lazy_expunge_mail_storage_module,
					mbox);
	}
}

static int
mailbox_move(struct mailbox_list *src_list, const char *src_name,
	     struct mailbox_list *dest_list, const char **_dest_name)
{
	const char *dir, *origin, *dest_name = *_dest_name;
	enum mail_error error;
	mode_t mode;
	gid_t gid;

	/* make sure the destination root directory exists */
	mailbox_list_get_dir_permissions(dest_list, NULL, &mode, &gid, &origin);
	dir = mailbox_list_get_path(dest_list, NULL, MAILBOX_LIST_PATH_TYPE_DIR);
	if (mkdir_parents_chgrp(dir, mode, gid, origin) < 0 &&
	    errno != EEXIST) {
		mailbox_list_set_critical(src_list,
			"mkdir_parents(%s) failed: %m", dir);
		return -1;
	}

	while (mailbox_list_rename_mailbox(src_list, src_name,
					   dest_list, dest_name, FALSE) < 0) {
		mailbox_list_get_last_error(src_list, &error);
		switch (error) {
		case MAIL_ERROR_EXISTS:
			return -1;
		case MAIL_ERROR_NOTFOUND:
			return 0;
		default:
			break;
		}

		/* mailbox is being deleted multiple times per second.
		   update the filename. */
		dest_name = t_strdup_printf("%s-%04u", *_dest_name,
					    (uint32_t)random());
	}
	return 1;
}

static int
lazy_expunge_mailbox_list_delete(struct mailbox_list *list, const char *name)
{
	struct lazy_expunge_mailbox_list *llist =
		LAZY_EXPUNGE_LIST_CONTEXT(list);
	struct mail_namespace *src_ns, *dest_ns;
	enum mailbox_name_status status;
	const char *destname;
	struct tm *tm;
	char timestamp[256];
	int ret;

	if (llist->internal_namespace)
		return llist->module_ctx.super.delete_mailbox(list, name);

	/* first do the normal sanity checks */
	if (strcmp(name, "INBOX") == 0) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE,
				       "INBOX can't be deleted.");
		return -1;
	}

	if (mailbox_list_get_mailbox_name_status(list, name, &status) < 0)
		return -1;
	if (status == MAILBOX_NAME_INVALID) {
		mailbox_list_set_error(list, MAIL_ERROR_PARAMS,
				       "Invalid mailbox name");
		return -1;
	}

	/* destination mailbox name needs to contain a timestamp */
	tm = localtime(&ioloop_time);
	if (strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", tm) == 0)
		i_strocpy(timestamp, dec2str(ioloop_time), sizeof(timestamp));
	destname = t_strconcat(name, "-", timestamp, NULL);

	/* first move the actual mailbox */
	dest_ns = get_lazy_ns(list->ns->user, LAZY_NAMESPACE_DELETE);
	if ((ret = mailbox_move(list, name, dest_ns->list, &destname)) < 0)
		return -1;
	if (ret == 0) {
		mailbox_list_set_error(list, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
		return -1;
	}

	/* next move the expunged messages mailbox, if it exists */
	src_ns = get_lazy_ns(list->ns->user, LAZY_NAMESPACE_EXPUNGE);
	dest_ns = get_lazy_ns(list->ns->user, LAZY_NAMESPACE_DELETE_EXPUNGE);
	(void)mailbox_move(src_ns->list, name, dest_ns->list, &destname);
	return 0;
}

static void lazy_expunge_mailbox_list_created(struct mailbox_list *list)
{
	struct lazy_expunge_mail_user *luser =
		LAZY_EXPUNGE_USER_CONTEXT(list->ns->user);
	struct lazy_expunge_mailbox_list *llist;
	const char *const *p;
	unsigned int i;

	/* if this is one of our internal namespaces, mark it as such before
	   quota plugin sees it */
	p = t_strsplit_spaces(luser->env, " ");
	for (i = 0; i < LAZY_NAMESPACE_COUNT; i++, p++) {
		if (strcmp(list->ns->prefix, *p) == 0) {
			list->ns->flags |= NAMESPACE_FLAG_NOQUOTA;
			break;
		}
	}

	if (luser != NULL && list->ns->type == NAMESPACE_PRIVATE) {
		llist = p_new(list->pool, struct lazy_expunge_mailbox_list, 1);
		llist->module_ctx.super = list->v;
		list->v.delete_mailbox = lazy_expunge_mailbox_list_delete;

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
	const char *const *p;
	int i;

	if (luser == NULL)
		return;

	p = t_strsplit_spaces(luser->env, " ");
	for (i = 0; i < LAZY_NAMESPACE_COUNT; i++, p++) {
		const char *name = *p;

		if (name == NULL)
			i_fatal("lazy_expunge: Missing namespace #%d", i + 1);

		luser->lazy_ns[i] =
			mail_namespace_find_prefix(namespaces, name);
		if (luser->lazy_ns[i] == NULL)
			i_fatal("lazy_expunge: Unknown namespace: '%s'", name);

		/* we don't want to override these namespaces' expunge/delete
		   operations. */
		llist = LAZY_EXPUNGE_LIST_CONTEXT(luser->lazy_ns[i]->list);
		llist->internal_namespace = TRUE;
	}
}

static void lazy_expunge_mail_user_created(struct mail_user *user)
{
	struct lazy_expunge_mail_user *luser;
	const char *env;

	env = mail_user_plugin_getenv(user, "lazy_expunge");
	if (env != NULL) {
		luser = p_new(user->pool, struct lazy_expunge_mail_user, 1);
		luser->module_ctx.super = user->v;
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
	.mailbox_allocated = lazy_expunge_mailbox_allocated
};

void lazy_expunge_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &lazy_expunge_mail_storage_hooks);
}

void lazy_expunge_plugin_deinit(void)
{
	mail_storage_hooks_remove(&lazy_expunge_mail_storage_hooks);
}
