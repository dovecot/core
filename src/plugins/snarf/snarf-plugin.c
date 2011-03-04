/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-namespace.h"
#include "mail-search-build.h"
#include "mail-storage-private.h"
#include "snarf-plugin.h"

#define SNARF_CONTEXT(obj) \
	MODULE_CONTEXT(obj, snarf_storage_module)

struct snarf_mail_storage {
	union mail_storage_module_context module_ctx;

	const char *snarf_path;
	bool snarfing_disabled;
};

struct snarf_mailbox {
	union mailbox_module_context module_ctx;
	struct mailbox *snarf_box;
};

const char *snarf_plugin_version = DOVECOT_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(snarf_storage_module,
				  &mail_storage_module_register);

static int snarf(struct mailbox *srcbox, struct mailbox *destbox)
{
	struct mail_search_args *search_args;
	struct mail_search_context *search_ctx;
        struct mailbox_transaction_context *src_trans, *dest_trans;
	struct mail_save_context *save_ctx;
	struct mail *mail;
	enum mail_error error;
	int ret;

	/* make sure the destination mailbox has been opened */
	if (mailbox_open(destbox) < 0)
		return -1;

	if (mailbox_sync(srcbox, MAILBOX_SYNC_FLAG_FULL_READ) < 0)
		return -1;

	src_trans = mailbox_transaction_begin(srcbox, 0);
	dest_trans = mailbox_transaction_begin(destbox,
					MAILBOX_TRANSACTION_FLAG_EXTERNAL);

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	search_ctx = mailbox_search_init(src_trans, search_args, NULL);
	mail_search_args_unref(&search_args);

	ret = 0;
	mail = mail_alloc(src_trans, MAIL_FETCH_STREAM_HEADER |
			  MAIL_FETCH_STREAM_BODY, NULL);
	while (mailbox_search_next(search_ctx, mail)) {
		if (mail->expunged)
			continue;

		save_ctx = mailbox_save_alloc(dest_trans);
		if (mailbox_copy(&save_ctx, mail) < 0 && !mail->expunged) {
			(void)mail_storage_get_last_error(destbox->storage,
							  &error);
			/* if we failed because of out of disk space, just
			   move those messages we managed to move so far. */
			if (error != MAIL_ERROR_NOSPACE)
				ret = -1;
			break;
		}
		mail_expunge(mail);
	}
	mail_free(&mail);

	if (mailbox_search_deinit(&search_ctx) < 0)
		ret = -1;

	/* commit the copied messages to the destination mailbox. if we crash
	   between that and between expunging the messages from the source
	   mailbox, we're left with duplicates. */
	if (ret < 0)
		mailbox_transaction_rollback(&dest_trans);
	else if (mailbox_transaction_commit(&dest_trans) < 0)
		ret = -1;

	if (ret < 0)
		mailbox_transaction_rollback(&src_trans);
	else {
		if (mailbox_transaction_commit(&src_trans) < 0)
			ret = -1;
	}
	if (ret == 0) {
		if (mailbox_sync(srcbox, 0) < 0)
			ret = -1;
	}
	return ret;
}

static struct mailbox_sync_context *
snarf_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct snarf_mailbox *sbox = SNARF_CONTEXT(box);

	(void)snarf(sbox->snarf_box, box);
	return sbox->module_ctx.super.sync_init(box, flags);
}

static void snarf_mailbox_free(struct mailbox *box)
{
	struct snarf_mailbox *sbox = SNARF_CONTEXT(box);

	mailbox_free(&sbox->snarf_box);
	sbox->module_ctx.super.free(box);
}

static bool
snarf_box_find(struct mail_user *user, struct mailbox_list **list_r,
	       const char **name_r)
{
	struct mail_namespace *snarf_ns;
	const char *snarf_name;

	snarf_name = mail_user_plugin_getenv(user, "snarf");
	if (snarf_name == NULL)
		return FALSE;

	snarf_ns = mail_namespace_find(user->namespaces, &snarf_name);
	if (snarf_ns == NULL) {
		i_error("snarf: Namespace not found for mailbox: %s",
			snarf_name);
		return FALSE;
	}
	*list_r = snarf_ns->list;
	*name_r = snarf_name;
	return TRUE;
}

static void snarf_mailbox_allocated(struct mailbox *box)
{
	struct snarf_mail_storage *sstorage = SNARF_CONTEXT(box->storage);
	struct mailbox_vfuncs *v = box->vlast;
	struct snarf_mailbox *sbox;
	struct mailbox_list *snarf_list;
	const char *snarf_name;

	if (!box->inbox_user)
		return;
	if (sstorage != NULL && sstorage->snarfing_disabled)
		return;

	if (!snarf_box_find(box->storage->user, &snarf_list, &snarf_name))
		return;

	sbox = p_new(box->pool, struct snarf_mailbox, 1);
	sbox->module_ctx.super = *v;
	box->vlast = &sbox->module_ctx.super;

	sbox->snarf_box = mailbox_alloc(snarf_list, snarf_name,
					MAILBOX_FLAG_KEEP_RECENT);

	v->sync_init = snarf_sync_init;
	v->free = snarf_mailbox_free;
	MODULE_CONTEXT_SET(box, snarf_storage_module, sbox);
}

static struct mailbox *
snarf_mailbox_alloc(struct mail_storage *storage,
		    struct mailbox_list *list, const char *name,
		    enum mailbox_flags flags)
{
	struct snarf_mail_storage *sstorage = SNARF_CONTEXT(storage);
	struct mail_namespace *ns = mailbox_list_get_namespace(list);
	struct mailbox *box;
	struct mailbox_list *snarf_list;
	const char *snarf_name;
	struct stat st;

	if (strcmp(name, "INBOX") == 0 &&
	    (ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
		if (stat(sstorage->snarf_path, &st) == 0)
			sstorage->snarfing_disabled = FALSE;
		else {
			if (errno != ENOENT) {
				mail_storage_set_critical(storage,
							  "stat(%s) failed: %m",
							  sstorage->snarf_path);
			}
			sstorage->snarfing_disabled = TRUE;
			/* use the snarf box as our real INBOX */
			if (snarf_box_find(storage->user, &snarf_list,
					   &snarf_name)) {
				list = snarf_list;
				name = snarf_name;
			}
		}
	}

	box = sstorage->module_ctx.super.
		mailbox_alloc(storage, list, name, flags);
	if (sstorage->snarfing_disabled) {
		box->inbox_user = TRUE;
		box->inbox_any = TRUE;
	}
	return box;
}

static void
snarf_mail_storage_create(struct mail_storage *storage, const char *path)
{
	struct snarf_mail_storage *mstorage;
	struct mail_storage_vfuncs *v = storage->vlast;

	path = mail_user_home_expand(storage->user, path);
	mstorage = p_new(storage->pool, struct snarf_mail_storage, 1);
	mstorage->snarf_path = p_strdup(storage->pool, path);
	mstorage->module_ctx.super = *v;
	storage->vlast = &mstorage->module_ctx.super;
	v->mailbox_alloc = snarf_mailbox_alloc;

	MODULE_CONTEXT_SET(storage, snarf_storage_module, mstorage);
}

static void snarf_mail_storage_created(struct mail_storage *storage)
{
	const char *path;

	/* snarfing is optional: do it only if the path specified
	   by mbox_snarf exists */
	path = mail_user_plugin_getenv(storage->user, "mbox_snarf");
	if (path != NULL)
		snarf_mail_storage_create(storage, path);
}

static struct mail_storage_hooks snarf_mail_storage_hooks = {
	.mailbox_allocated = snarf_mailbox_allocated,
	.mail_storage_created = snarf_mail_storage_created
};

void snarf_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &snarf_mail_storage_hooks);
}

void snarf_plugin_deinit(void)
{
	mail_storage_hooks_remove(&snarf_mail_storage_hooks);
}
