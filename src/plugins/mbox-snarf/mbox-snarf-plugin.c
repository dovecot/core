/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "home-expand.h"
#include "mail-search-build.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "mail-user.h"
#include "mbox-snarf-plugin.h"

#include <stdlib.h>
#include <sys/stat.h>

#define MBOX_SNARF_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mbox_snarf_storage_module)

struct mbox_snarf_mail_storage {
	union mail_storage_module_context module_ctx;

	const char *snarf_inbox_path;
	bool open_spool_inbox;
};

struct mbox_snarf_mailbox {
	union mailbox_module_context module_ctx;
};

const char *mbox_snarf_plugin_version = PACKAGE_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(mbox_snarf_storage_module,
				  &mail_storage_module_register);

static int mbox_snarf(struct mailbox *srcbox, struct mailbox *destbox)
{
	struct mail_search_args *search_args;
	struct mail_search_context *search_ctx;
        struct mailbox_transaction_context *src_trans, *dest_trans;
	struct mail_save_context *save_ctx;
	struct mail *mail;
	enum mail_error error;
	int ret;

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
mbox_snarf_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct mbox_snarf_mail_storage *mstorage =
		MBOX_SNARF_CONTEXT(box->storage);
	struct mbox_snarf_mailbox *mbox = MBOX_SNARF_CONTEXT(box);
	struct mailbox *spool_mbox;
	struct mailbox_sync_context *ctx;

	/* try to open the spool mbox */
	mstorage->open_spool_inbox = TRUE;
	spool_mbox = mailbox_alloc(box->list, "INBOX", NULL,
				   MAILBOX_FLAG_KEEP_RECENT |
				   MAILBOX_FLAG_NO_INDEX_FILES);
	mstorage->open_spool_inbox = FALSE;
	(void)mbox_snarf(spool_mbox, box);

	ctx = mbox->module_ctx.super.sync_init(box, flags);
	mailbox_close(&spool_mbox);
	return ctx;
}

static struct mailbox *
mbox_snarf_mailbox_alloc(struct mail_storage *storage,
			 struct mailbox_list *list,
			 const char *name, struct istream *input,
			 enum mailbox_flags flags)
{
	struct mbox_snarf_mail_storage *mstorage =
		MBOX_SNARF_CONTEXT(storage);
	struct mailbox *box;
	struct mbox_snarf_mailbox *mbox;
	struct stat st;
	enum mail_storage_flags old_flags = storage->flags;
	enum mailbox_list_flags old_list_flags;
	bool use_snarfing = FALSE;

	old_list_flags = list->flags;

	if (strcasecmp(name, "INBOX") == 0 && !mstorage->open_spool_inbox) {
		if (stat(mstorage->snarf_inbox_path, &st) == 0) {
			/* use ~/mbox as the INBOX */
			name = mstorage->snarf_inbox_path;
			use_snarfing = TRUE;
			//FIXME:storage->set->mail_full_filesystem_access = TRUE;
		} else if (errno != ENOENT) {
			mail_storage_set_critical(storage,
						  "stat(%s) failed: %m",
						  mstorage->snarf_inbox_path);
		}
	}

	box = mstorage->module_ctx.super.
		mailbox_alloc(storage, list, name, input, flags);
	storage->flags = old_flags;
	list->flags = old_list_flags;

	if (box == NULL || !use_snarfing)
		return box;

	mbox = p_new(box->pool, struct mbox_snarf_mailbox, 1);
	mbox->module_ctx.super = box->v;

	box->v.sync_init = mbox_snarf_sync_init;
	MODULE_CONTEXT_SET(box, mbox_snarf_storage_module, mbox);
	return box;
}

static void
mbox_snarf_mail_storage_create(struct mail_storage *storage, const char *path)
{
	struct mbox_snarf_mail_storage *mstorage;

	path = mail_user_home_expand(storage->user, path);
	mstorage = p_new(storage->pool, struct mbox_snarf_mail_storage, 1);
	mstorage->snarf_inbox_path = p_strdup(storage->pool, path);
	mstorage->module_ctx.super = storage->v;
	storage->v.mailbox_alloc = mbox_snarf_mailbox_alloc;

	MODULE_CONTEXT_SET(storage, mbox_snarf_storage_module, mstorage);
}

static void mbox_snarf_mail_storage_created(struct mail_storage *storage)
{
	const char *path;

	path = mail_user_plugin_getenv(storage->user, "mbox_snarf");
	if (path != NULL)
		mbox_snarf_mail_storage_create(storage, path);
}

static struct mail_storage_hooks mbox_snarf_mail_storage_hooks = {
	.mail_storage_created = mbox_snarf_mail_storage_created
};

void mbox_snarf_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &mbox_snarf_mail_storage_hooks);
}

void mbox_snarf_plugin_deinit(void)
{
	mail_storage_hooks_remove(&mbox_snarf_mail_storage_hooks);
}
