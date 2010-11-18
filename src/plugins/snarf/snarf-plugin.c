/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-namespace.h"
#include "mail-search-build.h"
#include "mail-storage-private.h"
#include "snarf-plugin.h"

#define SNARF_CONTEXT(obj) \
	MODULE_CONTEXT(obj, snarf_storage_module)

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

static void snarf_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	struct snarf_mailbox *sbox;
	struct mail_namespace *snarf_ns;
	const char *snarf_name;

	if (!box->inbox_user)
		return;

	snarf_name = mail_user_plugin_getenv(box->storage->user, "snarf");
	if (snarf_name == NULL)
		return;

	snarf_ns = mail_namespace_find(box->storage->user->namespaces,
				       &snarf_name);
	if (snarf_ns == NULL) {
		i_error("snarf: Namespace not found for mailbox: %s",
			snarf_name);
		return;
	}

	sbox = p_new(box->pool, struct snarf_mailbox, 1);
	sbox->module_ctx.super = *v;
	box->vlast = &sbox->module_ctx.super;

	sbox->snarf_box = mailbox_alloc(snarf_ns->list, snarf_name,
					MAILBOX_FLAG_KEEP_RECENT);

	v->sync_init = snarf_sync_init;
	v->free = snarf_mailbox_free;
	MODULE_CONTEXT_SET(box, snarf_storage_module, sbox);
}

static struct mail_storage_hooks snarf_mail_storage_hooks = {
	.mailbox_allocated = snarf_mailbox_allocated
};

void snarf_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &snarf_mail_storage_hooks);
}

void snarf_plugin_deinit(void)
{
	mail_storage_hooks_remove(&snarf_mail_storage_hooks);
}
