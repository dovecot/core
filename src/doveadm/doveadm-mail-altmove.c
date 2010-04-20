/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-index.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "mail-search-build.h"
#include "mail-search-parser.h"
#include "doveadm-mail.h"

static struct mail_search_args *build_search_args(const char *const args[])
{
	struct mail_search_parser *parser;
	struct mail_search_args *sargs;
	const char *error;

	parser = mail_search_parser_init_cmdline(args);
	if (mail_search_build(mail_search_register_human, parser, "UTF-8",
			      &sargs, &error) < 0)
		i_fatal("%s", error);
	mail_search_parser_deinit(&parser);
	return sargs;
}

static int
cmd_altmove_box(struct mailbox *box, struct mail_search_args *search_args)
{
	struct mail_storage *storage;
	struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	const char *box_name;
	int ret = 0;

	box_name = mailbox_get_vname(box);
	storage = mailbox_get_storage(box);
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		i_error("Syncing mailbox %s failed: %s", box_name,
			mail_storage_get_last_error(storage, NULL));
		return -1;
	}

	t = mailbox_transaction_begin(box, 0);
	search_ctx = mailbox_search_init(t, search_args, NULL);
	mail = mail_alloc(t, 0, NULL);
	while (mailbox_search_next(search_ctx, mail)) {
		if (doveadm_debug)
			i_debug("altmove: box=%s uid=%u", box_name, mail->uid);
		mail_update_flags(mail, MODIFY_ADD,
				  MAIL_INDEX_MAIL_FLAG_BACKEND);
	}
	mail_free(&mail);
	if (mailbox_search_deinit(&search_ctx) < 0) {
		i_error("Searching mailbox %s failed: %s", box_name,
			mail_storage_get_last_error(storage, NULL));
		ret = -1;
	}
	if (mailbox_transaction_commit(&t) < 0) {
		i_error("Commiting mailbox %s failed: %s", box_name,
			mail_storage_get_last_error(storage, NULL));
		ret = -1;
	}
	return ret;
}

static void
cmd_altmove_ns(struct mail_namespace *ns, struct mail_search_args *search_args)
{
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	struct mailbox *box;

	iter = mailbox_list_iter_init(ns->list, "*",
				      MAILBOX_LIST_ITER_RAW_LIST |
				      MAILBOX_LIST_ITER_NO_AUTO_INBOX |
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		box = mailbox_alloc(ns->list, info->name,
				    MAILBOX_FLAG_KEEP_RECENT |
				    MAILBOX_FLAG_IGNORE_ACLS);
		(void)cmd_altmove_box(box, search_args);
		mailbox_free(&box);
	}
	if (mailbox_list_iter_deinit(&iter) < 0) {
		i_error("Listing namespace '%s' mailboxes failed: %s",
			ns->prefix,
			mailbox_list_get_last_error(ns->list, NULL));
	}

	if (mail_storage_purge(ns->storage) < 0) {
		i_error("Purging namespace '%s' failed: %s", ns->prefix,
			mail_storage_get_last_error(ns->storage, NULL));
	}
}

void cmd_altmove(struct mail_user *user, const char *const args[])
{
	struct mail_search_args *search_args;
	struct mail_namespace *ns;

	if (args[0] == NULL)
		doveadm_mail_help_name("altmove");
	search_args = build_search_args(args);

	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->type != NAMESPACE_PRIVATE || ns->alias_for != NULL)
			continue;

		cmd_altmove_ns(ns, search_args);
	}
}
