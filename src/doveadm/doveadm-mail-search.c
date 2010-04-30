/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"
#include "doveadm-mail-list-iter.h"
#include "doveadm-mail-iter.h"
#include "doveadm-mail.h"

#include <stdio.h>

static int
cmd_search_box(const struct mailbox_info *info,
	       struct mail_search_args *search_args)
{
	struct doveadm_mail_iter *iter;
	struct mailbox_transaction_context *trans;
	struct mail *mail;
	uint8_t guid[MAIL_GUID_128_SIZE];
	const char *guid_str;
	int ret;

	if (doveadm_mail_iter_init(info, search_args, &trans, &iter) < 0)
		return -1;

	mail = mail_alloc(trans, 0, NULL);
	if (mailbox_get_guid(mail->box, guid) < 0)
		ret = -1;
	else {
		guid_str = mail_guid_128_to_string(guid);
		while (doveadm_mail_iter_next(iter, mail))
			printf("mailbox-guid %s uid %u\n", guid_str, mail->uid);
	}
	mail_free(&mail);
	if (doveadm_mail_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

void cmd_search(struct mail_user *user, const char *const args[])
{
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_RAW_LIST |
		MAILBOX_LIST_ITER_VIRTUAL_NAMES |
		MAILBOX_LIST_ITER_NO_AUTO_INBOX |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct mail_search_args *search_args;
	struct doveadm_mail_list_iter *iter;
	const struct mailbox_info *info;

	if (args[0] == NULL)
		doveadm_mail_help_name("search");
	search_args = doveadm_mail_build_search_args(args);

	iter = doveadm_mail_list_iter_init(user, search_args, iter_flags);
	while ((info = doveadm_mail_list_iter_next(iter)) != NULL) T_BEGIN {
		(void)cmd_search_box(info, search_args);
	} T_END;
	doveadm_mail_list_iter_deinit(&iter);
}
