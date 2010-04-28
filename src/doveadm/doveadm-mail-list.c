/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"
#include "mail-search-build.h"
#include "doveadm-mail-list-iter.h"
#include "doveadm-mail.h"

#include <stdio.h>

void cmd_list(struct mail_user *user, const char *const args[])
{
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_RAW_LIST |
		MAILBOX_LIST_ITER_VIRTUAL_NAMES |
		MAILBOX_LIST_ITER_NO_AUTO_INBOX |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct mail_search_args *search_args;
	struct mail_search_arg *arg;
	struct doveadm_mail_list_iter *iter;
	const struct mailbox_info *info;
	unsigned int i;

	search_args = mail_search_build_init();
	for (i = 0; args[i] != NULL; i++) {
		arg = mail_search_build_add(search_args, SEARCH_MAILBOX_GLOB);
		arg->value.str = p_strdup(search_args->pool, args[i]);
	}
	if (i > 1) {
		struct mail_search_arg *subargs = search_args->args;

		search_args->args = NULL;
		arg = mail_search_build_add(search_args, SEARCH_OR);
		arg->value.subargs = subargs;
	}

	iter = doveadm_mail_list_iter_init(user, search_args, iter_flags);
	while ((info = doveadm_mail_list_iter_next(iter)) != NULL) {
		printf("%s\n", info->name);
	}
	doveadm_mail_list_iter_deinit(&iter);
}
