#ifndef DOVEADM_MAILBOX_LIST_ITER_H
#define DOVEADM_MAILBOX_LIST_ITER_H

#include "mailbox-list-iter.h"

struct doveadm_mail_cmd_context;

/* List only selectable mailboxes */
struct doveadm_mailbox_list_iter *
doveadm_mailbox_list_iter_init(struct doveadm_mail_cmd_context *ctx,
			       struct mail_user *user,
			       struct mail_search_args *search_args,
			       enum mailbox_list_iter_flags iter_flags);
/* List all mailboxes */
struct doveadm_mailbox_list_iter *
doveadm_mailbox_list_iter_full_init(struct doveadm_mail_cmd_context *ctx,
				    struct mail_user *user,
				    struct mail_search_args *search_args,
				    enum mailbox_list_iter_flags iter_flags);
int doveadm_mailbox_list_iter_deinit(struct doveadm_mailbox_list_iter **iter);

const struct mailbox_info *
doveadm_mailbox_list_iter_next(struct doveadm_mailbox_list_iter *iter);

#endif
