#ifndef DOVEADM_MAIL_LIST_ITER_H
#define DOVEADM_MAIL_LIST_ITER_H

/* List only selectable mailboxes */
struct doveadm_mail_list_iter *
doveadm_mail_list_iter_init(struct mail_user *user,
			    struct mail_search_args *search_args,
			    enum mailbox_list_iter_flags iter_flags);
/* List all mailboxes */
struct doveadm_mail_list_iter *
doveadm_mail_list_iter_full_init(struct mail_user *user,
				 struct mail_search_args *search_args,
				 enum mailbox_list_iter_flags iter_flags);
void doveadm_mail_list_iter_deinit(struct doveadm_mail_list_iter **iter);

const struct mailbox_info *
doveadm_mail_list_iter_next(struct doveadm_mail_list_iter *iter);

#endif
