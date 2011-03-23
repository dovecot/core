#ifndef DOVEADM_MAIL_ITER_H
#define DOVEADM_MAIL_ITER_H

struct doveadm_mail_iter;

int doveadm_mail_iter_init(const struct mailbox_info *info,
			   struct mail_search_args *search_args,
			   struct mailbox_transaction_context **trans_r,
			   struct doveadm_mail_iter **iter_r);
int doveadm_mail_iter_deinit(struct doveadm_mail_iter **iter);
int doveadm_mail_iter_deinit_sync(struct doveadm_mail_iter **iter);
void doveadm_mail_iter_deinit_rollback(struct doveadm_mail_iter **iter);

bool doveadm_mail_iter_next(struct doveadm_mail_iter *iter, struct mail *mail);

#endif

