#ifndef DOVEADM_MAIL_ITER_H
#define DOVEADM_MAIL_ITER_H

#include "mailbox-list-iter.h"

struct doveadm_mail_iter;
struct doveadm_mail_cmd_context;

int doveadm_mail_iter_init(struct doveadm_mail_cmd_context *ctx,
			   const struct mailbox_info *info,
			   struct mail_search_args *search_args,
			   enum mail_fetch_field wanted_fields,
			   const char *const *wanted_headers,
			   struct doveadm_mail_iter **iter_r) ATTR_NULL(5);
int doveadm_mail_iter_deinit(struct doveadm_mail_iter **iter);
int doveadm_mail_iter_deinit_sync(struct doveadm_mail_iter **iter);
int doveadm_mail_iter_deinit_keep_box(struct doveadm_mail_iter **iter,
				      struct mailbox **box_r);
void doveadm_mail_iter_deinit_rollback(struct doveadm_mail_iter **iter);
struct mailbox *doveadm_mail_iter_get_mailbox(struct doveadm_mail_iter *iter);

bool doveadm_mail_iter_next(struct doveadm_mail_iter *iter,
			    struct mail **mail_r);

#endif

