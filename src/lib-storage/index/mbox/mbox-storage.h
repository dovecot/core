#ifndef __MBOX_STORAGE_H
#define __MBOX_STORAGE_H

#include "index-storage.h"

int mbox_storage_copy(struct mailbox *box, struct mailbox *destbox,
		      const char *messageset, int uidset);

struct mail_save_context *
mbox_storage_save_init(struct mailbox *box, int transaction);
int mbox_storage_save_deinit(struct mail_save_context *ctx, int rollback);
int mbox_storage_save_next(struct mail_save_context *ctx,
			   const struct mail_full_flags *flags,
			   time_t received_date, int timezone_offset,
			   struct istream *data);

struct mailbox_list_context *
mbox_list_mailbox_init(struct mail_storage *storage, const char *mask,
		       enum mailbox_list_flags flags);
int mbox_list_mailbox_deinit(struct mailbox_list_context *ctx);
struct mailbox_list *mbox_list_mailbox_next(struct mailbox_list_context *ctx);

struct mail_expunge_context *
mbox_storage_expunge_init(struct mailbox *box,
			  enum mail_fetch_field wanted_fields, int expunge_all);
int mbox_storage_expunge_deinit(struct mail_expunge_context *ctx);
struct mail *mbox_storage_expunge_fetch_next(struct mail_expunge_context *ctx);
int mbox_storage_expunge(struct mail *mail, struct mail_expunge_context *ctx,
			 unsigned int *seq_r, int notify);

int mbox_is_valid_mask(const char *mask);

#endif
