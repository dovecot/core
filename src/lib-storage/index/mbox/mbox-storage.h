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
		       enum mailbox_list_flags flags, int *sorted);
int mbox_list_mailbox_deinit(struct mailbox_list_context *ctx);
struct mailbox_list *mbox_list_mailbox_next(struct mailbox_list_context *ctx);

int mbox_expunge_locked(struct index_mailbox *ibox, int notify);

int mbox_is_valid_mask(const char *mask);

#endif
