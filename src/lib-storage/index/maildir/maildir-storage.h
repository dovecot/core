#ifndef __MAILDIR_STORAGE_H
#define __MAILDIR_STORAGE_H

#include "index-storage.h"

int maildir_storage_copy(struct mailbox *box, struct mailbox *destbox,
			 const char *messageset, int uidset);

struct mail_save_context *
maildir_storage_save_init(struct mailbox *box, int transaction);
int maildir_storage_save_deinit(struct mail_save_context *ctx, int rollback);
int maildir_storage_save_next(struct mail_save_context *ctx,
			      const struct mail_full_flags *flags,
			      time_t received_date, int timezone_offset,
			      struct istream *data);

int maildir_find_mailboxes(struct mail_storage *storage, const char *mask,
			   mailbox_list_callback_t callback, void *context);
int maildir_find_subscribed(struct mail_storage *storage, const char *mask,
			    mailbox_list_callback_t callback, void *context);

int maildir_expunge_locked(struct index_mailbox *ibox, int notify);

/* Return new filename base to save into tmp/ */
const char *maildir_generate_tmp_filename(void);

#endif
