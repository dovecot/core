#ifndef __MAILDIR_STORAGE_H
#define __MAILDIR_STORAGE_H

#include "index-storage.h"

struct mail_copy_context *maildir_storage_copy_init(struct mailbox *box);
int maildir_storage_copy_deinit(struct mail_copy_context *ctx, int rollback);
int maildir_storage_copy(struct mail *mail, struct mail_copy_context *ctx);

struct mail_save_context *
maildir_storage_save_init(struct mailbox *box, int transaction);
int maildir_storage_save_deinit(struct mail_save_context *ctx, int rollback);
int maildir_storage_save_next(struct mail_save_context *ctx,
			      const struct mail_full_flags *flags,
			      time_t received_date, int timezone_offset,
			      struct istream *data);

struct mailbox_list_context *
maildir_list_mailbox_init(struct mail_storage *storage,
			  const char *mask, enum mailbox_list_flags flags,
			  int *sorted);
int maildir_list_mailbox_deinit(struct mailbox_list_context *ctx);
struct mailbox_list *
maildir_list_mailbox_next(struct mailbox_list_context *ctx);

struct mail_expunge_context *
maildir_storage_expunge_init(struct mailbox *box,
			     enum mail_fetch_field wanted_fields,
			     int expunge_all);
int maildir_storage_expunge_deinit(struct mail_expunge_context *ctx);
struct mail *
maildir_storage_expunge_fetch_next(struct mail_expunge_context *ctx);
int maildir_storage_expunge(struct mail *mail, struct mail_expunge_context *ctx,
			    unsigned int *seq_r, int notify);

const char *maildir_get_path(struct mail_storage *storage, const char *name);

#endif
