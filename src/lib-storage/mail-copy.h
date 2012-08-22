#ifndef MAIL_COPY_H
#define MAIL_COPY_H

struct mail;
struct mail_save_context;
struct mailbox;

int mail_storage_copy(struct mail_save_context *ctx, struct mail *mail);

/* If save context already doesn't have some metadata fields set, copy them
   from the given mail (e.g. received date, from envelope, guid). */
int mail_save_copy_default_metadata(struct mail_save_context *ctx,
				    struct mail *mail);

/* Returns TRUE if mail can be copied using hard linking from src to dest.
   (Assuming the storage itself supports this.) */
bool mail_storage_copy_can_use_hardlink(struct mailbox *src,
					struct mailbox *dest);

#endif
