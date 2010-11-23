#ifndef MAIL_COPY_H
#define MAIL_COPY_H

struct mail;
struct mail_save_context;
struct mailbox;

int mail_storage_copy(struct mail_save_context *ctx, struct mail *mail);

/* Returns TRUE if mail can be copied using hard linking from src to dest.
   (Assuming the storage itself supports this.) */
bool mail_storage_copy_can_use_hardlink(struct mailbox *src,
					struct mailbox *dest);

#endif
