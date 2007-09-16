#ifndef MAIL_COPY_H
#define MAIL_COPY_H

int mail_storage_copy(struct mailbox_transaction_context *t, struct mail *mail,
		      enum mail_flags flags, struct mail_keywords *keywords,
		      struct mail *dest_mail);

#endif
