#ifndef __MAIL_COPY_H
#define __MAIL_COPY_H

int mail_storage_copy(struct mailbox_transaction_context *t, struct mail *mail,
		      struct mail **dest_mail_r);

#endif
