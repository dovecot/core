#ifndef FAIL_MAIL_STORAGE_H
#define FAIL_MAIL_STORAGE_H

struct mail_storage *fail_mail_storage_create(void);

struct mailbox *
fail_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		   const char *vname, enum mailbox_flags flags);

struct mail *
fail_mailbox_mail_alloc(struct mailbox_transaction_context *t,
			enum mail_fetch_field wanted_fields,
			struct mailbox_header_lookup_ctx *wanted_headers);

#endif
