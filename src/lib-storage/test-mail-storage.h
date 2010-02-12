#ifndef TEST_MAIL_STORAGE_H
#define TEST_MAIL_STORAGE_H

struct mail_storage *test_mail_storage_create(void);

struct mailbox *
test_mailbox_alloc(struct mail_storage *storage, struct mailbox_list *list,
		   const char *name, enum mailbox_flags flags);

struct mail *
test_mailbox_mail_alloc(struct mailbox_transaction_context *t,
			enum mail_fetch_field wanted_fields,
			struct mailbox_header_lookup_ctx *wanted_headers);

#endif
