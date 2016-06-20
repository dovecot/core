#ifndef INDEX_POP3_H
#define INDEX_POP3_H

struct mail_index_transaction;
struct mail;
struct mailbox;
struct mailbox_transaction_context;

void index_pop3_uidl_set_max_uid(struct mailbox *box,
				 struct mail_index_transaction *trans,
				 uint32_t uid);
bool index_pop3_uidl_can_exist(struct mail *mail);
void index_pop3_uidl_update_exists(struct mail *mail, bool exists);
void index_pop3_uidl_update_exists_finish(struct mailbox_transaction_context *trans);

#endif
