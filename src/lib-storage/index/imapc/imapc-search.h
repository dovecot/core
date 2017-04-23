#ifndef IMAPC_SEARCH_H
#define IMAPC_SEARCH_H

struct mail_search_context *
imapc_search_init(struct mailbox_transaction_context *t,
		  struct mail_search_args *args,
		  const enum mail_sort_type *sort_program,
		  enum mail_fetch_field wanted_fields,
		  struct mailbox_header_lookup_ctx *wanted_headers);
bool imapc_search_next_update_seq(struct mail_search_context *ctx);
int imapc_search_deinit(struct mail_search_context *ctx);

void imapc_search_reply_search(const struct imap_arg *args,
			       struct imapc_mailbox *mbox);
void imapc_search_reply_esearch(const struct imap_arg *args,
				struct imapc_mailbox *mbox);

#endif
