#ifndef IMAPC_ATTRIBUTE_H
#define IMAPC_ATTRIBUTE_H

#include "mail-storage-private.h"

int imapc_storage_attribute_set(struct mailbox_transaction_context *t,
				enum mail_attribute_type type_flags,
				const char *key,
				const struct mail_attribute_value *value);
int imapc_storage_attribute_get(struct mailbox *box,
				enum mail_attribute_type type_flags,
				const char *key,
				struct mail_attribute_value *value_r);
struct mailbox_attribute_iter *
imapc_storage_attribute_iter_init(struct mailbox *box,
				  enum mail_attribute_type type_flags,
				  const char *prefix);
const char *imapc_storage_attribute_iter_next(struct mailbox_attribute_iter *iter);
int imapc_storage_attribute_iter_deinit(struct mailbox_attribute_iter *iter);

#endif
