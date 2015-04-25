#ifndef MAILBOX_ATTRIBUTE_PRIVATE_H
#define MAILBOX_ATTRIBUTE_PRIVATE_H

struct mailbox_attribute_iter {
	struct mailbox *box;
};

void mailbox_attributes_init(void);
void mailbox_attributes_deinit(void);

int mailbox_attribute_value_to_string(struct mail_storage *storage,
				      const struct mail_attribute_value *value,
				      const char **str_r);

#endif
