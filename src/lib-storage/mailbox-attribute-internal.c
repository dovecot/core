/* Copyright (c) 2003-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage-private.h"
#include "mailbox-attribute-internal.h"

/*
 * Internal mailbox attributes
 */

 /* /private/specialuse (RFC 6154) */

static int
mailbox_attribute_specialuse_get(struct mailbox_transaction_context *t,
  const char *key ATTR_UNUSED,
	struct mail_attribute_value *value_r)
{
	const struct mailbox_settings *set = t->box->set;

	if (set == NULL || *set->special_use == '\0')
		return 0;

	value_r->value = set->special_use;
	return 1;
}

static struct mailbox_attribute_internal
iattr_mbox_prv_special_use = {
	.type = MAIL_ATTRIBUTE_TYPE_PRIVATE,
	.key = MAILBOX_ATTRIBUTE_SPECIALUSE,
	.rank = MAIL_ATTRIBUTE_INTERNAL_RANK_AUTHORITY,

	.get = mailbox_attribute_specialuse_get
};

/*
 * Registry
 */

void mailbox_attributes_internal_init(void)
{
	/*
	 * Internal mailbox attributes
	 */

	/* /private/specialuse (RFC 6154) */
	mailbox_attribute_register_internal(&iattr_mbox_prv_special_use);
}
