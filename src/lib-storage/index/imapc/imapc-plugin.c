/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "imapc-list.h"
#include "imapc-storage.h"
#include "imapc-plugin.h"

const char *imapc_plugin_version = DOVECOT_ABI_VERSION;

void imapc_plugin_init(struct module *module ATTR_UNUSED)
{
	mail_storage_class_unregister(&imapc_stub_storage);
	mail_storage_class_register(&imapc_storage);
	mailbox_list_register(&imapc_mailbox_list);
}

void imapc_plugin_deinit(void)
{
	mail_storage_class_unregister(&imapc_storage);
	mailbox_list_unregister(&imapc_mailbox_list);
}
