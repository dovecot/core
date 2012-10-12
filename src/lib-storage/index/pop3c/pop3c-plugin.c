/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "pop3c-storage.h"
#include "pop3c-settings.h"
#include "pop3c-plugin.h"

const char *pop3c_plugin_version = DOVECOT_ABI_VERSION;

void pop3c_plugin_init(struct module *module ATTR_UNUSED)
{
	mail_storage_class_unregister(&pop3c_stub_storage);
	mail_storage_class_register(&pop3c_storage);
}

void pop3c_plugin_deinit(void)
{
	mail_storage_class_unregister(&pop3c_storage);
}
