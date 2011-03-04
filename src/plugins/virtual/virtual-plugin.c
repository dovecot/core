/* Copyright (c) 2008-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-namespace.h"
#include "virtual-storage.h"
#include "virtual-plugin.h"

const char *virtual_plugin_version = DOVECOT_VERSION;

void virtual_plugin_init(struct module *module ATTR_UNUSED)
{
	mail_storage_class_register(&virtual_storage);
}

void virtual_plugin_deinit(void)
{
	mail_storage_class_unregister(&virtual_storage);
}
