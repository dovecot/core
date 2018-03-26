/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"

extern struct mail_storage shared_storage;
extern struct mail_storage dbox_storage;
extern struct mail_storage mdbox_storage;
extern struct mail_storage mdbox_deleted_storage;
extern struct mail_storage sdbox_storage;
extern struct mail_storage maildir_storage;
extern struct mail_storage mbox_storage;
extern struct mail_storage cydir_storage;
extern struct mail_storage imapc_storage;
extern struct mail_storage pop3c_storage;
extern struct mail_storage raw_storage;
extern struct mail_storage fail_storage;

void mail_storage_register_all(void)
{
	mail_storage_class_register(&shared_storage);
	mail_storage_class_register(&dbox_storage);
	mail_storage_class_register(&mdbox_storage);
	mail_storage_class_register(&mdbox_deleted_storage);
	mail_storage_class_register(&sdbox_storage);
	mail_storage_class_register(&maildir_storage);
	mail_storage_class_register(&mbox_storage);
	mail_storage_class_register(&cydir_storage);
	mail_storage_class_register(&imapc_storage);
	mail_storage_class_register(&pop3c_storage);
	mail_storage_class_register(&raw_storage);
	mail_storage_class_register(&fail_storage);
}
