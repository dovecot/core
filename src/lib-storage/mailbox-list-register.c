/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mailbox-list.h"

extern struct mailbox_list maildir_mailbox_list;
extern struct mailbox_list imapdir_mailbox_list;
extern struct mailbox_list fs_mailbox_list;
extern struct mailbox_list index_mailbox_list;
extern struct mailbox_list imapc_mailbox_list;
extern struct mailbox_list none_mailbox_list;
extern struct mailbox_list shared_mailbox_list;

void mailbox_list_index_init(void);

void mailbox_list_register_all(void)
{
	mailbox_list_register(&maildir_mailbox_list);
	mailbox_list_register(&imapdir_mailbox_list);
	mailbox_list_register(&fs_mailbox_list);
	mailbox_list_register(&index_mailbox_list);
	mailbox_list_register(&imapc_mailbox_list);
	mailbox_list_register(&none_mailbox_list);
	mailbox_list_register(&shared_mailbox_list);
	mailbox_list_index_init();
}
