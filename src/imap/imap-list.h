#ifndef IMAP_LIST_H
#define IMAP_LIST_H

#include "mailbox-list-iter.h"

struct imap_list_return_flag_params {
	const char *name;
	const char *mutf7_name;

	enum mailbox_info_flags mbox_flags;
	enum mailbox_list_iter_flags list_flags;
	struct mail_namespace *ns;
};

/* Returns TRUE if anything was added to the string. */
bool imap_mailbox_flags2str(string_t *str, enum mailbox_info_flags flags);

#endif
