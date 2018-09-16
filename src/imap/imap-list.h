#ifndef IMAP_LIST_H
#define IMAP_LIST_H

struct imap_list_return_flag_params {
	const char *name;
	const char *mutf7_name;

	enum mailbox_info_flags mbox_flags;
};

/* Returns TRUE if anything was added to the string. */
bool imap_mailbox_flags2str(string_t *str, enum mailbox_info_flags flags);

#endif
