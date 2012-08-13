#ifndef IMAP_LIST_H
#define IMAP_LIST_H

/* Returns TRUE if anything was added to the string. */
bool imap_mailbox_flags2str(string_t *str, enum mailbox_info_flags flags);

#endif
