#ifndef IMAP_EXPUNGE_H
#define IMAP_EXPUNGE_H

bool imap_expunge(struct mailbox *box, struct mail_search_arg *next_search_arg);

#endif
