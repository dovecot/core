#ifndef __IMAP_MATCH_H
#define __IMAP_MATCH_H

struct imap_match_glob;

/* If inboxcase is TRUE, the "INBOX" string at the beginning of line is
   compared case-insensitively */
struct imap_match_glob *imap_match_init(const char *mask, int inboxcase,
					char separator);

/* Returns 1 if matched, 0 if it didn't match, but could match with additional
   hierarchies, -1 if definitely didn't match */
int imap_match(struct imap_match_glob *glob, const char *data);

#endif
