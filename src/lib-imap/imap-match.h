#ifndef __IMAP_MATCH_H
#define __IMAP_MATCH_H

typedef struct _ImapMatchGlob ImapMatchGlob;

/* If inboxcase is TRUE, the "INBOX" string at the beginning of line is
   compared case-insensitively */
ImapMatchGlob *imap_match_init(const char *mask, int inboxcase, char separator);

/* Returns 1 if matched, 0 if it didn't match, but could match with additional
   hierarchies, -1 if definitely didn't match */
int imap_match(ImapMatchGlob *glob, const char *data);

#endif
