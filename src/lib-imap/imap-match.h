#ifndef __IMAP_MATCH_H
#define __IMAP_MATCH_H

typedef struct _ImapMatchGlob ImapMatchGlob;

/* If inboxcase is TRUE, the "INBOX" string at the beginning of line is
   compared case-insensitively */
const ImapMatchGlob *imap_match_init(const char *str, int inboxcase,
				     char separator);

/* returns -1 if no match, otherwise length of match or partial-match
 *  glob      pre-processed glob string
 *  ptr       string to perform glob on
 *  len       length of ptr string (if 0, strlen() is used)
 *  min       pointer to minimum length of a valid partial-match.
 *            Set to -1 if no more matches.  Set to return value + 1
 *     	      if another match is possible.  If NULL, no partial-matches
 *            are returned.
 */
int imap_match(const ImapMatchGlob *glob, const char *ptr, int len, int *min);

#endif
