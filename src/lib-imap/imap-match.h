#ifndef __IMAP_MATCH_H
#define __IMAP_MATCH_H

enum imap_match_result {
	IMAP_MATCH_YES = 1, /* match */
	IMAP_MATCH_NO = -1, /* definite non-match */

	IMAP_MATCH_CHILDREN = 0, /* it's children might match */
	IMAP_MATCH_PARENT = -2 /* one of it's parents would match */
};

struct imap_match_glob;

/* If inboxcase is TRUE, the "INBOX" string at the beginning of line is
   compared case-insensitively */
struct imap_match_glob *
imap_match_init(pool_t pool, const char *mask, int inboxcase, char separator);

void imap_match_deinit(struct imap_match_glob *glob);

enum imap_match_result
imap_match(struct imap_match_glob *glob, const char *data);

#endif
