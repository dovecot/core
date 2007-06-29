#ifndef __IMAP_MATCH_H
#define __IMAP_MATCH_H

enum imap_match_result {
	IMAP_MATCH_YES = 1, /* match */
	IMAP_MATCH_NO = -1, /* definite non-match */

	/* non-match, but its children could match (eg. "box" vs "box/%") */
	IMAP_MATCH_CHILDREN = 0,
	/* non-match, but one of its parents does match. This should often be
	   handled with YES matches, because when listing for "%" and "box/foo"
	   exists but "box" doesn't, you should still list "box" as
	   (Nonexistent Children) mailbox. */
	IMAP_MATCH_PARENT = -2
};

struct imap_match_glob;

/* If inboxcase is TRUE, the "INBOX" string at the beginning of line is
   compared case-insensitively */
struct imap_match_glob *
imap_match_init(pool_t pool, const char *pattern,
		bool inboxcase, char separator);

void imap_match_deinit(struct imap_match_glob **glob);

enum imap_match_result
imap_match(struct imap_match_glob *glob, const char *data);

#endif
