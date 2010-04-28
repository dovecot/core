#ifndef IMAP_MATCH_H
#define IMAP_MATCH_H

enum imap_match_result {
	IMAP_MATCH_NO 		= 0x00, /* definite non-match */
	IMAP_MATCH_YES		= 0x01, /* match */

	/* YES and NO are returned alone, but CHILDREN and PARENT may be
	   returned both (eg. "foo*bar" vs. "foobar/baz") */

	/* non-match, but its children could match (eg. "box" vs "box/%") */
	IMAP_MATCH_CHILDREN	= 0x02,
	/* non-match, but one of its parents does match. This should often be
	   handled with YES matches, because when listing for "%" and "box/foo"
	   exists but "box" doesn't, you should still list "box" as
	   (Nonexistent HasChildren) mailbox. */
	IMAP_MATCH_PARENT	= 0x04
};

struct imap_match_glob;

/* If inboxcase is TRUE, the "INBOX" string at the beginning of line is
   compared case-insensitively */
struct imap_match_glob *
imap_match_init(pool_t pool, const char *pattern,
		bool inboxcase, char separator);
struct imap_match_glob *
imap_match_init_multiple(pool_t pool, const char *const *patterns,
			 bool inboxcase, char separator);
void imap_match_deinit(struct imap_match_glob **glob);

struct imap_match_glob *
imap_match_dup(pool_t pool, const struct imap_match_glob *glob);
/* Returns TRUE if two globs were created with same init() parameters
   (but inboxcase is ignored if no patterns can match INBOX) */
bool imap_match_globs_equal(const struct imap_match_glob *glob1,
			    const struct imap_match_glob *glob2);

enum imap_match_result
imap_match(struct imap_match_glob *glob, const char *data);

#endif
