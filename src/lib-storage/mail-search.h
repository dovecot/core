#ifndef __MAIL_SEARCH_H
#define __MAIL_SEARCH_H

#include "imap-parser.h"
#include "mail-storage.h"

typedef enum {
	SEARCH_OR,
	SEARCH_SUB,

	/* message sets */
	SEARCH_ALL,
	SEARCH_SET,
	SEARCH_UID,

	/* flags */
	SEARCH_ANSWERED,
	SEARCH_DELETED,
	SEARCH_DRAFT,
	SEARCH_FLAGGED,
	SEARCH_SEEN,
	SEARCH_RECENT,
	SEARCH_KEYWORD,

	/* dates */
	SEARCH_BEFORE,
	SEARCH_ON,
	SEARCH_SINCE,
	SEARCH_SENTBEFORE,
	SEARCH_SENTON,
	SEARCH_SENTSINCE,

	/* sizes */
	SEARCH_SMALLER,
	SEARCH_LARGER,

	/* headers */
	SEARCH_FROM,
	SEARCH_TO,
	SEARCH_CC,
	SEARCH_BCC,
	SEARCH_SUBJECT,
	SEARCH_HEADER,

	/* body */
	SEARCH_BODY,
	SEARCH_TEXT
} MailSearchArgType;

struct _MailSearchArg {
	MailSearchArg *next;

	MailSearchArgType type;
	union {
		MailSearchArg *subargs;
		const char *str;
	} value;

	const char *hdr_value; /* for SEARCH_HEADER */
	unsigned int not:1;

	int result;
};

typedef void (*MailSearchForeachFunc)(MailSearchArg *arg, void *context);

/* Builds search arguments based on IMAP arguments. */
MailSearchArg *mail_search_args_build(Pool pool, ImapArg *args, int args_count,
				      const char **error);

/* Reset the results in search arguments */
void mail_search_args_reset(MailSearchArg *args);

/* goes through arguments in list that don't have a result yet.
   Returns 1 = search matched, -1 = search unmatched, 0 = don't know yet */
int mail_search_args_foreach(MailSearchArg *args, MailSearchForeachFunc func,
			     void *context);

/* Fills have_headers, have_body and have_text based on if such search
   argument exists that needs to be checked. */
void mail_search_args_analyze(MailSearchArg *args, int *have_headers,
			      int *have_body, int *have_text);

#endif
