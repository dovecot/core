#ifndef __MAIL_SEARCH_H
#define __MAIL_SEARCH_H

enum mail_search_arg_type {
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
	SEARCH_TEXT,

	/* our shortcuts for headers */
        SEARCH_IN_REPLY_TO,
        SEARCH_MESSAGE_ID
};

struct mail_search_arg {
	struct mail_search_arg *next;

	enum mail_search_arg_type type;
	union {
		struct mail_search_arg *subargs;
		const char *str;
	} value;

        void *context;
	const char *hdr_field_name; /* for SEARCH_HEADER */
	unsigned int not:1;

	int result; /* -1 = unknown, 0 = unmatched, 1 = matched */
};

#define ARG_SET_RESULT(arg, res) \
	STMT_START { \
		(arg)->result = !(arg)->not ? (res) : \
			(res) == -1 ? -1 : !(res); \
	} STMT_END

typedef void (*mail_search_foreach_callback_t)(struct mail_search_arg *arg,
					       void *context);

/* Reset the results in search arguments */
void mail_search_args_reset(struct mail_search_arg *args);

/* goes through arguments in list that don't have a result yet.
   Returns 1 = search matched, 0 = search unmatched, -1 = don't know yet */
int mail_search_args_foreach(struct mail_search_arg *args,
			     mail_search_foreach_callback_t callback,
			     void *context);

/* Fills have_headers, have_body and have_text based on if such search
   argument exists that needs to be checked. */
void mail_search_args_analyze(struct mail_search_arg *args, int *have_headers,
			      int *have_body, int *have_text);

#endif
