#ifndef MAIL_SEARCH_H
#define MAIL_SEARCH_H

#include "mail-types.h"

enum mail_search_arg_type {
	SEARCH_OR,
	SEARCH_SUB,

	/* sequence sets */
	SEARCH_ALL,
	SEARCH_SEQSET,

	/* flags */
	SEARCH_FLAGS,
	SEARCH_KEYWORDS,

	/* dates */
	SEARCH_BEFORE,
	SEARCH_ON, /* time must point to beginning of the day */
	SEARCH_SINCE,
	SEARCH_SENTBEFORE,
	SEARCH_SENTON, /* time must point to beginning of the day */
	SEARCH_SENTSINCE,

	/* sizes */
	SEARCH_SMALLER,
	SEARCH_LARGER,

	/* headers */
	SEARCH_HEADER,
	SEARCH_HEADER_ADDRESS,

	/* body */
	SEARCH_BODY,
	SEARCH_TEXT,
	SEARCH_BODY_FAST,
	SEARCH_TEXT_FAST
};

struct mail_search_seqset {
	uint32_t seq1, seq2;
        struct mail_search_seqset *next;
};

struct mail_search_arg {
	struct mail_search_arg *next;

	enum mail_search_arg_type type;
	struct {
		struct mail_search_arg *subargs;
                struct mail_search_seqset *seqset;
		const char *str;
		time_t time;
		uoff_t size;
		enum mail_flags flags;
		struct mail_keywords *keywords;
	} value;

        void *context;
	const char *hdr_field_name; /* for SEARCH_HEADER* */
	unsigned int not:1;
	unsigned int match_always:1; /* result = 1 always */

	int result; /* -1 = unknown, 0 = unmatched, 1 = matched */
};

#define ARG_SET_RESULT(arg, res) \
	STMT_START { \
		(arg)->result = !(arg)->not ? (res) : \
			(res) == -1 ? -1 : !(res); \
	} STMT_END

typedef void mail_search_foreach_callback_t(struct mail_search_arg *arg,
					    void *context);

/* Reset the results in search arguments. match_always is reset only if
   full_reset is TRUE. */
void mail_search_args_reset(struct mail_search_arg *args, bool full_reset);

/* goes through arguments in list that don't have a result yet.
   Returns 1 = search matched, 0 = search unmatched, -1 = don't know yet */
int mail_search_args_foreach(struct mail_search_arg *args,
			     mail_search_foreach_callback_t *callback,
			     void *context);
#ifdef CONTEXT_TYPE_SAFETY
#  define mail_search_args_foreach(args, callback, context) \
	({(void)(1 ? 0 : callback((struct mail_search_arg *)NULL, context)); \
	  mail_search_args_foreach(args, \
		(mail_search_foreach_callback_t *)callback, context); })
#else
#  define mail_search_args_foreach(args, callback, context) \
	  mail_search_args_foreach(args, \
		(mail_search_foreach_callback_t *)callback, context)
#endif

/* Fills have_headers and have_body based on if such search argument exists
   that needs to be checked. Returns the headers that we're searching for, or
   NULL if we're searching for TEXT. */
const char *const *
mail_search_args_analyze(struct mail_search_arg *args,
			 bool *have_headers, bool *have_body);

/* 1) Change args so that SEARCH_SUB and SEARCH_OR will never have "not" set
   2) Drop unnecessary nested SEARCH_SUB and SEARCH_ORs */
void mail_search_args_simplify(struct mail_search_arg *args);

#endif
