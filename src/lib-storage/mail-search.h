#ifndef MAIL_SEARCH_H
#define MAIL_SEARCH_H

#include "seq-range-array.h"
#include "mail-types.h"
#include "mail-thread.h"

enum mail_search_arg_type {
	SEARCH_OR,
	SEARCH_SUB,

	/* sequence sets */
	SEARCH_ALL,
	SEARCH_SEQSET,
	SEARCH_UIDSET,

	/* flags */
	SEARCH_FLAGS,
	SEARCH_KEYWORDS,

	/* dates (date_type required) */
	SEARCH_BEFORE,
	SEARCH_ON, /* time must point to beginning of the day */
	SEARCH_SINCE,

	/* sizes */
	SEARCH_SMALLER,
	SEARCH_LARGER,

	/* headers */
	SEARCH_HEADER,
	SEARCH_HEADER_ADDRESS,
	SEARCH_HEADER_COMPRESS_LWSP,

	/* body */
	SEARCH_BODY,
	SEARCH_TEXT,
	SEARCH_BODY_FAST,
	SEARCH_TEXT_FAST,

	/* extensions */
	SEARCH_MODSEQ,
	SEARCH_INTHREAD,
	SEARCH_GUID,
	SEARCH_MAILBOX,
	SEARCH_MAILBOX_GUID,
	SEARCH_MAILBOX_GLOB
};

enum mail_search_date_type {
	MAIL_SEARCH_DATE_TYPE_SENT = 1,
	MAIL_SEARCH_DATE_TYPE_RECEIVED,
	MAIL_SEARCH_DATE_TYPE_SAVED
};

enum mail_search_arg_flag {
	/* For BEFORE/SINCE/ON searches: Don't drop timezone from
	   comparisons */
	MAIL_SEARCH_ARG_FLAG_USE_TZ	= 0x01,
};

enum mail_search_modseq_type {
	MAIL_SEARCH_MODSEQ_TYPE_ANY = 0,
	MAIL_SEARCH_MODSEQ_TYPE_PRIVATE,
	MAIL_SEARCH_MODSEQ_TYPE_SHARED
};

struct mail_search_modseq {
	uint64_t modseq;
	enum mail_search_modseq_type type;
};

struct mail_search_arg {
	struct mail_search_arg *next;

	enum mail_search_arg_type type;
	struct {
		struct mail_search_arg *subargs;
		ARRAY_TYPE(seq_range) seqset;
		const char *str;
		time_t time;
		uoff_t size;
		enum mail_flags flags;
		enum mail_search_arg_flag search_flags;
		enum mail_search_date_type date_type;
		enum mail_thread_type thread_type;
		struct mail_keywords *keywords;
		struct mail_search_modseq *modseq;
		struct mail_search_args *search_args;
		struct mail_search_result *search_result;
		struct imap_match_glob *mailbox_glob;
	} value;

        void *context;
	const char *hdr_field_name; /* for SEARCH_HEADER* */
	unsigned int not:1;
	unsigned int match_always:1; /* result = 1 always */
	unsigned int nonmatch_always:1; /* result = 0 always */

	int result; /* -1 = unknown, 0 = unmatched, 1 = matched */
};

struct mail_search_args {
	int refcount, init_refcount;

	pool_t pool;
	struct mailbox *box;
	struct mail_search_arg *args;
	const char *charset;

	unsigned int simplified:1;
	unsigned int have_inthreads:1;
};

#define ARG_SET_RESULT(arg, res) \
	STMT_START { \
		(arg)->result = !(arg)->not ? (res) : \
			(res) == -1 ? -1 : !(res); \
	} STMT_END

typedef void mail_search_foreach_callback_t(struct mail_search_arg *arg,
					    void *context);

/* Allocate keywords for search arguments. If change_uidsets is TRUE,
   change uidsets to seqsets. */
void mail_search_args_init(struct mail_search_args *args,
			   struct mailbox *box, bool change_uidsets,
			   const ARRAY_TYPE(seq_range) *search_saved_uidset);
/* Free keywords. The args can initialized afterwards again if needed.
   The args can be reused for other queries after calling this. */
void mail_search_args_deinit(struct mail_search_args *args);
/* Convert sequence sets in args to UIDs. */
void mail_search_args_seq2uid(struct mail_search_args *args);
/* Returns TRUE if the two search arguments are fully compatible.
   Always returns FALSE if there are seqsets, since they may point to different
   messages depending on when the search is run. */
bool mail_search_args_equal(const struct mail_search_args *args1,
			    const struct mail_search_args *args2);

void mail_search_args_ref(struct mail_search_args *args);
void mail_search_args_unref(struct mail_search_args **args);

struct mail_search_args *
mail_search_args_dup(const struct mail_search_args *args);

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

/* Returns FALSE if search query contains MAILBOX[_GLOB] args such that the
   query can never match any messages in the given mailbox. */
bool mail_search_args_match_mailbox(struct mail_search_args *args,
				    const char *vname, char sep);

/* Simplify/optimize search arguments. Afterwards all OR/SUB args are
   guaranteed to have not=FALSE. */
void mail_search_args_simplify(struct mail_search_args *args);

#endif
