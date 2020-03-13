#ifndef MAIL_SEARCH_H
#define MAIL_SEARCH_H

#include "seq-range-array.h"
#include "mail-types.h"
#include "mail-thread.h"

struct mail_search_mime_part;

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

	/* extensions */
	SEARCH_MODSEQ,
	SEARCH_INTHREAD,
	SEARCH_GUID,
	SEARCH_MAILBOX,
	SEARCH_MAILBOX_GUID,
	SEARCH_MAILBOX_GLOB,
	SEARCH_REAL_UID,
	SEARCH_MIMEPART
};

enum mail_search_date_type {
	MAIL_SEARCH_DATE_TYPE_SENT = 1,
	MAIL_SEARCH_DATE_TYPE_RECEIVED,
	MAIL_SEARCH_DATE_TYPE_SAVED
};

enum mail_search_arg_flag {
	/* Used by *BEFORE/SINCE/ON searches.

	   When NOT set: Adjust search timestamps so that the email's timezone
	   is included in the comparisons. For example
	   "04-Nov-2016 00:00:00 +0200" would match 4th day. This allows
	   searching for mails with dates from the email sender's point of
	   view. For received/saved dates there is no known timezone, and
	   without this flag the dates are compared using the server's local
	   timezone.

	   When set: Compare the timestamp as UTC. For example
	   "04-Nov-2016 00:00:00 +0200" would be treated as
	   "03-Nov-2016 22:00:00 UTC" and would match 3rd day. This allows
	   searching for mails within precise time interval. Since imap-dates
	   don't allow specifying timezone this isn't really possible with IMAP
	   protocol, except using OLDER/YOUNGER searches. */
	MAIL_SEARCH_ARG_FLAG_UTC_TIMES	= 0x01,
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
	/* NOTE: when adding new fields, make sure mail_search_arg_dup_one()
	   and mail_search_arg_one_equals() are updated. */
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
		struct mail_search_modseq *modseq;
		struct mail_search_result *search_result;
		struct mail_search_mime_part *mime_part;
	} value;
	/* set by mail_search_args_init(): */
	struct {
		struct mail_search_args *search_args;
		/* Note that initialized keywords may be empty if the keyword
		   wasn't valid in this mailbox. */
		struct mail_keywords *keywords;
		struct imap_match_glob *mailbox_glob;
	} initialized;

        void *context;
	const char *hdr_field_name; /* for SEARCH_HEADER* */
	bool match_not:1; /* result = !result */
	bool match_always:1; /* result = 1 always */
	bool nonmatch_always:1; /* result = 0 always */
	bool fuzzy:1; /* use fuzzy matching for this arg */
	bool no_fts:1; /* do NOT call FTS */

	int result; /* -1 = unknown, 0 = unmatched, 1 = matched */
};

struct mail_search_args {
	int refcount, init_refcount;

	pool_t pool;
	struct mailbox *box;
	struct mail_search_arg *args;

	bool simplified:1;
	bool have_inthreads:1;
	/* Stop mail_search_next() when finding a non-matching mail.
	   (Could be useful when wanting to find only the oldest mails.) */
	bool stop_on_nonmatch:1;
	/* fts plugin has already expanded the search args - no need to do
	   it again. */
	bool fts_expanded:1;
};

#define ARG_SET_RESULT(arg, res) \
	STMT_START { \
		(arg)->result = !(arg)->match_not ? (res) : \
			((res) == -1 ? -1 : ((res) == 0 ? 1 : 0)); \
	} STMT_END

typedef void mail_search_foreach_callback_t(struct mail_search_arg *arg,
					    void *context);

/* Allocate keywords for search arguments. If change_uidsets is TRUE,
   change uidsets to seqsets. */
void mail_search_args_init(struct mail_search_args *args,
			   struct mailbox *box, bool change_uidsets,
			   const ARRAY_TYPE(seq_range) *search_saved_uidset)
	ATTR_NULL(4);
/* Initialize arg and its children. args is used for getting mailbox and
   pool. */
void mail_search_arg_init(struct mail_search_args *args,
			  struct mail_search_arg *arg);
/* Free memory allocated by mail_search_args_init(). The args can initialized
   afterwards again if needed. The args can be reused for other queries after
   calling this. */
void mail_search_args_deinit(struct mail_search_args *args);
/* Free arg and its siblings and children. */
void mail_search_arg_deinit(struct mail_search_arg *arg);
/* Free arg and its children, but not its siblings. */
void mail_search_arg_one_deinit(struct mail_search_arg *arg);
/* Convert sequence sets in args to UIDs. */
void mail_search_args_seq2uid(struct mail_search_args *args);
/* Returns TRUE if the two search arguments are fully compatible.
   Always returns FALSE if there are seqsets, since they may point to different
   messages depending on when the search is run. */
bool mail_search_args_equal(const struct mail_search_args *args1,
			    const struct mail_search_args *args2);
/* Same as mail_search_args_equal(), but for individual mail_search_arg
   structs. All the siblings of arg1 and arg2 are also compared. */
bool mail_search_arg_equals(const struct mail_search_arg *arg1,
			    const struct mail_search_arg *arg2);
/* Same as mail_search_arg_equals(), but don't compare siblings. */
bool mail_search_arg_one_equals(const struct mail_search_arg *arg1,
				const struct mail_search_arg *arg2);

void mail_search_args_ref(struct mail_search_args *args);
void mail_search_args_unref(struct mail_search_args **args);

struct mail_search_args *
mail_search_args_dup(const struct mail_search_args *args);
struct mail_search_arg *
mail_search_arg_dup(pool_t pool, const struct mail_search_arg *arg);

/* Reset the results in search arguments. match_always is reset only if
   full_reset is TRUE. */
void mail_search_args_reset(struct mail_search_arg *args, bool full_reset);

/* goes through arguments in list that don't have a result yet.
   Returns 1 = search matched, 0 = search unmatched, -1 = don't know yet */
int mail_search_args_foreach(struct mail_search_arg *args,
			     mail_search_foreach_callback_t *callback,
			     void *context) ATTR_NULL(3);
#define mail_search_args_foreach(args, callback, context) \
	  mail_search_args_foreach(args - \
		CALLBACK_TYPECHECK(callback, void (*)( \
			struct mail_search_arg *, typeof(context))), \
		(mail_search_foreach_callback_t *)callback, context)

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
   guaranteed to have match_not=FALSE. */
void mail_search_args_simplify(struct mail_search_args *args);

/* Append all args as IMAP SEARCH AND-query to the dest string and returns TRUE.
   If some search arg can't be written as IMAP SEARCH parameter, error_r is set
   and FALSE is returned. */
bool mail_search_args_to_imap(string_t *dest, const struct mail_search_arg *args,
			      const char **error_r);
/* Like mail_search_args_to_imap(), but append only a single arg. */
bool mail_search_arg_to_imap(string_t *dest, const struct mail_search_arg *arg,
			     const char **error_r);
/* Write all args to dest string as cmdline/human compatible input. */
void mail_search_args_to_cmdline(string_t *dest,
				 const struct mail_search_arg *args);

/* Serialization for search args' results. */
void mail_search_args_result_serialize(const struct mail_search_args *args,
				       buffer_t *dest);
void mail_search_args_result_deserialize(struct mail_search_args *args,
					 const unsigned char *data,
					 size_t size);

#endif
