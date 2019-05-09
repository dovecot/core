#ifndef MAIL_SEARCH_MIMEPART_H
#define MAIL_SEARCH_MIMEPART_H

enum mail_search_mime_arg_type {
	SEARCH_MIME_OR,
	SEARCH_MIME_SUB,

	/* sizes */
	SEARCH_MIME_SIZE_EQUAL,
	SEARCH_MIME_SIZE_LARGER,
	SEARCH_MIME_SIZE_SMALLER,

	/* part properties */
	SEARCH_MIME_DESCRIPTION,
	SEARCH_MIME_DISPOSITION_TYPE,
	SEARCH_MIME_DISPOSITION_PARAM,
	SEARCH_MIME_ENCODING,
	SEARCH_MIME_ID,
	SEARCH_MIME_LANGUAGE,
	SEARCH_MIME_LOCATION,
	SEARCH_MIME_MD5,

	/* content-type */
	SEARCH_MIME_TYPE,
	SEARCH_MIME_SUBTYPE,
	SEARCH_MIME_PARAM,

	/* headers */
	SEARCH_MIME_HEADER,

	/* body */
	SEARCH_MIME_BODY,
	SEARCH_MIME_TEXT,

	/* message */
	SEARCH_MIME_CC,
	SEARCH_MIME_BCC,
	SEARCH_MIME_FROM,
	SEARCH_MIME_IN_REPLY_TO,
	SEARCH_MIME_MESSAGE_ID,
	SEARCH_MIME_REPLY_TO,
	SEARCH_MIME_SENDER,
	SEARCH_MIME_SENTBEFORE,
	SEARCH_MIME_SENTON, /* time must point to beginning of the day */
	SEARCH_MIME_SENTSINCE,
	SEARCH_MIME_SUBJECT,
	SEARCH_MIME_TO,

	/* relations */
	SEARCH_MIME_PARENT,
	SEARCH_MIME_CHILD,

	/* position */
	SEARCH_MIME_DEPTH_EQUAL,
	SEARCH_MIME_DEPTH_MIN,
	SEARCH_MIME_DEPTH_MAX,
	SEARCH_MIME_INDEX,

	/* filename */
	SEARCH_MIME_FILENAME_IS,
	SEARCH_MIME_FILENAME_CONTAINS,
	SEARCH_MIME_FILENAME_BEGINS,
	SEARCH_MIME_FILENAME_ENDS
};

struct mail_search_mime_arg {
	/* NOTE: when adding new fields, make sure mail_search_mime_arg_dup_one()
	   and mail_search_mime_arg_one_equals() are updated. */
	struct mail_search_mime_arg *next;

	enum mail_search_mime_arg_type type;
	union {
		struct mail_search_mime_arg *subargs;
		const char *str;
		time_t time;
		uoff_t size;
		unsigned int number;
	} value;

	void *context;
	const char *field_name; /* for SEARCH_HEADER* */
	bool match_not:1; /* result = !result */
	bool match_always:1; /* result = 1 always */
	bool nonmatch_always:1; /* result = 0 always */

	int result; /* -1 = unknown, 0 = unmatched, 1 = matched */
};

struct mail_search_mime_part {
	struct mail_search_mime_arg *args;

	bool simplified:1;
};

typedef void
mail_search_mime_foreach_callback_t(struct mail_search_mime_arg *arg,
					    void *context);

/* Returns TRUE if the two mimepart search keys are fully compatible. */
bool mail_search_mime_parts_equal(const struct mail_search_mime_part *mpart1,
			    const struct mail_search_mime_part *mpart2);
/* Same as mail_search_mime_part_equal(), but for individual
   mail_search_mime_arg structs. All the siblings of arg1 and arg2 are
   also compared. */
bool mail_search_mime_arg_equals(const struct mail_search_mime_arg *arg1,
			    const struct mail_search_mime_arg *arg2);
/* Same as mail_search_mime_arg_equals(), but don't compare siblings. */
bool mail_search_mime_arg_one_equals(const struct mail_search_mime_arg *arg1,
				const struct mail_search_mime_arg *arg2);

struct mail_search_mime_part *
mail_search_mime_part_dup(pool_t pool,
	const struct mail_search_mime_part *mpart);
struct mail_search_mime_arg *
mail_search_mime_arg_dup(pool_t pool,
	const struct mail_search_mime_arg *arg);

/* Reset the results in search arguments. match_always is reset only if
   full_reset is TRUE. */
void mail_search_mime_args_reset(struct mail_search_mime_arg *args,
	bool full_reset);

/* goes through arguments in list that don't have a result yet.
   Returns 1 = search matched, 0 = search unmatched, -1 = don't know yet */
int mail_search_mime_args_foreach(struct mail_search_mime_arg *args,
			     mail_search_mime_foreach_callback_t *callback,
			     void *context) ATTR_NULL(3);
#define mail_search_mime_args_foreach(args, callback, context) \
	  mail_search_mime_args_foreach(args - \
		CALLBACK_TYPECHECK(callback, void (*)( \
			struct mail_search_mime_arg *, typeof(context))), \
		(mail_search_mime_foreach_callback_t *)callback, context)

/* Simplify/optimize search arguments. Afterwards all OR/SUB args are
   guaranteed to have match_not=FALSE. */
void mail_search_mime_simplify(struct mail_search_mime_part *args);

/* Appends MIMEPART search key to the dest string and returns TRUE. */
bool mail_search_mime_part_to_imap(string_t *dest,
	const struct mail_search_mime_part *mpart, const char **error_r);
/* Like mail_search_mime_part_to_imap(), but append only a single MIMEPART
   key. */
bool mail_search_mime_arg_to_imap(string_t *dest,
	const struct mail_search_mime_arg *arg, const char **error_r);

#endif
