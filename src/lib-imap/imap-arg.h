#ifndef IMAP_ARG_H
#define IMAP_ARG_H

#include "array.h"

/* We use this macro to read atoms from input. It should probably contain
   everything some day, but for now we can't handle some input otherwise:

   ']' is required for parsing section (FETCH BODY[])
   '%', '*' and ']' are valid list-chars for LIST patterns
   '\' is used in flags */
#define IS_ATOM_SPECIAL_INPUT(c) \
	((c) == '(' || (c) == ')' || (c) == '{' || \
	 (c) == '"' || (c) <= 32 || (c) == 0x7f)

#define IS_ATOM_SPECIAL(c) \
	(IS_ATOM_SPECIAL_INPUT(c) || \
	 (c) == ']' || (c) == '%' || (c) == '*' || (c) == '\\')

enum imap_arg_type {
	IMAP_ARG_NIL = 0,
	IMAP_ARG_ATOM,
	IMAP_ARG_STRING,
	IMAP_ARG_LIST,

	/* literals are returned as IMAP_ARG_STRING by default */
	IMAP_ARG_LITERAL,
	IMAP_ARG_LITERAL_SIZE,
	IMAP_ARG_LITERAL_SIZE_NONSYNC,

	IMAP_ARG_EOL /* end of argument list */
};

ARRAY_DEFINE_TYPE(imap_arg_list, struct imap_arg);
struct imap_arg {
	enum imap_arg_type type;
        struct imap_arg *parent; /* always of type IMAP_ARG_LIST */

	union {
		const char *str;
		uoff_t literal_size;
		ARRAY_TYPE(imap_arg_list) list;
	} _data;
};

/* RFC 3501's astring type */
#define IMAP_ARG_TYPE_IS_ASTRING(type) \
	((type) == IMAP_ARG_ATOM || \
	 (type) == IMAP_ARG_STRING || \
	 (type) == IMAP_ARG_LITERAL)
#define IMAP_ARG_IS_ASTRING(arg) \
	IMAP_ARG_TYPE_IS_ASTRING((arg)->type)
#define IMAP_ARG_IS_NSTRING(arg) \
	(IMAP_ARG_IS_ASTRING(arg) || (arg)->type == IMAP_ARG_NIL)
#define IMAP_ARG_IS_EOL(arg) \
	((arg)->type == IMAP_ARG_EOL)

bool imap_arg_get_atom(const struct imap_arg *arg, const char **str_r)
	ATTR_WARN_UNUSED_RESULT;
bool imap_arg_get_quoted(const struct imap_arg *arg, const char **str_r)
	ATTR_WARN_UNUSED_RESULT;
bool imap_arg_get_string(const struct imap_arg *arg, const char **str_r)
	ATTR_WARN_UNUSED_RESULT;
bool imap_arg_get_astring(const struct imap_arg *arg, const char **str_r)
	ATTR_WARN_UNUSED_RESULT;
/* str is set to NULL for NIL. */
bool imap_arg_get_nstring(const struct imap_arg *arg, const char **str_r)
	ATTR_WARN_UNUSED_RESULT;

bool imap_arg_get_literal_size(const struct imap_arg *arg, uoff_t *size_r)
	ATTR_WARN_UNUSED_RESULT;

bool imap_arg_get_list(const struct imap_arg *arg,
		       const struct imap_arg **list_r)
	ATTR_WARN_UNUSED_RESULT;
bool imap_arg_get_list_full(const struct imap_arg *arg,
			    const struct imap_arg **list_r,
			    unsigned int *list_count_r) ATTR_WARN_UNUSED_RESULT;

/* Similar to above, but assumes that arg is already of correct type. */
const char *imap_arg_as_astring(const struct imap_arg *arg);
const char *imap_arg_as_nstring(const struct imap_arg *arg);
uoff_t imap_arg_as_literal_size(const struct imap_arg *arg);
const struct imap_arg *imap_arg_as_list(const struct imap_arg *arg);

/* Returns TRUE if arg is atom and case-insensitively matches str */
bool imap_arg_atom_equals(const struct imap_arg *arg, const char *str);

#endif
