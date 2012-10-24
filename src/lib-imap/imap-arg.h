#ifndef IMAP_ARG_H
#define IMAP_ARG_H

#include "array.h"

/* ABNF:

   CHAR           =  %x01-7F
   CTL            =  %x00-1F / %x7F
   SP             =  %x20
   DQUOTE         =  %x22 */

/* ASTRING-CHAR   = ATOM-CHAR / resp-specials */
#define IS_ASTRING_CHAR(c) (IS_ATOM_CHAR(c) || IS_RESP_SPECIAL(c))
/* ATOM-CHAR       = <any CHAR except atom-specials> */
#define IS_ATOM_CHAR(c) (!IS_ATOM_SPECIAL(c))
/* atom-specials   = "(" / ")" / "{" / SP / CTL / list-wildcards /
                     quoted-specials / resp-specials
   Since atoms are only 7bit, we'll also optimize a bit by assuming 8bit chars
   are also atom-specials. */
#define IS_ATOM_SPECIAL(c) \
	((unsigned char)(c) <= 0x20 || (unsigned char)(c) >= 0x7f || \
	 (c) == '(' || (c) == ')' || (c) == '{' || IS_LIST_WILDCARD(c) || \
	 IS_QUOTED_SPECIAL(c) || IS_RESP_SPECIAL(c))

/* list-wildcards  = "%" / "*" */
#define IS_LIST_WILDCARD(c) ((c) == '%' || (c) == '*')
/* quoted-specials = DQUOTE / "\" */
#define IS_QUOTED_SPECIAL(c) ((c) == '\"' || (c) == '\\')
/* resp-specials   = "]" */
#define IS_RESP_SPECIAL(c) ((c) == ']')

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

	/* Set when _data.str is set */
	size_t str_len;

	union {
		const char *str;
		uoff_t literal_size;
		ARRAY_TYPE(imap_arg_list) list;
	} _data;
	unsigned int literal8:1; /* BINARY literal8 used */
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
