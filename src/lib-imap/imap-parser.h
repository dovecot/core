#ifndef IMAP_PARSER_H
#define IMAP_PARSER_H

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

enum imap_parser_flags {
	/* Set this flag if you wish to read only size of literal argument
	   and not convert literal into string. Useful when you need to deal
	   with large literal sizes. The literal must be the last read
	   parameter. */
	IMAP_PARSE_FLAG_LITERAL_SIZE	= 0x01,
	/* Don't remove '\' chars from string arguments */
	IMAP_PARSE_FLAG_NO_UNESCAPE	= 0x02,
	/* Return literals as IMAP_ARG_LITERAL instead of IMAP_ARG_STRING */
	IMAP_PARSE_FLAG_LITERAL_TYPE	= 0x04,
	/* Don't check if atom contains invalid characters */
	IMAP_PARSE_FLAG_ATOM_ALLCHARS	= 0x08,
	/* Allow strings to contain CRLFs */
	IMAP_PARSE_FLAG_MULTILINE_STR	= 0x10
};

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

struct imap_parser;

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

#define IMAP_ARG_TYPE_IS_STRING(type) \
	((type) == IMAP_ARG_ATOM || (type) == IMAP_ARG_STRING || \
	 (type) == IMAP_ARG_LITERAL)

#define IMAP_ARG_STR(arg) \
	((arg)->type == IMAP_ARG_NIL ? NULL : \
	 IMAP_ARG_TYPE_IS_STRING((arg)->type) ? \
	 (arg)->_data.str : imap_arg_str_error())

#define IMAP_ARG_STR_NONULL(arg) \
	((arg)->type == IMAP_ARG_ATOM || (arg)->type == IMAP_ARG_STRING || \
	 (arg)->type == IMAP_ARG_LITERAL ? \
	 (arg)->_data.str : imap_arg_str_error())

#define IMAP_ARG_LITERAL_SIZE(arg) \
	(((arg)->type == IMAP_ARG_LITERAL_SIZE || \
	 (arg)->type == IMAP_ARG_LITERAL_SIZE_NONSYNC) ? \
	 (arg)->_data.literal_size : imap_arg_literal_size_error())

#define IMAP_ARG_LIST(arg) \
	((arg)->type == IMAP_ARG_LIST ? \
	 &(arg)->_data.list : imap_arg_list_error())
#define IMAP_ARG_LIST_ARGS(arg) \
	array_idx(IMAP_ARG_LIST(arg), 0)
#define IMAP_ARG_LIST_COUNT(arg) \
	(array_count(IMAP_ARG_LIST(arg)) - 1)

/* Create new IMAP argument parser. output is used for sending command
   continuation requests for literals.

   max_line_size can be used to approximately limit the maximum amount of
   memory that gets allocated when parsing a line. Input buffer size limits
   the maximum size of each parsed token.

   Usually the largest lines are large only because they have a one huge
   message set token, so you'll probably want to keep input buffer size the
   same as max_line_size. That means the maximum memory usage is around
   2 * max_line_size. */
struct imap_parser *
imap_parser_create(struct istream *input, struct ostream *output,
		   size_t max_line_size);
void imap_parser_destroy(struct imap_parser **parser);

/* Reset the parser to initial state. */
void imap_parser_reset(struct imap_parser *parser);

/* Change parser's input and output streams */
void imap_parser_set_streams(struct imap_parser *parser, struct istream *input,
			     struct ostream *output);

/* Return the last error in parser. fatal is set to TRUE if there's no way to
   continue parsing, currently only if too large non-sync literal size was
   given. */
const char *imap_parser_get_error(struct imap_parser *parser, bool *fatal);

/* Read a number of arguments. This function doesn't call i_stream_read(), you
   need to do that. Returns number of arguments read (may be less than count
   in case of EOL), -2 if more data is needed or -1 if error occurred.

   count-sized array of arguments are stored into args when return value is
   0 or larger. If all arguments weren't read, they're set to NIL. count
   can be set to 0 to read all arguments in the line. Last element in
   args is always of type IMAP_ARG_EOL. */
int imap_parser_read_args(struct imap_parser *parser, unsigned int count,
			  enum imap_parser_flags flags,
			  const struct imap_arg **args_r);
/* If parsing ended with literal size, return it. */
bool imap_parser_get_literal_size(struct imap_parser *parser, uoff_t *size_r);
/* IMAP_PARSE_FLAG_LITERAL_SIZE is set and last read argument was a literal.
   Calling this function causes the literal size to be replaced with the actual
   literal data when continuing argument parsing. */
void imap_parser_read_last_literal(struct imap_parser *parser);

/* just like imap_parser_read_args(), but assume \n at end of data in
   input stream. */
int imap_parser_finish_line(struct imap_parser *parser, unsigned int count,
			    enum imap_parser_flags flags,
			    const struct imap_arg **args_r);

/* Read one word - used for reading tag and command name.
   Returns NULL if more data is needed. */
const char *imap_parser_read_word(struct imap_parser *parser);

/* Returns the imap argument as string. NIL returns "" and list returns NULL. */
const char *imap_arg_string(const struct imap_arg *arg);

/* Error functions */
static inline char * ATTR_NORETURN
imap_arg_str_error(void)
{
	i_unreached();
#ifndef ATTRS_DEFINED
	return NULL;
#endif
}

static inline uoff_t ATTR_NORETURN
imap_arg_literal_size_error(void)
{
	i_unreached();
#ifndef ATTRS_DEFINED
	return 0;
#endif
}

static inline ARRAY_TYPE(imap_arg_list) * ATTR_NORETURN
imap_arg_list_error(void)
{
	i_unreached();
#ifndef ATTRS_DEFINED
	return NULL;
#endif
}

#endif
