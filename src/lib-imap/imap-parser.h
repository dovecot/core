#ifndef __IMAP_PARSER_H
#define __IMAP_PARSER_H

/* FIXME: we don't have ']' here due to FETCH BODY[] handling failing
   with it.. also '%' and '*' are banned due to LIST, and '\' due to it being
   in flags. oh well.. */
#define IS_ATOM_SPECIAL(c) \
	((c) == '(' || (c) == ')' || (c) == '{' || \
	 (c) == '"' || (c) <= 32 || (c) == 0x7f)

enum imap_parser_flags {
	/* Set this flag if you wish to read only size of literal argument
	   and not convert literal into string. Useful when you need to deal
	   with large literal sizes. The literal must be the last read
	   parameter. */
	IMAP_PARSE_FLAG_LITERAL_SIZE	= 0x01,
	/* Don't remove '\' chars from string arguments */
	IMAP_PARSE_FLAG_NO_UNESCAPE	= 0x02,
	/* Return literals as IMAP_ARG_LITERAL instead of IMAP_ARG_STRING */
	IMAP_PARSE_FLAG_LITERAL_TYPE	= 0x04
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

struct imap_arg {
	enum imap_arg_type type;
        struct imap_arg *parent; /* always of type IMAP_ARG_LIST */

	union {
		const char *str;
		uoff_t literal_size;
		struct imap_arg_list *list;
	} _data;
};

#define IMAP_ARG_STR(arg) \
	((arg)->type == IMAP_ARG_NIL ? NULL : \
	 (arg)->type == IMAP_ARG_ATOM || (arg)->type == IMAP_ARG_STRING || \
	 (arg)->type == IMAP_ARG_LITERAL ? \
	 (arg)->_data.str : _imap_arg_str_error(arg))

#define IMAP_ARG_STR_NONULL(arg) \
	((arg)->type == IMAP_ARG_ATOM || (arg)->type == IMAP_ARG_STRING || \
	 (arg)->type == IMAP_ARG_LITERAL ? \
	 (arg)->_data.str : _imap_arg_str_error(arg))

#define IMAP_ARG_LITERAL_SIZE(arg) \
	(((arg)->type == IMAP_ARG_LITERAL_SIZE || \
	 (arg)->type == IMAP_ARG_LITERAL_SIZE_NONSYNC) ? \
	 (arg)->_data.literal_size : _imap_arg_literal_size_error(arg))

#define IMAP_ARG_LIST(arg) \
	((arg)->type == IMAP_ARG_LIST ? \
	 (const struct imap_arg_list *)(arg)->_data.list : \
		_imap_arg_list_error(arg))

struct imap_arg_list {
	size_t size, alloc;
	struct imap_arg args[1]; /* variable size */
};

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
char *_imap_arg_str_error(const struct imap_arg *arg) __attr_noreturn__;
uoff_t _imap_arg_literal_size_error(const struct imap_arg *arg)
	__attr_noreturn__;
struct imap_arg_list *_imap_arg_list_error(const struct imap_arg *arg)
	__attr_noreturn__;

#endif
