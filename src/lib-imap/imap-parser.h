#ifndef __IMAP_PARSER_H
#define __IMAP_PARSER_H

enum imap_parser_flags {
	/* Set this flag if you wish to read only size of literal argument
	   and not convert literal into string. Useful when you need to deal
	   with large literal sizes. The literal must be the last read
	   parameter. */
	IMAP_PARSE_FLAG_LITERAL_SIZE	= 0x01,
	/* Don't remove '\' chars from string arguments */
	IMAP_PARSE_FLAG_NO_UNESCAPE	= 0x02,
};

enum imap_arg_type {
	IMAP_ARG_NIL = 0,
	IMAP_ARG_ATOM,
	IMAP_ARG_STRING,
	IMAP_ARG_LITERAL_SIZE,
	IMAP_ARG_LITERAL_SIZE_NONSYNC,
	IMAP_ARG_LIST,

	IMAP_ARG_EOL /* end of argument list */
};

struct imap_parser;

struct imap_arg {
	enum imap_arg_type type;
        struct imap_arg *parent; /* always of type IMAP_ARG_LIST */

	union {
		char *str;
		uoff_t literal_size;
		struct imap_arg_list *list;
	} _data;
};

#define IMAP_ARG_STR(arg) \
	((arg)->type == IMAP_ARG_NIL ? NULL : \
	 (arg)->type == IMAP_ARG_ATOM || (arg)->type == IMAP_ARG_STRING ? \
	 (arg)->_data.str : _imap_arg_str_error(arg))

#define IMAP_ARG_LITERAL_SIZE(arg) \
	(((arg)->type == IMAP_ARG_LITERAL_SIZE || \
	 (arg)->type == IMAP_ARG_LITERAL_SIZE_NONSYNC) ? \
	 (arg)->_data.literal_size : _imap_arg_literal_size_error(arg))

#define IMAP_ARG_LIST(arg) \
	((arg)->type == IMAP_ARG_LIST ? \
	 (arg)->_data.list : _imap_arg_list_error(arg))

struct imap_arg_list {
	size_t size, alloc;
	struct imap_arg args[1]; /* variable size */
};

/* Create new IMAP argument parser. There's no limit in argument sizes, only
   the maximum buffer size of input stream limits it. max_literal_size limits
   the maximum size of internally handled literals (ie. FLAG_LITERAL_SIZE is
   unset). max_elements sets the number of elements we allow entirely so that
   user can't give huge lists or lists inside lists. output is used for sending
   command continuation requests for literals. */
struct imap_parser *
imap_parser_create(struct istream *input, struct ostream *output,
		   size_t max_literal_size, size_t max_elements);
void imap_parser_destroy(struct imap_parser *parser);

/* Reset the parser to initial state. */
void imap_parser_reset(struct imap_parser *parser);

/* Return the last error in parser. */
const char *imap_parser_get_error(struct imap_parser *parser);

/* Read a number of arguments. This function doesn't call i_stream_read(), you
   need to do that. Returns number of arguments read (may be less than count
   in case of EOL), -2 if more data is needed or -1 if error occured.

   count-sized array of arguments are stored into args when return value is
   0 or larger. If all arguments weren't read, they're set to NIL. count
   can be set to 0 to read all arguments in the line. Last element in
   args is always of type IMAP_ARG_EOL. */
int imap_parser_read_args(struct imap_parser *parser, unsigned int count,
			  enum imap_parser_flags flags, struct imap_arg **args);

/* Read one word - used for reading tag and command name.
   Returns NULL if more data is needed. */
const char *imap_parser_read_word(struct imap_parser *parser);

/* Read the rest of the line. Returns NULL if more data is needed. */
const char *imap_parser_read_line(struct imap_parser *parser);

/* Returns the imap argument as string. NIL returns "" and list returns NULL. */
const char *imap_arg_string(struct imap_arg *arg);

/* Error functions */
char *_imap_arg_str_error(const struct imap_arg *arg);
uoff_t _imap_arg_literal_size_error(const struct imap_arg *arg);
struct imap_arg_list *_imap_arg_list_error(const struct imap_arg *arg);

#endif
