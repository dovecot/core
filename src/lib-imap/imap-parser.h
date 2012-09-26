#ifndef IMAP_PARSER_H
#define IMAP_PARSER_H

#include "imap-arg.h"

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
	IMAP_PARSE_FLAG_MULTILINE_STR	= 0x10,
	/* Parse in list context; ')' parses as EOL */
	IMAP_PARSE_FLAG_INSIDE_LIST	= 0x20,
	/* Parse literal8 and set it as flag to imap_arg. */
	IMAP_PARSE_FLAG_LITERAL8	= 0x40,
	/* We're parsing IMAP server replies. Parse the "text" after
	   OK/NO/BAD/BYE replies as a single atom. We assume that the initial
	   "*" or tag was already skipped over. */
	IMAP_PARSE_FLAG_SERVER_TEXT	= 0x80
};

struct imap_parser;

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
		   size_t max_line_size) ATTR_NULL(2);
void imap_parser_ref(struct imap_parser *parser);
void imap_parser_unref(struct imap_parser **parser);

/* Reset the parser to initial state. */
void imap_parser_reset(struct imap_parser *parser);

/* Change parser's input and output streams */
void imap_parser_set_streams(struct imap_parser *parser, struct istream *input,
			     struct ostream *output) ATTR_NULL(3);

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

#endif
