#ifndef __IMAP_PARSER_H
#define __IMAP_PARSER_H

typedef enum {
	/* Set this flag if you wish to read only size of literal argument
	   and not convert literal into string. Useful when you need to deal
	   with large literal sizes. The literal must be the last read
	   parameter. */
	IMAP_PARSE_FLAG_LITERAL_SIZE	= 0x01
} ImapParserFlags;

typedef enum {
	IMAP_ARG_NIL = 0,
	IMAP_ARG_ATOM,
	IMAP_ARG_STRING,
	IMAP_ARG_LITERAL_SIZE,
	IMAP_ARG_LIST
} ImapArgType;

typedef struct _ImapParser ImapParser;
typedef struct _ImapArg ImapArg;
typedef struct _ImapArgList ImapArgList;

struct _ImapArg {
	ImapArgType type;
        ImapArg *parent; /* always of type IMAP_ARG_LIST */

	union {
		char *str;
		uoff_t literal_size;
		ImapArgList *list;
	} data;
};

struct _ImapArgList {
	ImapArgList *next;
	ImapArg arg;
};

/* Create new IMAP argument parser. The max. size of inbuf limits the
   maximum size of each argument. outbuf is used for sending command
   continuation requests for string literals. */
ImapParser *imap_parser_create(IOBuffer *inbuf, IOBuffer *outbuf);
void imap_parser_destroy(ImapParser *parser);

/* Reset the parser to initial state. */
void imap_parser_reset(ImapParser *parser);

/* Read a number of arguments. This function doesn't call tbuffer_read(), you
   need to do that. Returns number of arguments read (may be less than count
   in case of EOL), -2 if more data is needed or -1 if error occured.

   count-sized array of arguments are stored into args when return value is
   0 or larger. If all arguments weren't read, they're set to NIL. count
   can be set to 0 to read all arguments in the line. */
int imap_parser_read_args(ImapParser *parser, unsigned int count,
			  ImapParserFlags flags, ImapArg **args);

/* Read one word - used for reading tag and command name.
   Returns NULL if more data is needed. */
const char *imap_parser_read_word(ImapParser *parser);

/* Read the rest of the line. Returns NULL if more data is needed. */
const char *imap_parser_read_line(ImapParser *parser);

/* Returns the imap argument as string. NIL returns "" and list returns NULL. */
const char *imap_arg_string(ImapArg *arg);

#endif
