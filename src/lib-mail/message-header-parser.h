#ifndef __MESSAGE_HEADER_PARSER_H
#define __MESSAGE_HEADER_PARSER_H

#define IS_LWSP(c) \
	((c) == ' ' || (c) == '\t')

struct message_size;
struct message_header_parser_ctx;

struct message_header_line {
	const char *name;
	size_t name_len;

	const unsigned char *value;
	size_t value_len;

	const unsigned char *full_value;
	size_t full_value_len;

	const unsigned char *middle;
	size_t middle_len;

	uoff_t name_offset, full_value_offset;

	unsigned int continues:1; /* multiline header, continues in next line */
	unsigned int continued:1; /* multiline header, continues */
	unsigned int eoh:1; /* "end of headers" line */
	unsigned int no_newline:1; /* no \n after this line */
	unsigned int crlf_newline:1; /* newline was \r\n */
	unsigned int use_full_value:1; /* set if you want full_value */
};

/* called once with hdr = NULL at the end of headers */
typedef void message_header_callback_t(struct message_header_line *hdr,
				       void *context);

/* skip_initial_lwsp controls if we should skip LWSP after "header: ".
   Note that there may not be the single whitespace after "header:", and that
   "header : " is also possible. These two conditions can't be determined from
   struct message_header_line. */
struct message_header_parser_ctx *
message_parse_header_init(struct istream *input, struct message_size *hdr_size,
			  bool skip_initial_lwsp);
void message_parse_header_deinit(struct message_header_parser_ctx **ctx);

/* Read and return next header line. Returns 1 if header is returned, 0 if
   input stream is non-blocking and more data needs to be read, -1 when all is
   done or error occurred (see stream's error status). */
int message_parse_header_next(struct message_header_parser_ctx *ctx,
			      struct message_header_line **hdr_r);

/* Returns TRUE if the parser has seen NUL characters. */
bool message_parse_header_has_nuls(struct message_header_parser_ctx *ctx);

/* Read and parse the header from the given stream. */
void message_parse_header(struct istream *input, struct message_size *hdr_size,
			  message_header_callback_t *callback, void *context);
#define message_parse_header(input, hdr_size, callback, context) \
	CONTEXT_CALLBACK2(message_parse_header, message_header_callback_t, \
			  callback, context, input, hdr_size)

#endif
