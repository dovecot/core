#ifndef MESSAGE_HEADER_PARSER_H
#define MESSAGE_HEADER_PARSER_H

#define IS_LWSP(c) \
	((c) == ' ' || (c) == '\t')

struct message_size;
struct message_header_parser_ctx;

enum message_header_parser_flags {
	/* Don't add LWSP after "header: " to value. */
	MESSAGE_HEADER_PARSER_FLAG_SKIP_INITIAL_LWSP	= 0x01,
	/* Don't add CRs to full_value even if input had them */
	MESSAGE_HEADER_PARSER_FLAG_DROP_CR		= 0x02,
	/* Convert [CR+]LF+LWSP to a space character in full_value */
	MESSAGE_HEADER_PARSER_FLAG_CLEAN_ONELINE	= 0x04,
	/* Replace 0x0 symbols with 0x80 */
	MESSAGE_HEADER_REPLACE_NULS_WITH_0x80		= 0x08,
};

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

	bool continues:1; /* multiline header, continues in next line */
	bool continued:1; /* multiline header, continues */
	bool eoh:1; /* "end of headers" line */
	bool no_newline:1; /* no \n after this line */
	bool crlf_newline:1; /* newline was \r\n */
	bool use_full_value:1; /* set if you want full_value */
};

/* called once with hdr = NULL at the end of headers */
typedef void message_header_callback_t(struct message_header_line *hdr,
				       void *context);

struct message_header_parser_ctx *
message_parse_header_init(struct istream *input, struct message_size *hdr_size,
			  enum message_header_parser_flags flags) ATTR_NULL(2);
void message_parse_header_deinit(struct message_header_parser_ctx **ctx);

/* Read and return next header line. Returns 1 if header is returned, 0 if
   input stream is non-blocking and more data needs to be read, -1 when all is
   done or error occurred (see stream's error status). */
int message_parse_header_next(struct message_header_parser_ctx *ctx,
			      struct message_header_line **hdr_r);

/* Returns TRUE if the parser has seen NUL characters. */
bool message_parse_header_has_nuls(const struct message_header_parser_ctx *ctx)
	ATTR_PURE;

/* Read and parse the header from the given stream. */
void message_parse_header(struct istream *input, struct message_size *hdr_size,
			  enum message_header_parser_flags flags,
			  message_header_callback_t *callback, void *context)
	ATTR_NULL(2);
#define message_parse_header(input, hdr_size, flags, callback, context) \
	  message_parse_header(input, hdr_size, flags + \
		CALLBACK_TYPECHECK(callback, void (*)( \
			struct message_header_line *hdr, typeof(context))), \
 		(message_header_callback_t *)callback, context)

/* Write the header line to buffer exactly as it was read, including the
   newline. */
void message_header_line_write(buffer_t *output,
			       const struct message_header_line *hdr);

#endif
