#ifndef __MESSAGE_PARSER_H
#define __MESSAGE_PARSER_H

#include "message-size.h"

#define IS_LWSP(c) \
	((c) == ' ' || (c) == '\t')

enum message_part_flags {
	MESSAGE_PART_FLAG_MULTIPART		= 0x01,
	MESSAGE_PART_FLAG_MULTIPART_DIGEST	= 0x02,
	MESSAGE_PART_FLAG_MESSAGE_RFC822	= 0x04,

	/* content-type: text/... */
	MESSAGE_PART_FLAG_TEXT			= 0x08,

	/* content-transfer-encoding: binary */
	MESSAGE_PART_FLAG_BINARY		= 0x10,

	/* message part header or body contains NULs */
	MESSAGE_PART_FLAG_HAS_NULS		= 0x20,

	/* Mime-Version header exists. */
	MESSAGE_PART_FLAG_IS_MIME		= 0x40
};

struct message_part {
	struct message_part *parent;
	struct message_part *next;
	struct message_part *children;

	uoff_t physical_pos; /* absolute position from beginning of message */
	struct message_size header_size;
	struct message_size body_size;

	enum message_part_flags flags;
	void *context;
};

struct message_parser_ctx;
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
	unsigned int use_full_value:1; /* set if you want full_value */
};

/* called once with hdr = NULL at the end of headers */
typedef void message_header_callback_t(struct message_part *part,
				       struct message_header_line *hdr,
				       void *context);
/* called once with size = 0 at the end of message part */
typedef void message_body_callback_t(struct message_part *part,
				     const unsigned char *data, size_t size,
				     void *context);

/* callback is called for each field in message header. */
void message_parse_from_parts(struct message_part *part, struct istream *input,
			      message_header_callback_t *callback,
			      void *context);
void message_parse_header(struct message_part *part, struct istream *input,
			  struct message_size *hdr_size,
			  message_header_callback_t *callback, void *context);


/* Initialize message parser. part_spool specifies where struct message_parts
   are allocated from. */
struct message_parser_ctx *
message_parser_init(pool_t part_pool, struct istream *input);
struct message_part *message_parser_deinit(struct message_parser_ctx *ctx);

/* Read and parse header. */
void message_parser_parse_header(struct message_parser_ctx *ctx,
				 struct message_size *hdr_size,
				 message_header_callback_t *callback,
				 void *context);
/* Read and parse body. If message is a MIME multipart or message/rfc822
   message, hdr_callback is called for all headers. body_callback is called
   for the body content. */
void message_parser_parse_body(struct message_parser_ctx *ctx,
			       message_header_callback_t *hdr_callback,
			       message_body_callback_t *body_callback,
			       void *context);

/* skip_initial_lwsp controls if we should skip LWSP after "header: ".
   Note that there may not be the single whitespace after "header:", and that
   "header : " is also possible. These two conditions can't be determined from
   struct message_header_line. */
struct message_header_parser_ctx *
message_parse_header_init(struct istream *input, struct message_size *hdr_size,
			 int skip_initial_lwsp);
void message_parse_header_deinit(struct message_header_parser_ctx *ctx);

/* Read and return next header line. Returns 1 if header is returned, 0 if
   input stream is non-blocking and more data needs to be read, -1 when all is
   done or error occured (see stream's error status). */
int message_parse_header_next(struct message_header_parser_ctx *ctx,
			      struct message_header_line **hdr_r);

#endif
