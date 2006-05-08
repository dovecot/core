#ifndef __MESSAGE_PARSER_H
#define __MESSAGE_PARSER_H

#include "message-header-parser.h"
#include "message-size.h"

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

struct message_block {
	/* non-NULL if a header line was read */
	struct message_header_line *hdr;

	/* hdr = NULL, size = 0 block returned at the end of headers */
	const unsigned char *data;
	size_t size;
};

/* called once with hdr = NULL at the end of headers */
typedef void message_part_header_callback_t(struct message_part *part,
					    struct message_header_line *hdr,
					    void *context);

/* Initialize message parser. part_spool specifies where struct message_parts
   are allocated from. */
struct message_parser_ctx *
message_parser_init(pool_t part_pool, struct istream *input);
struct message_part *message_parser_deinit(struct message_parser_ctx **ctx);

/* Read the next block of a message. Returns 1 if block is returned, 0 if
   input stream is non-blocking and more data needs to be read, -1 when all is
   done or error occurred (see stream's error status). */
int message_parser_parse_next_block(struct message_parser_ctx *ctx,
				    struct message_block *block_r);

/* Read and parse header. */
void message_parser_parse_header(struct message_parser_ctx *ctx,
				 struct message_size *hdr_size,
				 message_part_header_callback_t *callback,
				 void *context);
/* Read and parse body. If message is a MIME multipart or message/rfc822
   message, hdr_callback is called for all headers. body_callback is called
   for the body content. */
void message_parser_parse_body(struct message_parser_ctx *ctx,
			       message_part_header_callback_t *hdr_callback,
			       void *context);

/* callback is called for each field in message header. */
void message_parse_from_parts(struct message_part *part, struct istream *input,
			      message_part_header_callback_t *callback,
			      void *context);

#endif
