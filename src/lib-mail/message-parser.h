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
	MESSAGE_PART_FLAG_HAS_NULS		= 0x20
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

struct message_header_parser_ctx;

struct message_header_line {
	const char *name;
	size_t name_len;

	const unsigned char *value;
	size_t value_len;

	const unsigned char *full_value;
	size_t full_value_len;

	unsigned int continues:1; /* multiline header, continues in next line */
	unsigned int continued:1; /* multiline header, continues */
	unsigned int eoh:1; /* "end of headers" line */
	unsigned int no_newline:1; /* no \n after this line */
	unsigned int use_full_value:1; /* set if you want full_value */
};

/* called once with hdr = NULL at end of headers */
typedef void message_header_callback_t(struct message_part *part,
				       struct message_header_line *hdr,
				       void *context);

/* callback is called for each field in message header. */
struct message_part *message_parse(pool_t pool, struct istream *input,
				   message_header_callback_t *callback,
				   void *context);
void message_parse_header(struct message_part *part, struct istream *input,
			  struct message_size *hdr_size,
			  message_header_callback_t *callback, void *context);

struct message_header_parser_ctx *
message_parse_header_init(struct istream *input, struct message_size *hdr_size);
void message_parse_header_deinit(struct message_header_parser_ctx *ctx);

/* Read and return next header line. */
struct message_header_line *
message_parse_header_next(struct message_header_parser_ctx *ctx);

#endif
