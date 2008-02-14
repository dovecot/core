#ifndef MESSAGE_PARSER_H
#define MESSAGE_PARSER_H

#include "message-header-parser.h"
#include "message-size.h"

enum message_parser_flags {
	/* Don't return message bodies in message_blocks. */
	MESSAGE_PARSER_FLAG_SKIP_BODY_BLOCK	= 0x01,
	/* Buggy software creates Content-Type: headers without Mime-Version:
	   header. By default we allow this and assume message is MIME if
	   Content-Type: is found. This flag disables this. */
	MESSAGE_PARSER_FLAG_MIME_VERSION_STRICT	= 0x02
};

/* Note that these flags are used directly by message-parser-serialize, so
   existing flags can't be changed without breaking backwards compatibility */
enum message_part_flags {
	MESSAGE_PART_FLAG_MULTIPART		= 0x01,
	MESSAGE_PART_FLAG_MULTIPART_DIGEST	= 0x02,
	MESSAGE_PART_FLAG_MESSAGE_RFC822	= 0x04,

	/* content-type: text/... */
	MESSAGE_PART_FLAG_TEXT			= 0x08,

	MESSAGE_PART_FLAG_UNUSED		= 0x10,

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
	/* Message part this block belongs to */
	struct message_part *part;

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

extern message_part_header_callback_t *null_message_part_header_callback;

/* Initialize message parser. part_spool specifies where struct message_parts
   are allocated from. */
struct message_parser_ctx *
message_parser_init(pool_t part_pool, struct istream *input,
		    enum message_header_parser_flags hdr_flags,
		    enum message_parser_flags flags);
/* Use preparsed parts to speed up parsing. */
struct message_parser_ctx *
message_parser_init_from_parts(struct message_part *parts,
			       struct istream *input,
			       enum message_header_parser_flags hdr_flags,
			       enum message_parser_flags flags);
/* Returns 0 if parts were returned, -1 we used preparsed parts and they
   didn't match the current message */
int message_parser_deinit(struct message_parser_ctx **ctx,
			  struct message_part **parts_r);

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
#ifdef CONTEXT_TYPE_SAFETY
#  define message_parser_parse_header(ctx, hdr_size, callback, context) \
	({(void)(1 ? 0 : callback((struct message_part *)0, \
				  (struct message_header_line *)0, context)); \
	  message_parser_parse_header(ctx, hdr_size, \
		(message_part_header_callback_t *)callback, context); })
#else
#  define message_parser_parse_header(ctx, hdr_size, callback, context) \
	  message_parser_parse_header(ctx, hdr_size, \
		(message_part_header_callback_t *)callback, context)
#endif

/* Read and parse body. If message is a MIME multipart or message/rfc822
   message, hdr_callback is called for all headers. body_callback is called
   for the body content. */
void message_parser_parse_body(struct message_parser_ctx *ctx,
			       message_part_header_callback_t *hdr_callback,
			       void *context);
#ifdef CONTEXT_TYPE_SAFETY
#  define message_parser_parse_body(ctx, callback, context) \
	({(void)(1 ? 0 : callback((struct message_part *)0, \
				  (struct message_header_line *)0, context)); \
	  message_parser_parse_body(ctx, \
		(message_part_header_callback_t *)callback, context); })
#else
#  define message_parser_parse_body(ctx, callback, context) \
	  message_parser_parse_body(ctx, \
		(message_part_header_callback_t *)callback, context)
#endif

#endif
