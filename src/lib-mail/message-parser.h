#ifndef MESSAGE_PARSER_H
#define MESSAGE_PARSER_H

#include "message-header-parser.h"
#include "message-part.h"

enum message_parser_flags {
	/* Don't return message bodies in message_blocks. */
	MESSAGE_PARSER_FLAG_SKIP_BODY_BLOCK		= 0x01,
	/* Buggy software creates Content-Type: headers without Mime-Version:
	   header. By default we allow this and assume message is MIME if
	   Content-Type: is found. This flag disables this. */
	MESSAGE_PARSER_FLAG_MIME_VERSION_STRICT		= 0x02,
	/* Return multipart (preamble and epilogue) blocks */
	MESSAGE_PARSER_FLAG_INCLUDE_MULTIPART_BLOCKS	= 0x04,
	/* Return --boundary lines */
	MESSAGE_PARSER_FLAG_INCLUDE_BOUNDARIES		= 0x08
};

struct message_parser_ctx;

struct message_block {
	/* Message part this block belongs to */
	struct message_part *part;

	/* non-NULL if a header line was read */
	struct message_header_line *hdr;

	/* hdr = NULL, size = 0 block returned at the end of headers for the
	   empty line between header and body (unless the header is truncated).
	   Later on data and size>0 is returned for blocks of mail body that
	   is read (see message_parser_flags for what is actually returned) */
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
/* Deinitialize message parser. The ctx must NOT have been created by
   message_parser_init_from_parts(). */
void message_parser_deinit(struct message_parser_ctx **ctx,
			   struct message_part **parts_r);
/* Use preparsed parts to speed up parsing. */
struct message_parser_ctx *
message_parser_init_from_parts(struct message_part *parts,
			       struct istream *input,
			       enum message_header_parser_flags hdr_flags,
			       enum message_parser_flags flags);
/* Same as message_parser_deinit(), but return an error message describing
   why the preparsed parts didn't match the message. This can also safely be
   called even when preparsed parts weren't used - it'll always just return
   success in that case. */
int message_parser_deinit_from_parts(struct message_parser_ctx **_ctx,
				     struct message_part **parts_r,
				     const char **error_r);

/* Read the next block of a message. Returns 1 if block is returned, 0 if
   input stream is non-blocking and more data needs to be read, -1 when all is
   done or error occurred (see stream's error status). */
int message_parser_parse_next_block(struct message_parser_ctx *ctx,
				    struct message_block *block_r);

/* Read and parse header. */
void message_parser_parse_header(struct message_parser_ctx *ctx,
				 struct message_size *hdr_size,
				 message_part_header_callback_t *callback,
				 void *context) ATTR_NULL(4);
#define message_parser_parse_header(ctx, hdr_size, callback, context) \
	  message_parser_parse_header(ctx, hdr_size + \
		CALLBACK_TYPECHECK(callback, void (*)( \
			struct message_part *, \
			struct message_header_line *, typeof(context))), \
		(message_part_header_callback_t *)callback, context)

/* Read and parse body. If message is a MIME multipart or message/rfc822
   message, hdr_callback is called for all headers. body_callback is called
   for the body content. */
void message_parser_parse_body(struct message_parser_ctx *ctx,
			       message_part_header_callback_t *hdr_callback,
			       void *context) ATTR_NULL(3);
#define message_parser_parse_body(ctx, callback, context) \
	  message_parser_parse_body(ctx, \
		(message_part_header_callback_t *)callback, \
		(void *)((uintptr_t)context + CALLBACK_TYPECHECK(callback, \
			void (*)(struct message_part *, \
				struct message_header_line *, typeof(context)))))

#endif
