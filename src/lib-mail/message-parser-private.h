#ifndef MESSAGE_PARSER_PRIVATE_H
#define MESSAGE_PARSER_PRIVATE_H

#include "message-parser.h"

/* RFC-2046 requires boundaries are max. 70 chars + "--" prefix + "--" suffix.
   We'll add a bit more just in case. */
#define BOUNDARY_STRING_MAX_LEN (70 + 10)
#define BOUNDARY_END_MAX_LEN (BOUNDARY_STRING_MAX_LEN + 2 + 2)

struct message_boundary {
	struct message_boundary *next;

	struct message_part *part;
	const char *boundary;
	size_t len;

	bool epilogue_found:1;
};

struct message_parser_ctx {
	pool_t parser_pool, part_pool;
	struct istream *input;
	struct message_part *parts, *part;
	const char *broken_reason;

	enum message_header_parser_flags hdr_flags;
	enum message_parser_flags flags;

	const char *last_boundary;
	struct message_boundary *boundaries;

	struct message_part **next_part;
	ARRAY(struct message_part **) next_part_stack;

	size_t skip;
	char last_chr;
	unsigned int want_count;

	struct message_header_parser_ctx *hdr_parser_ctx;
	unsigned int prev_hdr_newline_size;

	int (*parse_next_block)(struct message_parser_ctx *ctx,
				struct message_block *block_r);

	bool part_seen_content_type:1;
	bool multipart:1;
	bool preparsed:1;
	bool eof:1;
};

struct message_parser_ctx *
message_parser_init_int(struct istream *input,
			enum message_header_parser_flags hdr_flags,
			enum message_parser_flags flags);
int message_parser_read_more(struct message_parser_ctx *ctx,
			     struct message_block *block_r, bool *full_r);

#endif
