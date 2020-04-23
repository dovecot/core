/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "message-parser-private.h"

static int preparsed_parse_epilogue_init(struct message_parser_ctx *ctx,
					 struct message_block *block_r);
static int preparsed_parse_next_header_init(struct message_parser_ctx *ctx,
					    struct message_block *block_r);

static int preparsed_parse_eof(struct message_parser_ctx *ctx ATTR_UNUSED,
			       struct message_block *block_r ATTR_UNUSED)
{
	return -1;
}

static void preparsed_skip_to_next(struct message_parser_ctx *ctx)
{
	ctx->parse_next_block = preparsed_parse_next_header_init;
	while (ctx->part != NULL) {
		if (ctx->part->next != NULL) {
			ctx->part = ctx->part->next;
			break;
		}

		/* parse epilogue of multipart parent if requested */
		if (ctx->part->parent != NULL &&
		    (ctx->part->parent->flags & MESSAGE_PART_FLAG_MULTIPART) != 0 &&
		    (ctx->flags & MESSAGE_PARSER_FLAG_INCLUDE_MULTIPART_BLOCKS) != 0) {
			/* check for presence of epilogue */
			uoff_t part_end = ctx->part->physical_pos +
				ctx->part->header_size.physical_size +
				ctx->part->body_size.physical_size;
			uoff_t parent_end = ctx->part->parent->physical_pos +
				ctx->part->parent->header_size.physical_size +
				ctx->part->parent->body_size.physical_size;

			if (parent_end > part_end) {
				ctx->parse_next_block = preparsed_parse_epilogue_init;
				break;
			}
		}
		ctx->part = ctx->part->parent;
	}
	if (ctx->part == NULL)
		ctx->parse_next_block = preparsed_parse_eof;
}

static int preparsed_parse_body_finish(struct message_parser_ctx *ctx,
				       struct message_block *block_r)
{
	i_stream_skip(ctx->input, ctx->skip);
	ctx->skip = 0;

	preparsed_skip_to_next(ctx);
	return ctx->parse_next_block(ctx, block_r);
}

static int preparsed_parse_prologue_finish(struct message_parser_ctx *ctx,
					   struct message_block *block_r)
{
	i_stream_skip(ctx->input, ctx->skip);
	ctx->skip = 0;

	ctx->parse_next_block = preparsed_parse_next_header_init;
	ctx->part = ctx->part->children;
	return ctx->parse_next_block(ctx, block_r);
}

static int preparsed_parse_body_more(struct message_parser_ctx *ctx,
				     struct message_block *block_r)
{
	uoff_t end_offset = ctx->part->physical_pos +
		ctx->part->header_size.physical_size +
		ctx->part->body_size.physical_size;
	bool full;
	int ret;

	if ((ret = message_parser_read_more(ctx, block_r, &full)) <= 0)
		return ret;

	if (ctx->input->v_offset + block_r->size >= end_offset) {
		block_r->size = end_offset - ctx->input->v_offset;
		ctx->parse_next_block = preparsed_parse_body_finish;
	}
	ctx->skip = block_r->size;
	return 1;
}

static int preparsed_parse_prologue_more(struct message_parser_ctx *ctx,
					 struct message_block *block_r)
{
	uoff_t boundary_min_start, end_offset;
	const unsigned char *cur;
	bool full;
	int ret;

	i_assert(ctx->part->children != NULL);
	end_offset = ctx->part->children->physical_pos;

	if ((ret = message_parser_read_more(ctx, block_r, &full)) <= 0)
		return ret;

	if (ctx->input->v_offset + block_r->size >= end_offset) {
		/* we've got the full prologue: clip off the initial boundary */
		block_r->size = end_offset - ctx->input->v_offset;
		cur = block_r->data + block_r->size - 1;

		/* [\r]\n--boundary[\r]\n */ 
		if (block_r->size < 5 || *cur != '\n') {
			ctx->broken_reason = "Prologue boundary end not at expected position";
			return -1;
		}
		
		cur--;
		if (*cur == '\r') cur--;

		/* find newline just before boundary */
		for (; cur >= block_r->data; cur--) {
			if (*cur == '\n') break;
		}

		if (cur[0] != '\n' || cur[1] != '-' || cur[2] != '-') {
			ctx->broken_reason = "Prologue boundary beginning not at expected position";
			return -1;
		}

		if (cur != block_r->data && cur[-1] == '\r') cur--;

		/* clip boundary */
		block_r->size = cur - block_r->data;			

		ctx->parse_next_block = preparsed_parse_prologue_finish;
		ctx->skip = block_r->size;
		return 1;
	}
		
	/* retain enough data in the stream buffer to contain initial boundary */
	if (end_offset > BOUNDARY_END_MAX_LEN)
		boundary_min_start = end_offset - BOUNDARY_END_MAX_LEN;
	else
		boundary_min_start = 0;

	if (ctx->input->v_offset + block_r->size >= boundary_min_start) {
		if (boundary_min_start <= ctx->input->v_offset)
			return 0;
		block_r->size = boundary_min_start - ctx->input->v_offset;
	}
	ctx->skip = block_r->size;
	return 1;
}

static int preparsed_parse_epilogue_more(struct message_parser_ctx *ctx,
					 struct message_block *block_r)
{
	uoff_t end_offset = ctx->part->physical_pos +
		ctx->part->header_size.physical_size +
		ctx->part->body_size.physical_size;
	bool full;
	int ret;

	if ((ret = message_parser_read_more(ctx, block_r, &full)) <= 0)
		return ret;

	if (ctx->input->v_offset + block_r->size >= end_offset) {
		block_r->size = end_offset - ctx->input->v_offset;
		ctx->parse_next_block = preparsed_parse_body_finish;
	}
	ctx->skip = block_r->size;
	return 1;
}

static int preparsed_parse_epilogue_boundary(struct message_parser_ctx *ctx,
					     struct message_block *block_r)
{
	uoff_t end_offset = ctx->part->physical_pos +
		ctx->part->header_size.physical_size +
		ctx->part->body_size.physical_size;
	const unsigned char *data, *cur;
	size_t size;
	bool full;
	int ret;

	if (end_offset - ctx->input->v_offset < 7) {
		ctx->broken_reason = "Epilogue position is wrong";
		return -1;
	}

	if ((ret = message_parser_read_more(ctx, block_r, &full)) <= 0)
		return ret;

	/* [\r]\n--boundary--[\r]\n */
	if (block_r->size < 7) {
		ctx->want_count = 7;
		return 0;
	}

	data = block_r->data;
	size = block_r->size;
	cur = data;

	if (*cur == '\r') cur++;

	if (cur[0] != '\n' || cur[1] != '-' || data[2] != '-') {
		ctx->broken_reason = "Epilogue boundary start not at expected position";
		return -1;
	}

	/* find the end of the line */
	cur += 3;
	if ((cur = memchr(cur, '\n', size - (cur-data))) == NULL) {
		if (end_offset < ctx->input->v_offset + size) {
			ctx->broken_reason = "Epilogue boundary end not at expected position";
			return -1;
		} else if (ctx->input->v_offset + size < end_offset &&
			   size < BOUNDARY_END_MAX_LEN &&
			   !ctx->input->eof && !full) {
			ctx->want_count = BOUNDARY_END_MAX_LEN;
			return 0;
		}
	}

	block_r->size = 0;
	ctx->parse_next_block = preparsed_parse_epilogue_more;
	ctx->skip = cur - data + 1;
	return 0;
}

static int preparsed_parse_body_init(struct message_parser_ctx *ctx,
				     struct message_block *block_r)
{
	uoff_t offset = ctx->part->physical_pos +
		ctx->part->header_size.physical_size;

	if (offset < ctx->input->v_offset) {
		/* header was actually larger than the cached size suggested */
		ctx->broken_reason = "Header larger than its cached size";
		return -1;
	}
	i_stream_skip(ctx->input, offset - ctx->input->v_offset);

	/* multipart messages may begin with --boundary--, which makes them
	   not have any children. */
	if ((ctx->part->flags & MESSAGE_PART_FLAG_MULTIPART) == 0 ||
	    ctx->part->children == NULL)
		ctx->parse_next_block = preparsed_parse_body_more;
	else
		ctx->parse_next_block = preparsed_parse_prologue_more;
	return ctx->parse_next_block(ctx, block_r);
}

static int preparsed_parse_epilogue_init(struct message_parser_ctx *ctx,
					 struct message_block *block_r)
{
	uoff_t offset = ctx->part->physical_pos +
		ctx->part->header_size.physical_size +
		ctx->part->body_size.physical_size;

	ctx->part = ctx->part->parent;

	if (offset < ctx->input->v_offset) {
		/* last child was actually larger than the cached size
		   suggested */
		ctx->broken_reason = "Part larger than its cached size";
		return -1;
	}
	i_stream_skip(ctx->input, offset - ctx->input->v_offset);

	ctx->parse_next_block = preparsed_parse_epilogue_boundary;
	return ctx->parse_next_block(ctx, block_r);
}

static int preparsed_parse_finish_header(struct message_parser_ctx *ctx,
					 struct message_block *block_r)
{
	if (ctx->part->children != NULL) {
		if ((ctx->part->flags & MESSAGE_PART_FLAG_MULTIPART) != 0 &&
		    (ctx->flags & MESSAGE_PARSER_FLAG_INCLUDE_MULTIPART_BLOCKS) != 0)
			ctx->parse_next_block = preparsed_parse_body_init;
		else {
			ctx->parse_next_block = preparsed_parse_next_header_init;
			ctx->part = ctx->part->children;
		}
	} else if ((ctx->flags & MESSAGE_PARSER_FLAG_SKIP_BODY_BLOCK) == 0) {
		ctx->parse_next_block = preparsed_parse_body_init;
	} else {
		preparsed_skip_to_next(ctx);
	}
	return ctx->parse_next_block(ctx, block_r);
}

static int preparsed_parse_next_header(struct message_parser_ctx *ctx,
				       struct message_block *block_r)
{
	struct message_header_line *hdr;
	int ret;

	ret = message_parse_header_next(ctx->hdr_parser_ctx, &hdr);
	if (ret == 0 || (ret < 0 && ctx->input->stream_errno != 0)) {
		ctx->want_count = i_stream_get_data_size(ctx->input) + 1;
		return ret;
	}

	if (hdr != NULL) {
		block_r->hdr = hdr;
		block_r->size = 0;
		return 1;
	}
	message_parse_header_deinit(&ctx->hdr_parser_ctx);

	ctx->parse_next_block = preparsed_parse_finish_header;

	/* return empty block as end of headers */
	block_r->hdr = NULL;
	block_r->size = 0;

	i_assert(ctx->skip == 0);
	if (ctx->input->v_offset != ctx->part->physical_pos +
	    ctx->part->header_size.physical_size) {
		ctx->broken_reason = "Cached header size mismatch";
		return -1;
	}
	return 1;
}

static int preparsed_parse_next_header_init(struct message_parser_ctx *ctx,
					    struct message_block *block_r)
{
	struct istream *hdr_input;

	i_assert(ctx->hdr_parser_ctx == NULL);

	i_assert(ctx->part->physical_pos >= ctx->input->v_offset);
	i_stream_skip(ctx->input, ctx->part->physical_pos -
		      ctx->input->v_offset);

	/* the header may become truncated by --boundaries. limit the header
	   stream's size to what it's supposed to be to avoid duplicating (and
	   keeping in sync!) all the same complicated logic as in
	   parse_next_header(). */
	hdr_input = i_stream_create_limit(ctx->input, ctx->part->header_size.physical_size);
	ctx->hdr_parser_ctx =
		message_parse_header_init(hdr_input, NULL, ctx->hdr_flags);
	i_stream_unref(&hdr_input);

	ctx->parse_next_block = preparsed_parse_next_header;
	return preparsed_parse_next_header(ctx, block_r);
}

struct message_parser_ctx *
message_parser_init_from_parts(struct message_part *parts,
			       struct istream *input,
			       const struct message_parser_settings *set)
{
	struct message_parser_ctx *ctx;

	i_assert(parts != NULL);

	ctx = message_parser_init_int(input, set);
	ctx->preparsed = TRUE;
	ctx->parts = ctx->part = parts;
	ctx->parse_next_block = preparsed_parse_next_header_init;
	return ctx;
}
