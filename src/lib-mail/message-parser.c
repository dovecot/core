/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "rfc822-parser.h"
#include "rfc2231-parser.h"
#include "message-parser.h"

/* RFC-2046 requires boundaries are max. 70 chars + "--" prefix + "--" suffix.
   We'll add a bit more just in case. */
#define BOUNDARY_END_MAX_LEN (70 + 2 + 2 + 10)

struct message_boundary {
	struct message_boundary *next;

	struct message_part *part;
	const char *boundary;
	size_t len;

	unsigned int epilogue_found:1;
};

struct message_parser_ctx {
	pool_t parser_pool, part_pool;
	struct istream *input;
	struct message_part *parts, *part;

	enum message_header_parser_flags hdr_flags;
	enum message_parser_flags flags;

	const char *last_boundary;
	struct message_boundary *boundaries;

	size_t skip;
	char last_chr;
	unsigned int want_count;

	struct message_header_parser_ctx *hdr_parser_ctx;

	int (*parse_next_block)(struct message_parser_ctx *ctx,
				struct message_block *block_r);

	unsigned int part_seen_content_type:1;
	unsigned int broken:1;
	unsigned int eof:1;
};

message_part_header_callback_t *null_message_part_header_callback = NULL;

static int parse_next_header_init(struct message_parser_ctx *ctx,
				  struct message_block *block_r);
static int parse_next_body_to_boundary(struct message_parser_ctx *ctx,
				       struct message_block *block_r);
static int parse_next_body_to_eof(struct message_parser_ctx *ctx,
				  struct message_block *block_r);
static int preparsed_parse_next_header_init(struct message_parser_ctx *ctx,
					    struct message_block *block_r);

static struct message_boundary *
boundary_find(struct message_boundary *boundaries,
	      const unsigned char *data, size_t len)
{
	/* As MIME spec says: search from latest one to oldest one so that we
	   don't break if the same boundary is used in nested parts. Also the
	   full message line doesn't have to match the boundary, only the
	   beginning. */
	while (boundaries != NULL) {
		if (boundaries->len <= len &&
		    memcmp(boundaries->boundary, data, boundaries->len) == 0)
			return boundaries;

		boundaries = boundaries->next;
	}

	return NULL;
}

static void parse_body_add_block(struct message_parser_ctx *ctx,
				 struct message_block *block)
{
	unsigned int missing_cr_count = 0;
	const unsigned char *cur, *next, *data = block->data;

	i_assert(block->size > 0);

	block->hdr = NULL;

	/* check if we have NULs */
	if (memchr(data, '\0', block->size) != NULL)
		ctx->part->flags |= MESSAGE_PART_FLAG_HAS_NULS;

	/* count number of lines and missing CRs */
	if (*data == '\n') {
		ctx->part->body_size.lines++;
		if (ctx->last_chr != '\r')
			missing_cr_count++;
	}

	cur = data + 1;
	while ((next = memchr(cur, '\n', block->size - (cur - data))) != NULL) {
		ctx->part->body_size.lines++;
		if (next[-1] != '\r')
			missing_cr_count++;

		cur = next + 1;
	}
	ctx->last_chr = data[block->size - 1];
	ctx->skip += block->size;

	ctx->part->body_size.physical_size += block->size;
	ctx->part->body_size.virtual_size += block->size + missing_cr_count;
}

static int message_parser_read_more(struct message_parser_ctx *ctx,
				    struct message_block *block_r, bool *full_r)
{
	int ret;

	if (ctx->skip > 0) {
		i_stream_skip(ctx->input, ctx->skip);
		ctx->skip = 0;
	}

	*full_r = FALSE;
	ret = i_stream_read_data(ctx->input, &block_r->data,
				 &block_r->size, ctx->want_count);
	if (ret <= 0) {
		switch (ret) {
		case 0:
			if (!ctx->input->eof) {
				i_assert(!ctx->input->blocking);
				return 0;
			}
			break;
		case -1:
			i_assert(ctx->input->eof ||
				 ctx->input->stream_errno != 0);
			ctx->eof = TRUE;
			if (block_r->size != 0) {
				/* EOF, but we still have some data.
				   return it. */
				return 1;
			}
			return -1;
		case -2:
			*full_r = TRUE;
			break;
		default:
			i_unreached();
		}
	}

	ctx->want_count = 1;
	return 1;
}

static struct message_part *
message_part_append(pool_t pool, struct message_part *parent)
{
	struct message_part *part, **list;

	part = p_new(pool, struct message_part, 1);
	part->parent = parent;

	/* set child position */
	part->physical_pos =
		parent->physical_pos +
		parent->body_size.physical_size +
		parent->header_size.physical_size;

	list = &part->parent->children;
	while (*list != NULL)
		list = &(*list)->next;

	*list = part;
	return part;
}

static void parse_next_body_multipart_init(struct message_parser_ctx *ctx)
{
	struct message_boundary *b;

	b = p_new(ctx->parser_pool, struct message_boundary, 1);
	b->part = ctx->part;
	b->boundary = ctx->last_boundary;
	b->len = strlen(b->boundary);

	b->next = ctx->boundaries;
	ctx->boundaries = b;

	ctx->last_boundary = NULL;
}

static int parse_next_body_message_rfc822_init(struct message_parser_ctx *ctx,
					       struct message_block *block_r)
{
	ctx->part = message_part_append(ctx->part_pool, ctx->part);
	return parse_next_header_init(ctx, block_r);
}

static int
boundary_line_find(struct message_parser_ctx *ctx,
		   const unsigned char *data, size_t size, bool full,
		   struct message_boundary **boundary_r)
{
	*boundary_r = NULL;

	if (size < 2) {
		i_assert(!full);

		if (ctx->input->eof)
			return -1;
		ctx->want_count = 2;
		return 0;
	}

	if (data[0] != '-' || data[1] != '-') {
		/* not a boundary, just skip this line */
		return -1;
	}

	/* need to find the end of line */
	if (memchr(data + 2, '\n', size - 2) == NULL &&
	    size < BOUNDARY_END_MAX_LEN &&
	    !ctx->input->eof && !full) {
		/* no LF found */
		ctx->want_count = BOUNDARY_END_MAX_LEN;
		return 0;
	}

	data += 2;
	size -= 2;

	*boundary_r = boundary_find(ctx->boundaries, data, size);
	if (*boundary_r == NULL)
		return -1;

	(*boundary_r)->epilogue_found =
		size >= (*boundary_r)->len + 2 &&
		memcmp(data + (*boundary_r)->len, "--", 2) == 0;
	return 1;
}

static int parse_next_mime_header_init(struct message_parser_ctx *ctx,
				       struct message_block *block_r)
{
	ctx->part = message_part_append(ctx->part_pool, ctx->part);
	ctx->part->flags |= MESSAGE_PART_FLAG_IS_MIME;

	return parse_next_header_init(ctx, block_r);
}

static int parse_next_body_skip_boundary_line(struct message_parser_ctx *ctx,
					      struct message_block *block_r)
{
	const unsigned char *ptr;
	int ret;
	bool full;

	if ((ret = message_parser_read_more(ctx, block_r, &full)) <= 0)
		return ret;

	ptr = memchr(block_r->data, '\n', block_r->size);
	if (ptr == NULL) {
		parse_body_add_block(ctx, block_r);
		return 1;
	}

	/* found the LF */
	block_r->size = (ptr - block_r->data) + 1;
	parse_body_add_block(ctx, block_r);

	/* a new MIME part begins */
	ctx->parse_next_block = parse_next_mime_header_init;
	return 1;
}

static int parse_part_finish(struct message_parser_ctx *ctx,
			     struct message_boundary *boundary,
			     struct message_block *block_r, bool first_line)
{
	struct message_part *part;

	/* get back to parent MIME part, summing the child MIME part sizes
	   into parent's body sizes */
	for (part = ctx->part; part != boundary->part; part = part->parent) {
		message_size_add(&part->parent->body_size, &part->body_size);
		message_size_add(&part->parent->body_size, &part->header_size);
	}
	ctx->part = part;

	if (boundary->epilogue_found) {
		/* this boundary isn't needed anymore */
		ctx->boundaries = boundary->next;

		if (ctx->boundaries != NULL)
			ctx->parse_next_block = parse_next_body_to_boundary;
		else
			ctx->parse_next_block = parse_next_body_to_eof;
		return ctx->parse_next_block(ctx, block_r);
	}

	/* forget about the boundaries we possibly skipped */
	ctx->boundaries = boundary;

	/* the boundary itself should already be in buffer. add that. */
	block_r->data = i_stream_get_data(ctx->input, &block_r->size);
	i_assert(block_r->size >= ctx->skip + 2 + boundary->len +
		 (first_line ? 0 : 1));
	block_r->data += ctx->skip;
	/* [\n]--<boundary> */
	block_r->size = (first_line ? 0 : 1) + 2 + boundary->len;
	parse_body_add_block(ctx, block_r);

	ctx->parse_next_block = parse_next_body_skip_boundary_line;
	return 1;
}

static int parse_next_body_to_boundary(struct message_parser_ctx *ctx,
				       struct message_block *block_r)
{
	struct message_boundary *boundary = NULL;
	const unsigned char *data, *cur, *next, *end;
	size_t boundary_start;
	int ret;
	bool full;

	if ((ret = message_parser_read_more(ctx, block_r, &full)) <= 0)
		return ret;

	data = block_r->data;
	if (ctx->last_chr == '\n') {
		/* handle boundary in first line of message. alternatively
		   it's an empty line. */
		ret = boundary_line_find(ctx, block_r->data,
					 block_r->size, full, &boundary);
		if (ret >= 0) {
			return ret == 0 ? 0 :
				parse_part_finish(ctx, boundary, block_r, TRUE);
		}
	}

	i_assert(block_r->size > 0);
	boundary_start = 0;

	/* skip to beginning of the next line. the first line was
	   handled already. */
	cur = data; end = data + block_r->size;
	while ((next = memchr(cur, '\n', end - cur)) != NULL) {
		cur = next + 1;

		boundary_start = next - data;
		if (next > data && next[-1] == '\r')
			boundary_start--;

		if (boundary_start != 0) {
			/* we can at least skip data until the first [CR]LF.
			   input buffer can't be full anymore. */
			full = FALSE;
		}

		ret = boundary_line_find(ctx, cur, end - cur, full, &boundary);
		if (ret >= 0) {
			/* found / need more data */
			if (ret == 0 && boundary_start == 0)
				ctx->want_count += cur - block_r->data;
			break;
		}
	}

	if (next != NULL) {
		/* found / need more data */
		i_assert(ret >= 0);
		i_assert(!(ret == 0 && full));
	} else if (boundary_start == 0) {
		/* no linefeeds in this block. we can just skip it. */
		ret = 0;
		boundary_start = block_r->size;
	} else {
		/* the boundary wasn't found from this data block,
		   we'll need more data. */
		ret = 0;
		ctx->want_count = (block_r->size - boundary_start) + 1;
	}

	if (ret > 0 || (ret == 0 && !ctx->eof)) {
		/* a) we found the boundary
		   b) we need more data and haven't reached EOF yet
		   so leave CR+LF + last line to buffer */
		block_r->size = boundary_start;
	}
	if (block_r->size != 0) {
		parse_body_add_block(ctx, block_r);
		return 1;
	}
	return ret <= 0 ? ret :
		parse_part_finish(ctx, boundary, block_r, FALSE);
}

static int parse_next_body_to_eof(struct message_parser_ctx *ctx,
				  struct message_block *block_r)
{
	bool full;
	int ret;

	if ((ret = message_parser_read_more(ctx, block_r, &full)) <= 0)
		return ret;

	parse_body_add_block(ctx, block_r);
	return 1;
}

static void parse_content_type(struct message_parser_ctx *ctx,
			       struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	const char *const *results;
	string_t *content_type;

	if (ctx->part_seen_content_type)
		return;
	ctx->part_seen_content_type = TRUE;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	(void)rfc822_skip_lwsp(&parser);

	content_type = t_str_new(64);
	if (rfc822_parse_content_type(&parser, content_type) < 0)
		return;

	if (strcasecmp(str_c(content_type), "message/rfc822") == 0)
		ctx->part->flags |= MESSAGE_PART_FLAG_MESSAGE_RFC822;
	else if (strncasecmp(str_c(content_type), "text", 4) == 0 &&
		 (str_len(content_type) == 4 ||
		  str_data(content_type)[4] == '/'))
		ctx->part->flags |= MESSAGE_PART_FLAG_TEXT;
	else if (strncasecmp(str_c(content_type), "multipart/", 10) == 0) {
		ctx->part->flags |= MESSAGE_PART_FLAG_MULTIPART;

		if (strcasecmp(str_c(content_type)+10, "digest") == 0)
			ctx->part->flags |= MESSAGE_PART_FLAG_MULTIPART_DIGEST;
	}

	if ((ctx->part->flags & MESSAGE_PART_FLAG_MULTIPART) == 0 ||
	    ctx->last_boundary != NULL)
		return;

	(void)rfc2231_parse(&parser, &results);
	for (; *results != NULL; results += 2) {
		if (strcasecmp(results[0], "boundary") == 0) {
			ctx->last_boundary =
				p_strdup(ctx->parser_pool, results[1]);
			break;
		}
	}
}

#define MUTEX_FLAGS \
	(MESSAGE_PART_FLAG_MESSAGE_RFC822 | MESSAGE_PART_FLAG_MULTIPART)

static int parse_next_header(struct message_parser_ctx *ctx,
			     struct message_block *block_r)
{
	struct message_part *part = ctx->part;
	struct message_header_line *hdr;
	size_t size;
	int ret;

	if (ctx->skip > 0) {
		i_stream_skip(ctx->input, ctx->skip);
		ctx->skip = 0;
	}

	ret = message_parse_header_next(ctx->hdr_parser_ctx, &hdr);
	if (ret == 0 || (ret < 0 && ctx->input->stream_errno != 0)) {
		(void)i_stream_get_data(ctx->input, &size);
		ctx->want_count = size + 1;
		return ret;
	}

	if (hdr != NULL) {
		if (hdr->eoh)
			;
		else if (strcasecmp(hdr->name, "Mime-Version") == 0) {
			/* it's MIME. Content-* headers are valid */
			part->flags |= MESSAGE_PART_FLAG_IS_MIME;
		} else if (strcasecmp(hdr->name, "Content-Type") == 0) {
			if ((ctx->flags &
			     MESSAGE_PARSER_FLAG_MIME_VERSION_STRICT) == 0)
				part->flags |= MESSAGE_PART_FLAG_IS_MIME;

			if (hdr->continues)
				hdr->use_full_value = TRUE;
			else T_BEGIN {
				parse_content_type(ctx, hdr);
			} T_END;
		}

		block_r->hdr = hdr;
		block_r->size = 0;
		return 1;
	}

	/* end of headers */
	if ((part->flags & MESSAGE_PART_FLAG_MULTIPART) != 0 &&
	    ctx->last_boundary == NULL) {
		/* multipart type but no message boundary */
		part->flags = 0;
	}
	if ((part->flags & MESSAGE_PART_FLAG_IS_MIME) == 0) {
		/* It's not MIME. Reset everything we found from
		   Content-Type. */
		part->flags = 0;
		ctx->last_boundary = NULL;
	}

	if (!ctx->part_seen_content_type ||
	    (part->flags & MESSAGE_PART_FLAG_IS_MIME) == 0) {
		if (part->parent != NULL &&
		    (part->parent->flags &
		     MESSAGE_PART_FLAG_MULTIPART_DIGEST) != 0) {
			/* when there's no content-type specified and we're
			   below multipart/digest, assume message/rfc822
			   content-type */
			part->flags |= MESSAGE_PART_FLAG_MESSAGE_RFC822;
		} else {
			/* otherwise we default to text/plain */
			part->flags |= MESSAGE_PART_FLAG_TEXT;
		}
	}

	if (message_parse_header_has_nuls(ctx->hdr_parser_ctx))
		part->flags |= MESSAGE_PART_FLAG_HAS_NULS;
	message_parse_header_deinit(&ctx->hdr_parser_ctx);

	i_assert((part->flags & MUTEX_FLAGS) != MUTEX_FLAGS);

	ctx->last_chr = '\n';
	if (ctx->last_boundary != NULL) {
		parse_next_body_multipart_init(ctx);
		ctx->parse_next_block = parse_next_body_to_boundary;
	} else if (part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822)
		ctx->parse_next_block = parse_next_body_message_rfc822_init;
	else if (ctx->boundaries != NULL)
		ctx->parse_next_block = parse_next_body_to_boundary;
	else
		ctx->parse_next_block = parse_next_body_to_eof;

	ctx->want_count = 1;

	/* return empty block as end of headers */
	block_r->hdr = NULL;
	block_r->size = 0;
	return 1;
}

static int parse_next_header_init(struct message_parser_ctx *ctx,
				  struct message_block *block_r)
{
	i_assert(ctx->hdr_parser_ctx == NULL);

	ctx->hdr_parser_ctx =
		message_parse_header_init(ctx->input, &ctx->part->header_size,
					  ctx->hdr_flags);
	ctx->part_seen_content_type = FALSE;

	ctx->parse_next_block = parse_next_header;
	return parse_next_header(ctx, block_r);
}

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

static int preparsed_parse_body_init(struct message_parser_ctx *ctx,
				     struct message_block *block_r)
{
	uoff_t offset = ctx->part->physical_pos +
		ctx->part->header_size.physical_size;

	if (offset < ctx->input->v_offset) {
		/* header was actually larger than the cached size suggested */
		ctx->broken = TRUE;
		return -1;
	}
	i_stream_skip(ctx->input, offset - ctx->input->v_offset);

	ctx->parse_next_block = preparsed_parse_body_more;
	return preparsed_parse_body_more(ctx, block_r);
}

static int preparsed_parse_finish_header(struct message_parser_ctx *ctx,
					 struct message_block *block_r)
{
	if (ctx->part->children != NULL) {
		ctx->parse_next_block = preparsed_parse_next_header_init;
		ctx->part = ctx->part->children;
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
	size_t size;
	int ret;

	ret = message_parse_header_next(ctx->hdr_parser_ctx, &hdr);
	if (ret == 0 || (ret < 0 && ctx->input->stream_errno != 0)) {
		(void)i_stream_get_data(ctx->input, &size);
		ctx->want_count = size + 1;
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
		ctx->broken = TRUE;
		return -1;
	}
	return 1;
}

static int preparsed_parse_next_header_init(struct message_parser_ctx *ctx,
					    struct message_block *block_r)
{
	i_assert(ctx->hdr_parser_ctx == NULL);

	i_assert(ctx->part->physical_pos >= ctx->input->v_offset);
	i_stream_skip(ctx->input, ctx->part->physical_pos -
		      ctx->input->v_offset);

	ctx->hdr_parser_ctx =
		message_parse_header_init(ctx->input, NULL, ctx->hdr_flags);

	ctx->parse_next_block = preparsed_parse_next_header;
	return preparsed_parse_next_header(ctx, block_r);
}

struct message_parser_ctx *
message_parser_init(pool_t part_pool, struct istream *input,
		    enum message_header_parser_flags hdr_flags,
		    enum message_parser_flags flags)
{
	struct message_parser_ctx *ctx;
	pool_t pool;

	pool = pool_alloconly_create("Message Parser", 1024);
	ctx = p_new(pool, struct message_parser_ctx, 1);
	ctx->parser_pool = pool;
	ctx->part_pool = part_pool;
	ctx->hdr_flags = hdr_flags;
	ctx->flags = flags;
	ctx->input = input;
	ctx->parts = ctx->part = part_pool == NULL ? NULL :
		p_new(part_pool, struct message_part, 1);
	ctx->parse_next_block = parse_next_header_init;
	i_stream_ref(input);
	return ctx;
}

struct message_parser_ctx *
message_parser_init_from_parts(struct message_part *parts,
			       struct istream *input,
			       enum message_header_parser_flags hdr_flags,
			       enum message_parser_flags flags)
{
	struct message_parser_ctx *ctx;

	ctx = message_parser_init(NULL, input, hdr_flags, flags);
	ctx->parts = ctx->part = parts;
	ctx->parse_next_block = preparsed_parse_next_header_init;
	return ctx;
}

int message_parser_deinit(struct message_parser_ctx **_ctx,
			  struct message_part **parts_r)
{
        struct message_parser_ctx *ctx = *_ctx;
	int ret = ctx->broken ? -1 : 0;

	*_ctx = NULL;
	*parts_r = ctx->parts;

	if (ctx->hdr_parser_ctx != NULL)
		message_parse_header_deinit(&ctx->hdr_parser_ctx);
	i_stream_unref(&ctx->input);
	pool_unref(&ctx->parser_pool);
	return ret;
}

int message_parser_parse_next_block(struct message_parser_ctx *ctx,
				    struct message_block *block_r)
{
	int ret;
	bool eof = FALSE, full;

	while ((ret = ctx->parse_next_block(ctx, block_r)) == 0) {
		ret = message_parser_read_more(ctx, block_r, &full);
		if (ret == 0) {
			i_assert(!ctx->input->blocking);
			return 0;
		}
		if (ret == -1) {
			i_assert(!eof);
			eof = TRUE;
		}
	}

	block_r->part = ctx->part;

	if (ret < 0 && ctx->part != NULL) {
		/* Successful EOF or unexpected failure */
		i_assert(ctx->input->eof || ctx->input->closed ||
			 ctx->input->stream_errno != 0 || ctx->broken);
		while (ctx->part->parent != NULL) {
			message_size_add(&ctx->part->parent->body_size,
					 &ctx->part->body_size);
			message_size_add(&ctx->part->parent->body_size,
					 &ctx->part->header_size);
			ctx->part = ctx->part->parent;
		}
	}

	return ret;
}

#undef message_parser_parse_header
void message_parser_parse_header(struct message_parser_ctx *ctx,
				 struct message_size *hdr_size,
				 message_part_header_callback_t *callback,
				 void *context)
{
	struct message_block block;
	int ret;

	while ((ret = message_parser_parse_next_block(ctx, &block)) > 0) {
		callback(block.part, block.hdr, context);

		if (block.hdr == NULL)
			break;
	}
	i_assert(ret != 0);

	if (ret < 0) {
		/* well, can't return error so fake end of headers */
		callback(ctx->part, NULL, context);
	}

        *hdr_size = ctx->part->header_size;
}

#undef message_parser_parse_body
void message_parser_parse_body(struct message_parser_ctx *ctx,
			       message_part_header_callback_t *hdr_callback,
			       void *context)
{
	struct message_block block;
	int ret;

	while ((ret = message_parser_parse_next_block(ctx, &block)) > 0) {
		if (block.size == 0 && hdr_callback != NULL)
			hdr_callback(block.part, block.hdr, context);
	}
	i_assert(ret != 0);
}
