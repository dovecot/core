/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "rfc822-tokenize.h"
#include "message-send.h"
#include "index-storage.h"
#include "index-fetch.h"

#include <ctype.h>
#include <unistd.h>

typedef struct {
	String *dest;
	OStream *output;
	uoff_t dest_size;

	uoff_t skip, max_size;
	const char **fields;
	int (*match_func) (const char **, const char *, size_t);
} FetchHeaderFieldContext;

/* For FETCH[HEADER.FIELDS*] we need to modify the header data before sending
   it. We can either save it in memory and then send it, or we can parse it
   twice, first calculating the size and then send it. This value specifies
   the maximum amount of memory we allow to allocate before using
   double-parsing. */
#define MAX_HEADER_BUFFER_SIZE (32*1024)

ImapCacheField index_fetch_body_get_cache(const char *section)
{
	if (*section >= '0' && *section <= '9')
		return IMAP_CACHE_MESSAGE_PART | IMAP_CACHE_MESSAGE_OPEN;

	if (*section == '\0' || strcasecmp(section, "TEXT") == 0) {
		/* no IMAP_CACHE_MESSAGE_BODY_SIZE, so that we don't
		   uselessly check it when we want to read partial data */
		return IMAP_CACHE_MESSAGE_OPEN;
	}

	if (strncasecmp(section, "HEADER", 6) == 0 ||
	    strcasecmp(section, "MIME") == 0)
		return IMAP_CACHE_MESSAGE_HDR_SIZE | IMAP_CACHE_MESSAGE_OPEN;

	/* error */
	return 0;
}

/* fetch BODY[] or BODY[TEXT] */
static int fetch_body(MailIndexRecord *rec, MailFetchBodyData *sect,
		      FetchContext *ctx, const char *prefix, int fetch_header)
{
	MessageSize size;
	IStream *input;
	const char *str;
	int cr_skipped;

	if (!imap_msgcache_get_rfc822_partial(ctx->cache, sect->skip,
					      sect->max_size, fetch_header,
					      &size, &input, &cr_skipped)) {
		i_error("Couldn't get BODY[] for UID %u (index %s)",
			rec->uid, ctx->index->filepath);
		return FALSE;
	}

	str = t_strdup_printf("%s {%"PRIuUOFF_T"}\r\n",
			      prefix, size.virtual_size);
	if (o_stream_send_str(ctx->output, str) < 0)
		return FALSE;

	if (cr_skipped)
		size.virtual_size++;

	return message_send(ctx->output, input, &size,
			    cr_skipped ? 1 : 0, sect->max_size);
}

static const char **get_fields_array(const char *fields)
{
	const char **field_list, **field;

	while (*fields == ' ')
		fields++;
	if (*fields == '(')
		fields++;

	field_list = t_strsplit(fields, " )");

	/* array ends at ")" element */
	for (field = field_list; *field != NULL; field++) {
		if (strcasecmp(*field, ")") == 0)
			*field = NULL;
	}

	return field_list;
}

static int header_match(const char **fields, const char *name, size_t size)
{
	const char *field, *name_start, *name_end;

	if (size == 0)
		return FALSE;

	name_start = name;
	name_end = name + size;

	for (; *fields != NULL; fields++) {
		field = *fields;
		if (*field == '\0')
			continue;

		for (name = name_start; name != name_end; name++) {
			/* field has been uppercased long time ago while
			   parsing FETCH command */
			if (i_toupper(*name) != *field)
				break;

			field++;
			if (*field == '\0') {
				if (name+1 == name_end)
					return TRUE;
				break;
			}
		}
	}

	return FALSE;
}

static int header_match_not(const char **fields, const char *name, size_t size)
{
	return !header_match(fields, name, size);
}

static int header_match_mime(const char **fields __attr_unused__,
			     const char *name, size_t size)
{
	if (size > 8 && strncasecmp(name, "Content-", 8) == 0)
		return TRUE;

	if (size == 12 && strncasecmp(name, "Mime-Version", 13) == 0)
		return TRUE;

	return FALSE;
}

static int fetch_header_append(FetchHeaderFieldContext *ctx,
			       const char *str, size_t size)
{
	if (ctx->skip > 0) {
		if (ctx->skip >= size) {
			ctx->skip -= size;
			return TRUE;
		}

		str += ctx->skip;
		size -= ctx->skip;
		ctx->skip = 0;
	}

	if (ctx->dest_size + size > ctx->max_size) {
		i_assert(ctx->dest_size <= ctx->max_size);
		size = ctx->max_size - ctx->dest_size;
	}

	if (ctx->dest != NULL)
		str_append_n(ctx->dest, str, size);
	ctx->dest_size += size;

	if (ctx->output != NULL) {
		if (o_stream_send(ctx->output, str, size) < 0)
			return FALSE;
	}
	return ctx->dest_size < ctx->max_size;
}

static void fetch_header_field(MessagePart *part __attr_unused__,
			       const char *name, size_t name_len,
			       const char *value __attr_unused__,
			       size_t value_len __attr_unused__,
			       void *context)
{
	FetchHeaderFieldContext *ctx = context;
	const char *field_start, *field_end, *cr, *p;

	/* see if we want this field */
	if (!ctx->match_func(ctx->fields, name, name_len))
		return;

	/* add the field, inserting CRs when needed. FIXME: is this too
	   kludgy? we assume name continues with ": value".. */
	field_start = name;
	field_end = value + value_len;

	cr = NULL;
	for (p = field_start; p != field_end; p++) {
		if (*p == '\r')
			cr = p;
		else if (*p == '\n' && cr != p-1) {
			/* missing CR */
			if (!fetch_header_append(ctx, field_start,
						 (size_t) (p-field_start)))
				return;
			if (!fetch_header_append(ctx, "\r\n", 2))
				return;

			field_start = p+1;
		}
	}

	if (field_start != field_end) {
		if (!fetch_header_append(ctx, field_start,
					 (size_t) (field_end-field_start)))
			return;
	}

	(void)fetch_header_append(ctx, "\r\n", 2);
}

static int fetch_header_fields(IStream *input, const char *section,
			       FetchHeaderFieldContext *ctx)
{
	if (strncasecmp(section, "HEADER.FIELDS ", 14) == 0) {
		ctx->fields = get_fields_array(section + 14);
		ctx->match_func = header_match;
	} else if (strncasecmp(section, "HEADER.FIELDS.NOT ", 18) == 0) {
		ctx->fields = get_fields_array(section + 18);
		ctx->match_func = header_match_not;
	} else if (strcasecmp(section, "MIME") == 0) {
		/* Mime-Version + Content-* fields */
		ctx->match_func = header_match_mime;
	} else {
		/* invalid section given by user - FIXME: tell user about it */
		return FALSE;
	}

	ctx->dest_size = 0;
	message_parse_header(NULL, input, NULL, fetch_header_field, ctx);

	i_assert(ctx->dest_size <= ctx->max_size);
	i_assert(ctx->dest == NULL || str_len(ctx->dest) == ctx->dest_size);
	return TRUE;
}

/* fetch wanted headers from given data */
static int fetch_header_from(IStream *input, OStream *output,
			     const char *prefix, MessageSize *size,
			     const char *section, MailFetchBodyData *sect)
{
	FetchHeaderFieldContext ctx;
	const char *str;
	uoff_t start_offset;
	int failed;

	/* HEADER, MIME, HEADER.FIELDS (list), HEADER.FIELDS.NOT (list) */

	if (strcasecmp(section, "HEADER") == 0) {
		/* all headers */
		str = t_strdup_printf("%s {%"PRIuUOFF_T"}\r\n",
				      prefix, size->virtual_size);
		if (o_stream_send_str(output, str) < 0)
			return FALSE;
		return message_send(output, input, size,
				    sect->skip, sect->max_size);
	}

	/* partial headers - copy the wanted fields into memory, inserting
	   missing CRs on the way. If the header is too large, calculate 
	   the size first and then send the data directly to output stream. */

	memset(&ctx, 0, sizeof(ctx));
	ctx.skip = sect->skip;
	ctx.max_size = sect->max_size;

	failed = FALSE;
	start_offset = input->v_offset;

	t_push();

	/* first pass, we need at least the size */
	if (size->virtual_size > MAX_HEADER_BUFFER_SIZE &&
	    sect->max_size > MAX_HEADER_BUFFER_SIZE) {
		if (!fetch_header_fields(input, section, &ctx))
			failed = TRUE;

		i_assert(ctx.dest_size <= size->virtual_size);
	} else {
		ctx.dest = t_str_new(size->virtual_size < 4096 ?
				     size->virtual_size : 4096);
		if (!fetch_header_fields(input, section, &ctx))
			failed = TRUE;
	}

	if (!failed) {
		str = t_strdup_printf("%s {%"PRIuUOFF_T"}\r\n",
				      prefix, ctx.dest_size);
		if (o_stream_send_str(output, str) < 0)
			failed = TRUE;
	}

	if (!failed) {
		if (ctx.dest == NULL) {
			/* second pass, write the data to output stream */
			uoff_t first_size = ctx.dest_size;

			ctx.output = output;
			i_stream_seek(input, start_offset);

			if (!failed &&
			    !fetch_header_fields(input, section, &ctx))
				failed = TRUE;

			i_assert(first_size == ctx.dest_size);
		} else {
			if (o_stream_send(output, str_c(ctx.dest),
					  str_len(ctx.dest)) < 0)
				failed = TRUE;
		}
	}

	t_pop();
	return !failed;
}

/* fetch BODY[HEADER...] */
static int fetch_header(MailFetchBodyData *sect, FetchContext *ctx,
			const char *prefix)
{
	MessageSize hdr_size;
	IStream *input;

	if (!imap_msgcache_get_rfc822(ctx->cache, &input, &hdr_size, NULL))
		return FALSE;

	return fetch_header_from(input, ctx->output, prefix, &hdr_size,
				 sect->section, sect);
}

/* Find MessagePart for section (eg. 1.3.4) */
static MessagePart *part_find(MailFetchBodyData *sect, FetchContext *ctx,
			      const char **section)
{
	MessagePart *part;
	const char *path;
	unsigned int num;

	part = imap_msgcache_get_parts(ctx->cache);

	path = sect->section;
	while (*path >= '0' && *path <= '9' && part != NULL) {
		/* get part number */
		num = 0;
		while (*path != '\0' && *path != '.') {
			if (*path < '0' || *path > '9')
				return NULL;
			num = num*10 + (*path - '0');
			path++;
		}

		if (*path == '.')
			path++;

		if (part->flags & MESSAGE_PART_FLAG_MULTIPART) {
			/* find the part */
			part = part->children;
			for (; num > 1 && part != NULL; num--)
				part = part->next;
		} else {
			/* only 1 allowed with non-multipart messages */
			if (num != 1)
				return NULL;
		}

		if (part != NULL &&
		    (part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822)) {
			/* skip the message/rfc822 part */
			part = part->children;
		}
	}

	*section = path;
	return part;
}

/* fetch BODY[1.2] or BODY[1.2.TEXT] */
static int fetch_part_body(MessagePart *part, MailFetchBodyData *sect,
			   FetchContext *ctx, const char *prefix)
{
	IStream *input;
	const char *str;
	uoff_t skip_pos;

	if (!imap_msgcache_get_data(ctx->cache, &input))
		return FALSE;

	/* jump to beginning of wanted data */
	skip_pos = part->physical_pos + part->header_size.physical_size;
	i_stream_skip(input, skip_pos);

	str = t_strdup_printf("%s {%"PRIuUOFF_T"}\r\n",
			      prefix, part->body_size.virtual_size);
	if (o_stream_send_str(ctx->output, str) < 0)
		return FALSE;

	/* FIXME: potential performance problem with big messages:
	   FETCH BODY[1]<100000..1024>, hopefully no clients do this */
	return message_send(ctx->output, input, &part->body_size,
			    sect->skip, sect->max_size);
}

/* fetch BODY[1.2.MIME|HEADER...] */
static int fetch_part_header(MessagePart *part, const char *section,
			     MailFetchBodyData *sect, FetchContext *ctx,
			     const char *prefix)
{
	IStream *input;

	if (!imap_msgcache_get_data(ctx->cache, &input))
		return FALSE;

	i_stream_skip(input, part->physical_pos);
	return fetch_header_from(input, ctx->output, prefix, &part->header_size,
				 section, sect);
}

static int fetch_part(MailFetchBodyData *sect, FetchContext *ctx,
		      const char *prefix)
{
	MessagePart *part;
	const char *section;

	part = part_find(sect, ctx, &section);
	if (part == NULL)
		return FALSE;

	if (*section == '\0' || strcasecmp(section, "TEXT") == 0)
		return fetch_part_body(part, sect, ctx, prefix);

	if (strncasecmp(section, "HEADER", 6) == 0)
		return fetch_part_header(part, section, sect, ctx, prefix);
	if (strcasecmp(section, "MIME") == 0)
		return fetch_part_header(part, section, sect, ctx, prefix);

	return FALSE;
}

int index_fetch_body_section(MailIndexRecord *rec, MailFetchBodyData *sect,
			     FetchContext *ctx)
{
	const char *prefix;

	prefix = !sect->skip_set ?
		t_strdup_printf(" BODY[%s]", sect->section) :
		t_strdup_printf(" BODY[%s]<%"PRIuUOFF_T">",
				sect->section, sect->skip);
	if (ctx->first) {
		prefix++; ctx->first = FALSE;
	}

	if (*sect->section == '\0')
		return fetch_body(rec, sect, ctx, prefix, TRUE);
	if (strcasecmp(sect->section, "TEXT") == 0)
		return fetch_body(rec, sect, ctx, prefix, FALSE);
	if (strncasecmp(sect->section, "HEADER", 6) == 0)
		return fetch_header(sect, ctx, prefix);
	if (*sect->section >= '0' && *sect->section <= '9')
		return fetch_part(sect, ctx, prefix);

	/* FIXME: point the error to user */
	return FALSE;
}
