/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "istream-crlf.h"
#include "istream-nonuls.h"
#include "istream-header-filter.h"
#include "message-parser.h"
#include "mail-storage-private.h"
#include "mail-namespace.h"
#include "imap-parser.h"
#include "imap-msgpart.h"

enum fetch_type {
	FETCH_FULL,
	FETCH_MIME,
	FETCH_HEADER,
	FETCH_HEADER_FIELDS,
	FETCH_HEADER_FIELDS_NOT,
	FETCH_BODY
};

struct imap_msgpart {
	pool_t pool;

	/* "" for root, otherwise e.g. "1.2.3". the .MIME, .HEADER, etc.
	   suffix not included */
	const char *section_number;
	enum fetch_type fetch_type;
	enum mail_fetch_field wanted_fields;

	/* HEADER.FIELDS[.NOT] (list of headers) */
        struct mailbox_header_lookup_ctx *header_ctx;
	const char *const *headers;

	/* which part of the message part to fetch (default: 0..(uoff_t)-1) */
	uoff_t partial_offset, partial_size;
};

struct imap_msgpart_open_ctx {
	/* from matching message_part, set after opening: */
	uoff_t physical_pos;
	struct message_size mime_hdr_size;
	struct message_size mime_body_size;
};

static struct imap_msgpart *imap_msgpart_type(enum fetch_type fetch_type)
{
	struct imap_msgpart *msgpart;
	pool_t pool;

	pool = pool_alloconly_create("imap msgpart", sizeof(*msgpart)+32);
	msgpart = p_new(pool, struct imap_msgpart, 1);
	msgpart->pool = pool;
	msgpart->partial_size = (uoff_t)-1;
	msgpart->fetch_type = fetch_type;
	if (fetch_type == FETCH_HEADER || fetch_type == FETCH_FULL)
		msgpart->wanted_fields |= MAIL_FETCH_STREAM_HEADER;
	if (fetch_type == FETCH_BODY || fetch_type == FETCH_FULL)
		msgpart->wanted_fields |= MAIL_FETCH_STREAM_BODY;
	return msgpart;
}

struct imap_msgpart *imap_msgpart_full(void)
{
	return imap_msgpart_type(FETCH_FULL);
}

struct imap_msgpart *imap_msgpart_header(void)
{
	return imap_msgpart_type(FETCH_HEADER);
}

struct imap_msgpart *imap_msgpart_body(void)
{
	return imap_msgpart_type(FETCH_BODY);
}

static struct message_part *
imap_msgpart_find(struct message_part *parts, const char *section)
{
	struct message_part *part = parts;
	const char *path;
	unsigned int num;

	path = section;
	while (*path >= '0' && *path <= '9' && part != NULL) {
		/* get part number, we have already verified its validity */
		num = 0;
		while (*path != '\0' && *path != '.') {
			i_assert(*path >= '0' && *path <= '9');

			num = num*10 + (*path - '0');
			path++;
		}

		if (*path == '.')
			path++;

		if ((part->flags & MESSAGE_PART_FLAG_MULTIPART) != 0) {
			/* find the part */
			part = part->children;
			for (; num > 1 && part != NULL; num--)
				part = part->next;
		} else {
			/* only 1 allowed with non-multipart messages */
			if (num != 1)
				part = NULL;
		}

		if (part != NULL &&
		    (part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) != 0 &&
		    (*path >= '0' && *path <= '9')) {
			/* if we continue inside the message/rfc822, skip this
			   body part */
			part = part->children;
		}
	}
	i_assert(part == NULL || *path == '\0');
	return part;
}

static int
imap_msgpart_get_header_fields(pool_t pool, const char *header_list,
			       ARRAY_TYPE(const_string) *fields)
{
	struct istream *input;
	struct imap_parser *parser;
	const struct imap_arg *args, *hdr_list;
	unsigned int list_count;
	unsigned int i;
	int result = 0;

	input = i_stream_create_from_data(header_list, strlen(header_list));
	parser = imap_parser_create(input, NULL, (size_t)-1);

	if (imap_parser_finish_line(parser, 0, 0, &args) > 0 &&
	    imap_arg_get_list_full(args, &hdr_list, &list_count) &&
	    args[1].type == IMAP_ARG_EOL &&
	    list_count > 0) {
		const char *value;
		
		p_array_init(fields, pool, list_count);
		for (i = 0; i < list_count; i++) {
			if (!imap_arg_get_astring(&hdr_list[i], &value)) {
				result = -1;
				break;
			}

			value = p_strdup(pool, t_str_ucase(value));
			array_append(fields, &value, 1);
		}
	} else {
		result = -1;
	}

	/* istream-header-filter requires headers to be sorted */
	array_sort(fields, i_strcasecmp_p);

	imap_parser_unref(&parser);
	i_stream_unref(&input);
	return result;
}

static int
imap_msgpart_parse_header_fields(struct mailbox *box,
				 struct imap_msgpart *msgpart,
				 const char *header_list)
{
	ARRAY_TYPE(const_string) fields;

	/* HEADER.FIELDS (list), HEADER.FIELDS.NOT (list) */
	if (imap_msgpart_get_header_fields(msgpart->pool, header_list,
					   &fields) < 0)
		return -1;

	(void)array_append_space(&fields);
	msgpart->headers = array_idx(&fields, 0);
	msgpart->header_ctx = mailbox_header_lookup_init(box, msgpart->headers);
	return 0;
}

int imap_msgpart_parse(struct mailbox *box, const char *section,
		       struct imap_msgpart **msgpart_r)
{
	struct imap_msgpart *msgpart;
	pool_t pool;
	unsigned int i;
	bool next_digit;
	int ret;

	pool = pool_alloconly_create("imap msgpart", 512);
	msgpart = *msgpart_r = p_new(pool, struct imap_msgpart, 1);
	msgpart->pool = pool;
	msgpart->partial_size = (uoff_t)-1;

	/* get the section number */
	next_digit = TRUE;
	for (i = 0; section[i] != '\0'; i++) {
		if (section[i] >= '0' && section[i] <= '9') {
			next_digit = FALSE;
		} else if (!next_digit && section[i] == '.') {
			next_digit = TRUE;
		} else {
			break;
		}
	}
	if (i == 0) {
		/* [], [HEADER], etc. */
		msgpart->section_number = "";
	} else if (section[i] == '\0') {
		/* [1.2.3] */
		if (i > 0 && section[i-1] == '.') {
			pool_unref(&pool);
			return -1;
		}
		msgpart->section_number = p_strdup(pool, section);
		section = "";
	} else {
		/* [1.2.3.MIME], [1.2.3.HEADER], etc */
		if (section[i-1] != '.') {
			pool_unref(&pool);
			return -1;
		}
		msgpart->section_number = p_strndup(pool, section, i-1);
		section += i;
	}

	if (*section == '\0') {
		/* full message/MIME part */
		msgpart->fetch_type = FETCH_FULL;
		msgpart->wanted_fields |= MAIL_FETCH_STREAM_BODY;
		if (*msgpart->section_number == '\0')
			msgpart->wanted_fields |= MAIL_FETCH_STREAM_HEADER;
		return 0;
	}
	section = t_str_ucase(section);

	if (strcmp(section, "MIME") == 0) {
		msgpart->fetch_type = FETCH_MIME;
		msgpart->wanted_fields |= MAIL_FETCH_STREAM_BODY;
	} else if (strcmp(section, "TEXT") == 0) {
		/* message body */
		msgpart->fetch_type = FETCH_BODY;
		msgpart->wanted_fields |= MAIL_FETCH_STREAM_BODY;
	} else if (strncmp(section, "HEADER", 6) == 0) {
		/* header */
		if (section[6] == '\0') {
			msgpart->fetch_type = FETCH_HEADER;
			ret = 0;
		} else if (strncmp(section, "HEADER.FIELDS ", 14) == 0) {
			msgpart->fetch_type = FETCH_HEADER_FIELDS;
			ret = imap_msgpart_parse_header_fields(box, msgpart,
							       section+14);
		} else if (strncmp(section, "HEADER.FIELDS.NOT ", 18) == 0) {
			msgpart->fetch_type = FETCH_HEADER_FIELDS_NOT;
			ret = imap_msgpart_parse_header_fields(box, msgpart,
							       section+18);
		} else {
			ret = -1;
		}
		if (ret < 0) {
			imap_msgpart_free(&msgpart);
			return -1;
		}
		if (msgpart->fetch_type == FETCH_HEADER_FIELDS) {
			/* we may be able to get this from cache, don't give a
			   wanted_fields hint */
		} else if (*msgpart->section_number == '\0')
			msgpart->wanted_fields |= MAIL_FETCH_STREAM_HEADER;
		else
			msgpart->wanted_fields |= MAIL_FETCH_STREAM_BODY;
	}
	return 0;
}

void imap_msgpart_free(struct imap_msgpart **_msgpart)
{
	struct imap_msgpart *msgpart = *_msgpart;

	*_msgpart = NULL;

	if (msgpart->header_ctx != NULL)
		mailbox_header_lookup_unref(&msgpart->header_ctx);
	pool_unref(&msgpart->pool);
}

void imap_msgpart_set_partial(struct imap_msgpart *msgpart,
			      uoff_t offset, uoff_t size)
{
	msgpart->partial_offset = offset;
	msgpart->partial_size = size;
}

uoff_t imap_msgpart_get_partial_offset(struct imap_msgpart *msgpart)
{
	return msgpart->partial_offset;
}

enum mail_fetch_field imap_msgpart_get_fetch_data(struct imap_msgpart *msgpart)
{
	return msgpart->wanted_fields;
}

static int
imap_msgpart_get_partial_header(struct mail *mail, struct istream *mail_input,
				const struct imap_msgpart *msgpart,
				struct message_size *hdr_size_r,
				struct imap_msgpart_open_result *result_r)
{
	const char *const *hdr_fields = msgpart->headers;
	unsigned int hdr_count = str_array_length(hdr_fields);
	struct istream *input;

	if (msgpart->fetch_type == FETCH_HEADER_FIELDS) {
		input = i_stream_create_header_filter(mail_input,
						      HEADER_FILTER_INCLUDE |
						      HEADER_FILTER_HIDE_BODY,
						      hdr_fields, hdr_count,
						      null_header_filter_callback, NULL);
	} else {
		i_assert(msgpart->fetch_type == FETCH_HEADER_FIELDS_NOT);
		input = i_stream_create_header_filter(mail_input,
						      HEADER_FILTER_EXCLUDE |
						      HEADER_FILTER_HIDE_BODY,
						      hdr_fields, hdr_count,
						      null_header_filter_callback, NULL);
	}

	if (message_get_header_size(input, hdr_size_r, NULL) < 0) {
		errno = input->stream_errno;
		mail_storage_set_critical(mail->box->storage,
			"read(%s) failed: %m", i_stream_get_name(mail_input));
		i_stream_unref(&input);
		return -1;
	}
	i_stream_seek(input, 0);
	result_r->input = input;
	result_r->size = hdr_size_r->virtual_size;
	return 0;
}

static void
skip_using_parts(struct mail *mail, struct istream *input,
		 uoff_t *virtual_skip)
{
	enum mail_lookup_abort old_lookup_abort;
	struct message_part *parts, *part;
	uoff_t vpos;
	int ret;

	old_lookup_abort = mail->lookup_abort;
	mail->lookup_abort = MAIL_LOOKUP_ABORT_NOT_IN_CACHE;
	ret = mail_get_parts(mail, &parts);
	mail->lookup_abort = old_lookup_abort;
	if (ret < 0)
		return;

	for (part = parts, vpos = 0; part != NULL; ) {
		if (vpos + part->header_size.virtual_size > *virtual_skip)
			break;
		/* skip header */
		vpos += part->header_size.virtual_size;
		*virtual_skip -= part->header_size.virtual_size;
		i_stream_seek(input, part->physical_pos +
			      part->header_size.physical_size);

		if (vpos + part->body_size.virtual_size <= *virtual_skip) {
			/* skip body */
			vpos += part->body_size.virtual_size;
			*virtual_skip -= part->body_size.virtual_size;
			i_stream_seek(input, part->physical_pos +
				      part->header_size.physical_size +
				      part->body_size.physical_size);
			part = part->next;
		} else {
			/* maybe we have a child and can skip using it? */
			part = part->children;
		}
	}
}

static struct istream *
imap_msgpart_crlf_seek(struct mail *mail, struct istream *input,
		       const struct imap_msgpart *msgpart)
{
	struct mail_msgpart_partial_cache *cache = &mail->box->partial_cache;
	struct istream *nul_input, *crlf_input;
	const unsigned char *data;
	size_t size;
	uoff_t physical_start = input->v_offset;
	uoff_t virtual_skip = msgpart->partial_offset;

	i_assert(msgpart->headers == NULL); /* HEADER.FIELDS returns CRLFs */

	if (virtual_skip == 0) {
		/* no need to seek */
	} else if (cache->uid == mail->uid &&
		   cache->physical_start == physical_start &&
		   cache->virtual_pos < virtual_skip) {
		/* use cache */
		i_stream_seek(input, cache->physical_pos);
		virtual_skip -= cache->virtual_pos;
	} else {
		/* can't use cache, but maybe we can skip faster using the
		   message parts. */
		skip_using_parts(mail, input, &virtual_skip);
	}
	if (!mail->has_no_nuls) {
		nul_input = i_stream_create_nonuls(input, 0x80);
		i_stream_unref(&input);
		input = nul_input;
	}
	crlf_input = i_stream_create_crlf(input);
	i_stream_unref(&input);
	input = crlf_input;
	i_stream_skip(input, virtual_skip);

	if ((msgpart->partial_offset != 0 ||
	     msgpart->partial_size != (uoff_t)-1) &&
	    i_stream_read_data(input, &data, &size, 0) > 0) {
		/* update cache */
		cache->uid = mail->uid;
		cache->physical_start = physical_start;
		cache->physical_pos = input->v_offset;
		cache->virtual_pos = msgpart->partial_offset;
		if (data[0] == '\n') {
			/* the physical_pos points to virtual CRLF, but
			   virtual_pos already skipped CR. that can't work,
			   so seek back the virtual CR */
			cache->virtual_pos--;
		}
	}
	return input;
}

static void
imap_msgpart_get_partial(struct mail *mail, const struct imap_msgpart *msgpart,
			 const struct message_size *part_size,
			 struct imap_msgpart_open_result *result)
{
	struct istream *input2;
	uoff_t bytes_left;

	/* input is already seeked to the beginning of the wanted data */

	if (msgpart->partial_offset >= part_size->virtual_size) {
		/* can't seek past the MIME part */
		i_stream_unref(&result->input);
		result->input = i_stream_create_from_data("", 0);
		result->size = 0;
		return;
	}

	if (part_size->virtual_size == part_size->physical_size) {
		/* input has CRLF linefeeds, we can quickly seek to
		   wanted position */
		i_stream_skip(result->input, msgpart->partial_offset);
	} else {
		/* input has LF linefeeds. it can be slow to seek to wanted
		   position, so try to do caching whenever possible */
		result->input = imap_msgpart_crlf_seek(mail, result->input,
						       msgpart);
	}

	bytes_left = part_size->virtual_size - msgpart->partial_offset;
	if (msgpart->partial_size <= bytes_left) {
		/* limit output to specified number of bytes */
		result->size = msgpart->partial_size;
	} else {
		/* send all bytes */
		result->size = bytes_left;
	}
	input2 = i_stream_create_limit(result->input, result->size);
	i_stream_unref(&result->input);
	result->input = input2;
}

int imap_msgpart_open(struct mail *mail, struct imap_msgpart *msgpart,
		      struct imap_msgpart_open_result *result_r)
{
	struct message_part *parts, *part = NULL;
	struct message_size hdr_size, body_size, part_size;
	struct istream *input = NULL;
	uoff_t physical_pos = 0;

	memset(result_r, 0, sizeof(*result_r));
	memset(&hdr_size, 0, sizeof(hdr_size));
	memset(&body_size, 0, sizeof(body_size));
	memset(&part_size, 0, sizeof(part_size));

	if (*msgpart->section_number != '\0') {
		/* find the MIME part */
		if (mail_get_parts(mail, &parts) < 0)
			return -1;
		part = imap_msgpart_find(parts, msgpart->section_number);
		if (part != NULL && (msgpart->fetch_type == FETCH_HEADER ||
				     msgpart->fetch_type == FETCH_BODY)) {
			/* fetching message/rfc822 part's header/body */
			if ((part->flags & MESSAGE_PART_FLAG_MESSAGE_RFC822) == 0)
				part = NULL;
			else {
				i_assert(part->children != NULL &&
					 part->children->next == NULL);
				part = part->children;
			}
		}
		if (part == NULL) {
			/* MIME part not found. return an empty stream. */
			result_r->input = i_stream_create_from_data("", 0);
			return 0;
		}
		if (mail_get_stream(mail, NULL, NULL, &input) < 0)
			return -1;

		physical_pos = part->physical_pos;
		hdr_size = part->header_size;
		body_size = part->body_size;
	} else switch (msgpart->fetch_type) {
	case FETCH_FULL:
		/* fetch the whole message */
		if (mail_get_stream(mail, NULL, NULL, &input) < 0 ||
		    mail_get_virtual_size(mail, &body_size.virtual_size) < 0 ||
		    mail_get_physical_size(mail, &body_size.physical_size) < 0)
			return -1;
		result_r->size_field = MAIL_FETCH_VIRTUAL_SIZE;
		break;
	case FETCH_MIME:
		i_unreached();
	case FETCH_HEADER:
	case FETCH_HEADER_FIELDS_NOT:
		/* fetch the message's header */
		if (mail_get_hdr_stream(mail, &hdr_size, &input) < 0)
			return -1;
		result_r->size_field = MAIL_FETCH_MESSAGE_PARTS;
		break;
	case FETCH_HEADER_FIELDS:
		/* try to lookup the headers from cache */
		i_assert(msgpart->header_ctx != NULL);
		if (mail_get_header_stream(mail, msgpart->header_ctx,
					   &input) < 0)
			return -1;
		result_r->size_field = 0;
		break;
	case FETCH_BODY:
		/* fetch the message's body */
		if (mail_get_stream(mail, &hdr_size, &body_size, &input) < 0)
			return -1;
		result_r->size_field = MAIL_FETCH_MESSAGE_PARTS;
		break;
	}
	i_stream_seek(input, physical_pos);

	if (msgpart->headers != NULL) {
		/* return specific headers */
		if (imap_msgpart_get_partial_header(mail, input, msgpart,
						    &hdr_size, result_r) < 0)
			return -1;
		imap_msgpart_get_partial(mail, msgpart, &hdr_size, result_r);
		return 0;
	}

	switch (msgpart->fetch_type) {
	case FETCH_FULL:
		part_size.physical_size += body_size.physical_size;
		part_size.virtual_size += body_size.virtual_size;
		/* fall through */
	case FETCH_MIME:
	case FETCH_HEADER:
		part_size.physical_size += hdr_size.physical_size;
		part_size.virtual_size += hdr_size.virtual_size;
		break;
	case FETCH_HEADER_FIELDS:
	case FETCH_HEADER_FIELDS_NOT:
		i_unreached();
	case FETCH_BODY:
		i_stream_skip(input, hdr_size.physical_size);
		part_size.physical_size += body_size.physical_size;
		part_size.virtual_size += body_size.virtual_size;
		break;
	}

	result_r->input = input;
	i_stream_ref(input);
	imap_msgpart_get_partial(mail, msgpart, &part_size, result_r);
	return 0;
}
