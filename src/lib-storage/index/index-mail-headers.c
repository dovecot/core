/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "array.h"
#include "buffer.h"
#include "str.h"
#include "message-date.h"
#include "message-parser.h"
#include "message-header-decode.h"
#include "istream-tee.h"
#include "istream-header-filter.h"
#include "imap-envelope.h"
#include "imap-bodystructure.h"
#include "index-storage.h"
#include "index-mail.h"

#include <stdlib.h>

struct index_header_lookup_ctx {
	struct mailbox_header_lookup_ctx ctx;
	pool_t pool;

	unsigned int count;
	unsigned int *idx;
	const char **name;
};

static const enum message_header_parser_flags hdr_parser_flags =
	MESSAGE_HEADER_PARSER_FLAG_SKIP_INITIAL_LWSP |
	MESSAGE_HEADER_PARSER_FLAG_DROP_CR;
static const enum message_parser_flags msg_parser_flags =
	MESSAGE_PARSER_FLAG_SKIP_BODY_BLOCK;

static int header_line_cmp(const struct index_mail_line *l1,
			   const struct index_mail_line *l2)
{
	int diff;

	diff = (int)l1->field_idx - (int)l2->field_idx;
	return diff != 0 ? diff :
		(int)l1->line_num - (int)l2->line_num;
}

static void index_mail_parse_header_finish(struct index_mail *mail)
{
	const struct index_mail_line *lines;
	const unsigned char *header, *data;
	const uint8_t *match;
	buffer_t *buf;
	size_t data_size;
	unsigned int i, j, count, match_idx, match_count;
	bool noncontiguous;

	/* sort it first so fields are grouped together and ordered by
	   line number */
	array_sort(&mail->header_lines, header_line_cmp);

	lines = array_get(&mail->header_lines, &count);
	match = array_get(&mail->header_match, &match_count);
	header = buffer_get_data(mail->header_data, NULL);
	buf = buffer_create_dynamic(pool_datastack_create(), 256);

	/* go through all the header lines we found */
	for (i = match_idx = 0; i < count; i = j) {
		/* matches and header lines are both sorted, all matches
		   until lines[i] weren't found */
		while (match_idx < lines[i].field_idx &&
		       match_idx < match_count) {
			if (HEADER_MATCH_USABLE(mail, match[match_idx]) &&
			    mail_cache_field_can_add(mail->trans->cache_trans,
						     mail->data.seq,
						     match_idx)) {
				/* this header doesn't exist. remember that. */
				i_assert((match[match_idx] &
					  HEADER_MATCH_FLAG_FOUND) == 0);
				index_mail_cache_add_idx(mail, match_idx,
							 NULL, 0);
			}
			match_idx++;
		}

		if (match_idx < match_count) {
			/* save index to first header line */
			j = i + 1;
			array_idx_set(&mail->header_match_lines, match_idx, &j);
			match_idx++;
		}

		if (!mail_cache_field_can_add(mail->trans->cache_trans,
					      mail->data.seq,
					      lines[i].field_idx)) {
			/* header is already cached */
			j = i + 1;
			continue;
		}

		/* buffer contains: { uint32_t line_num[], 0, header texts }
		   noncontiguous is just a small optimization.. */
		buffer_set_used_size(buf, 0);
		buffer_append(buf, &lines[i].line_num,
			      sizeof(lines[i].line_num));

		noncontiguous = FALSE;
		for (j = i+1; j < count; j++) {
			if (lines[j].field_idx != lines[i].field_idx)
				break;

			if (lines[j].start_pos != lines[j-1].end_pos)
				noncontiguous = TRUE;
			buffer_append(buf, &lines[j].line_num,
				      sizeof(lines[j].line_num));
		}
		buffer_append_zero(buf, sizeof(uint32_t));

		if (noncontiguous) {
			for (; i < j; i++) {
				buffer_append(buf, header + lines[i].start_pos,
					      lines[i].end_pos -
					      lines[i].start_pos);
			}
			i--;
		} else {
			buffer_append(buf, header + lines[i].start_pos,
				      lines[j-1].end_pos - lines[i].start_pos);
		}

		data = buffer_get_data(buf, &data_size);
		index_mail_cache_add_idx(mail, lines[i].field_idx,
					 data, data_size);
	}

	for (; match_idx < match_count; match_idx++) {
		if (HEADER_MATCH_USABLE(mail, match[match_idx]) &&
		    mail_cache_field_can_add(mail->trans->cache_trans,
					     mail->data.seq,
					     match_idx)) {
			/* this header doesn't exist. remember that. */
			i_assert((match[match_idx] &
				  HEADER_MATCH_FLAG_FOUND) == 0);
			index_mail_cache_add_idx(mail, match_idx, NULL, 0);
		}
	}

	mail->data.dont_cache_field_idx = -1U;
}

static unsigned int
get_header_field_idx(struct mailbox *box, const char *field,
		     enum mail_cache_decision_type decision)
{
	struct mail_cache_field header_field = {
		NULL, 0, MAIL_CACHE_FIELD_HEADER, 0,
		MAIL_CACHE_DECISION_NO
	};

	header_field.decision = decision;
	T_BEGIN {
		header_field.name = t_strconcat("hdr.", field, NULL);
		mail_cache_register_fields(box->cache, &header_field, 1);
	} T_END;
	return header_field.idx;
}

bool index_mail_want_parse_headers(struct index_mail *mail)
{
	if (mail->wanted_headers != NULL ||
	    mail->data.save_bodystructure_header)
		return TRUE;

	if ((mail->data.cache_fetch_fields & MAIL_FETCH_DATE) != 0 &&
	    !mail->data.sent_date_parsed)
		return TRUE;
	return FALSE;
}

static void index_mail_parse_header_register_all_wanted(struct index_mail *mail)
{
	const struct mail_cache_field *all_cache_fields;
	unsigned int i, count;

	all_cache_fields =
		mail_cache_register_get_list(mail->mail.mail.box->cache,
					     pool_datastack_create(), &count);
	for (i = 0; i < count; i++) {
		if (strncasecmp(all_cache_fields[i].name, "hdr.", 4) != 0)
			continue;
		if (!mail_cache_field_want_add(mail->trans->cache_trans,
					       mail->data.seq, i))
			continue;

		array_idx_set(&mail->header_match, all_cache_fields[i].idx,
			      &mail->header_match_value);
	}
}

void index_mail_parse_header_init(struct index_mail *mail,
				  struct mailbox_header_lookup_ctx *_headers)
{
	struct index_header_lookup_ctx *headers =
		(struct index_header_lookup_ctx *)_headers;
	const uint8_t *match;
	unsigned int i, field_idx, match_count;

	mail->header_seq = mail->data.seq;
	if (mail->header_data == NULL) {
		mail->header_data = buffer_create_dynamic(default_pool, 4096);
		i_array_init(&mail->header_lines, 32);
		i_array_init(&mail->header_match, 32);
		i_array_init(&mail->header_match_lines, 32);
		mail->header_match_value = HEADER_MATCH_SKIP_COUNT;
	} else {
		buffer_set_used_size(mail->header_data, 0);
		array_clear(&mail->header_lines);
		array_clear(&mail->header_match_lines);

		mail->header_match_value += HEADER_MATCH_SKIP_COUNT;
		i_assert((mail->header_match_value &
			  (HEADER_MATCH_SKIP_COUNT-1)) == 0);
		if (mail->header_match_value == 0) {
			/* wrapped, we'll have to clear the buffer */
			array_clear(&mail->header_match);
			mail->header_match_value = HEADER_MATCH_SKIP_COUNT;
		}
	}

	if (headers != NULL) {
		for (i = 0; i < headers->count; i++) {
			array_idx_set(&mail->header_match, headers->idx[i],
				      &mail->header_match_value);
		}
	}

	if (mail->wanted_headers != NULL && mail->wanted_headers != headers) {
		headers = mail->wanted_headers;
		for (i = 0; i < headers->count; i++) {
			array_idx_set(&mail->header_match, headers->idx[i],
				      &mail->header_match_value);
		}
	}

	/* register also all the other headers that exist in cache file */
	T_BEGIN {
		index_mail_parse_header_register_all_wanted(mail);
	} T_END;

	/* if we want sent date, it doesn't mean that we also want to cache
	   Date: header. if we have Date field's index set at this point we
	   know that we want it. otherwise add it and remember that we don't
	   want it cached. */
	field_idx = get_header_field_idx(mail->mail.mail.box, "Date",
					 MAIL_CACHE_DECISION_NO);
	match = array_get(&mail->header_match, &match_count);
	if (field_idx < match_count &&
	    match[field_idx] == mail->header_match_value) {
		/* cache Date: header */
	} else if ((mail->data.cache_fetch_fields & MAIL_FETCH_DATE) != 0 ||
		   mail->data.save_sent_date) {
		/* parse Date: header, but don't cache it. */
		mail->data.dont_cache_field_idx = field_idx;
		array_idx_set(&mail->header_match, field_idx,
			      &mail->header_match_value);
	}
}

static void index_mail_parse_finish_imap_envelope(struct index_mail *mail)
{
	const unsigned int cache_field_envelope =
		mail->ibox->cache_fields[MAIL_CACHE_IMAP_ENVELOPE].idx;
	string_t *str;

	str = str_new(mail->data_pool, 256);
	imap_envelope_write_part_data(mail->data.envelope_data, str);
	mail->data.envelope = str_c(str);

	if (mail_cache_field_can_add(mail->trans->cache_trans,
				     mail->data.seq, cache_field_envelope)) {
		index_mail_cache_add_idx(mail, cache_field_envelope,
					 str_data(str), str_len(str));
	}
}

void index_mail_parse_header(struct message_part *part,
			     struct message_header_line *hdr,
			     struct index_mail *mail)
{
	struct mail *_mail = &mail->mail.mail;
	struct index_mail_data *data = &mail->data;
	unsigned int field_idx, count;
	uint8_t *match;

        data->parse_line_num++;

	if (data->save_bodystructure_header) {
		i_assert(part != NULL);
		imap_bodystructure_parse_header(mail->data_pool, part, hdr);
	}

	if (data->save_envelope) {
		imap_envelope_parse_header(mail->data_pool,
					   &data->envelope_data, hdr);

		if (hdr == NULL)
                        index_mail_parse_finish_imap_envelope(mail);
	}

	if (hdr == NULL) {
		/* end of headers */
		if (mail->data.save_sent_date)
			mail->data.sent_date_parsed = TRUE;
		T_BEGIN {
			index_mail_parse_header_finish(mail);
		} T_END;
                data->save_bodystructure_header = FALSE;
		return;
	}

	if (!hdr->continued) {
		T_BEGIN {
			const char *cache_field_name =
				t_strconcat("hdr.", hdr->name, NULL);
			data->parse_line.field_idx =
				mail_cache_register_lookup(_mail->box->cache,
							   cache_field_name);
		} T_END;
	}
	field_idx = data->parse_line.field_idx;
	match = array_get_modifiable(&mail->header_match, &count);
	if (field_idx >= count ||
	    !HEADER_MATCH_USABLE(mail, match[field_idx])) {
		/* we don't want this header. */
		return;
	}

	if (!hdr->continued) {
		/* beginning of a line. add the header name. */
		data->parse_line.start_pos = str_len(mail->header_data);
		data->parse_line.line_num = data->parse_line_num;
		str_append(mail->header_data, hdr->name);
		str_append_n(mail->header_data, hdr->middle, hdr->middle_len);

		/* remember that we saw this header so we don't add it to
		   cache as nonexistent. */
		match[field_idx] |= HEADER_MATCH_FLAG_FOUND;
	}
	str_append_n(mail->header_data, hdr->value, hdr->value_len);
	if (!hdr->no_newline)
		str_append(mail->header_data, "\n");
	if (!hdr->continues) {
		data->parse_line.end_pos = str_len(mail->header_data);
		array_append(&mail->header_lines, &data->parse_line, 1);
	}
}

static void
index_mail_parse_part_header_cb(struct message_part *part,
				struct message_header_line *hdr,
				struct index_mail *mail)
{
	index_mail_parse_header(part, hdr, mail);
}

static void
index_mail_parse_header_cb(struct message_header_line *hdr,
			   struct index_mail *mail)
{
	index_mail_parse_header(mail->data.parts, hdr, mail);
}

struct istream *
index_mail_cache_parse_init(struct mail *_mail, struct istream *input)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct istream *input2;

	i_assert(mail->data.tee_stream == NULL);
	i_assert(mail->data.parser_ctx == NULL);

	/* we're doing everything for now, figure out later if we want to
	   save them. */
	mail->data.save_sent_date = TRUE;
	mail->data.save_bodystructure_header = TRUE;
	mail->data.save_bodystructure_body = TRUE;

	mail->data.tee_stream = tee_i_stream_create(input);
	input = tee_i_stream_create_child(mail->data.tee_stream);
	input2 = tee_i_stream_create_child(mail->data.tee_stream);

	index_mail_parse_header_init(mail, NULL);
	mail->data.parser_ctx =
		message_parser_init(mail->data_pool, input,
				    hdr_parser_flags, msg_parser_flags);
	i_stream_unref(&input);
	return input2;
}

static void index_mail_init_parser(struct index_mail *mail)
{
	struct index_mail_data *data = &mail->data;
	struct message_part *parts;

	if (data->parser_ctx != NULL)
		(void)message_parser_deinit(&data->parser_ctx, &parts);

	if (data->parts == NULL) {
		data->parser_ctx = message_parser_init(mail->data_pool,
						       data->stream,
						       hdr_parser_flags,
						       msg_parser_flags);
	} else {
		data->parser_ctx =
			message_parser_init_from_parts(data->parts,
						       data->stream,
						       hdr_parser_flags,
						       msg_parser_flags);
	}
}

int index_mail_parse_headers(struct index_mail *mail,
			     struct mailbox_header_lookup_ctx *headers)
{
	struct index_mail_data *data = &mail->data;
	struct istream *input;
	uoff_t old_offset;

	old_offset = data->stream == NULL ? 0 : data->stream->v_offset;

	if (mail_get_stream(&mail->mail.mail, NULL, NULL, &input) < 0)
		return -1;

	index_mail_parse_header_init(mail, headers);

	if (data->parts == NULL || data->save_bodystructure_header) {
		/* initialize bodystructure parsing in case we read the whole
		   message. */
		index_mail_init_parser(mail);
		message_parser_parse_header(data->parser_ctx, &data->hdr_size,
					    index_mail_parse_part_header_cb,
					    mail);
	} else {
		/* just read the header */
		message_parse_header(data->stream, &data->hdr_size,
				     hdr_parser_flags,
				     index_mail_parse_header_cb, mail);
	}
	data->hdr_size_set = TRUE;
	data->access_part &= ~PARSE_HDR;

	i_stream_seek(data->stream, old_offset);
	return 0;
}

static void
imap_envelope_parse_callback(struct message_header_line *hdr,
			     struct index_mail *mail)
{
	imap_envelope_parse_header(mail->data_pool,
				   &mail->data.envelope_data, hdr);

	if (hdr == NULL)
		index_mail_parse_finish_imap_envelope(mail);
}

int index_mail_headers_get_envelope(struct index_mail *mail)
{
	const unsigned int cache_field_envelope =
		mail->ibox->cache_fields[MAIL_CACHE_IMAP_ENVELOPE].idx;
	struct mailbox_header_lookup_ctx *header_ctx;
	struct istream *stream;
	uoff_t old_offset;
	string_t *str;

	str = str_new(mail->data_pool, 256);
	if (index_mail_cache_lookup_field(mail, str,
					  cache_field_envelope) > 0) {
		mail->data.envelope = str_c(str);
		return 0;
	}
	str_free(&str);

	old_offset = mail->data.stream == NULL ? 0 :
		mail->data.stream->v_offset;

	mail->data.save_envelope = TRUE;
	header_ctx = mailbox_header_lookup_init(mail->mail.mail.box,
						imap_envelope_headers);
	if (mail_get_header_stream(&mail->mail.mail, header_ctx, &stream) < 0) {
		mailbox_header_lookup_unref(&header_ctx);
		return -1;
	}

	if (mail->data.envelope == NULL && stream != NULL) {
		/* we got the headers from cache - parse them to get the
		   envelope */
		message_parse_header(stream, NULL, hdr_parser_flags,
				     imap_envelope_parse_callback, mail);
		mail->data.save_envelope = FALSE;
	}
	mailbox_header_lookup_unref(&header_ctx);

	if (mail->data.stream != NULL)
		i_stream_seek(mail->data.stream, old_offset);
	return 0;
}

static size_t get_header_size(buffer_t *buffer, size_t pos)
{
	const unsigned char *data;
	size_t i, size;

	data = buffer_get_data(buffer, &size);
	i_assert(pos <= size);

	for (i = pos; i < size; i++) {
		if (data[i] == '\n') {
			if (i+1 == size ||
			    (data[i+1] != ' ' && data[i+1] != '\t'))
				return i - pos;
		}
	}
	return size - pos;
}

static int index_mail_header_is_parsed(struct index_mail *mail,
				       unsigned int field_idx)
{
	const uint8_t *match;
	unsigned int count;

	match = array_get(&mail->header_match, &count);
	if (field_idx < count && HEADER_MATCH_USABLE(mail, match[field_idx]))
		return (match[field_idx] & HEADER_MATCH_FLAG_FOUND) != 0;
	return -1;
}

static bool skip_header(const unsigned char **data, size_t len)
{
	const unsigned char *p = *data;
	size_t i;

	for (i = 0; i < len; i++) {
		if (p[i] == ':')
			break;
	}
	if (i == len)
		return FALSE;

	for (i++; i < len; i++) {
		if (!IS_LWSP(p[i]))
			break;
	}

	*data = p + i;
	return TRUE;
}

static const char *const *
index_mail_get_parsed_header(struct index_mail *mail, unsigned int field_idx)
{
	ARRAY_DEFINE(header_values, const char *);
        const struct index_mail_line *lines;
	const unsigned char *header, *value_start, *value_end;
	const unsigned int *line_idx;
	const char *value;
	unsigned int i, lines_count, first_line_idx;

	line_idx = array_idx(&mail->header_match_lines, field_idx);
	i_assert(*line_idx != 0);
	first_line_idx = *line_idx - 1;

	p_array_init(&header_values, mail->data_pool, 4);
	header = buffer_get_data(mail->header_data, NULL);

	lines = array_get(&mail->header_lines, &lines_count);
	for (i = first_line_idx; i < lines_count; i++) {
		if (lines[i].field_idx != lines[first_line_idx].field_idx)
			break;

		/* skip header: and drop ending LF */
		value_start = header + lines[i].start_pos;
		value_end = header + lines[i].end_pos;
		if (skip_header(&value_start, value_end - value_start)) {
			if (value_start != value_end && value_end[-1] == '\n')
				value_end--;
			value = p_strndup(mail->data_pool, value_start,
					  value_end - value_start);
			array_append(&header_values, &value, 1);
		}
	}

	(void)array_append_space(&header_values);
	return array_idx(&header_values, 0);
}

static int
index_mail_get_raw_headers(struct index_mail *mail, const char *field,
			   const char *const **value_r)
{
	const char *headers[2], *value;
	struct mailbox_header_lookup_ctx *headers_ctx;
	unsigned char *data;
	unsigned int field_idx;
	string_t *dest;
	size_t i, len;
	int ret;
	ARRAY_DEFINE(header_values, const char *);

	i_assert(field != NULL);

	field_idx = get_header_field_idx(mail->mail.mail.box, field,
					 MAIL_CACHE_DECISION_TEMP);

	dest = str_new(mail->data_pool, 128);
	if (mail_cache_lookup_headers(mail->trans->cache_view, dest,
				      mail->data.seq, &field_idx, 1) <= 0) {
		/* not in cache / error - first see if it's already parsed */
		p_free(mail->data_pool, dest);

		if (mail->header_seq != mail->data.seq ||
		    index_mail_header_is_parsed(mail, field_idx) < 0) {
			/* parse */
			headers[0] = field; headers[1] = NULL;
			headers_ctx = mailbox_header_lookup_init(
						mail->mail.mail.box, headers);
			ret = index_mail_parse_headers(mail, headers_ctx);
			mailbox_header_lookup_unref(&headers_ctx);
			if (ret < 0)
				return -1;
		}

		if ((ret = index_mail_header_is_parsed(mail, field_idx)) <= 0) {
			/* not found */
			i_assert(ret != -1);
			*value_r = p_new(mail->data_pool, const char *, 1);
			return 0;
		}
		*value_r = index_mail_get_parsed_header(mail, field_idx);
		return 0;
	}
	mail->mail.stats_cache_hit_count++;
	data = buffer_get_modifiable_data(dest, &len);

	if (len == 0) {
		/* cached as nonexistent. */
		*value_r = p_new(mail->data_pool, const char *, 1);
		return 0;
	}

	p_array_init(&header_values, mail->data_pool, 4);

	/* cached. skip "header name: " parts in dest. */
	for (i = 0; i < len; i++) {
		if (data[i] == ':') {
			if (i+1 != len && data[++i] == ' ') i++;

			/* @UNSAFE */
			len = get_header_size(dest, i);
			data[i + len] = '\0';
			value = (const char *)data + i;
			i += len + 1;

			array_append(&header_values, &value, 1);
		}
	}

	(void)array_append_space(&header_values);
	*value_r = array_idx(&header_values, 0);
	return 0;
}

static int unfold_header(pool_t pool, const char **_str)
{
	const char *str = *_str;
	char *new_str;
	unsigned int i, j;

	for (i = 0; str[i] != '\0'; i++) {
		if (str[i] == '\n')
			break;
	}
	if (str[i] == '\0')
		return 0;

	/* @UNSAFE */
	new_str = p_malloc(pool, i + strlen(str+i) + 1);
	memcpy(new_str, str, i);
	for (j = i; str[i] != '\0'; i++) {
		if (str[i] == '\n') {
			new_str[j++] = ' ';
			i++;
			if (str[i] == '\0')
				break;

			if (str[i] != ' ' && str[i] != '\t') {
				/* corrupted */
				return -1;
			}
		} else {
			new_str[j++] = str[i];
		}
	}
	new_str[j] = '\0';
	*_str = new_str;
	return 0;
}

static int
index_mail_headers_decode(struct index_mail *mail, const char *const **_list,
			  unsigned int max_count)
{
	const char *const *list = *_list;
	const char **decoded_list, *input;
	unsigned int i, count;
	string_t *str;

	count = str_array_length(list);
	if (count > max_count)
		count = max_count;
	decoded_list = p_new(mail->data_pool, const char *, count + 1);

	str = t_str_new(512);
	for (i = 0; i < count; i++) {
		str_truncate(str, 0);
		input = list[i];
		/* unfold all lines into a single line */
		if (unfold_header(mail->data_pool, &input) < 0)
			return -1;

		/* decode MIME encoded-words. decoding may also add new LFs. */
		if (message_header_decode_utf8((const unsigned char *)input,
					       strlen(list[i]), str, FALSE))
			input = p_strdup(mail->data_pool, str_c(str));
		decoded_list[i] = input;
	}
	*_list = decoded_list;
	return 0;
}

int index_mail_get_headers(struct mail *_mail, const char *field,
			   bool decode_to_utf8, const char *const **value_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	int ret, i;

	for (i = 0; i < 2; i++) {
		if (index_mail_get_raw_headers(mail, field, value_r) < 0)
			return -1;
		if (!decode_to_utf8 || **value_r == NULL)
			return 0;

		T_BEGIN {
			ret = index_mail_headers_decode(mail, value_r, -1U);
		} T_END;

		if (ret < 0) {
			mail_cache_set_corrupted(_mail->box->cache,
				"Broken header %s for mail UID %u",
				field, _mail->uid);
		}
	}
	return ret;
}

int index_mail_get_first_header(struct mail *_mail, const char *field,
				bool decode_to_utf8, const char **value_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	const char *const *list;
	int ret, i;

	for (i = 0; i < 2; i++) {
		if (index_mail_get_raw_headers(mail, field, &list) < 0)
			return -1;
		if (!decode_to_utf8 || list[0] == NULL) {
			ret = 0;
			break;
		}

		T_BEGIN {
			ret = index_mail_headers_decode(mail, &list, 1);
		} T_END;

		if (ret < 0) {
			mail_cache_set_corrupted(_mail->box->cache,
				"Broken header %s for mail UID %u",
				field, _mail->uid);
		}
	}
	*value_r = list[0];
	return ret < 0 ? -1 : (list[0] != NULL ? 1 : 0);
}

static void header_cache_callback(struct message_header_line *hdr,
				  bool *matched, struct index_mail *mail)
{
	if (hdr != NULL && hdr->eoh)
		*matched = FALSE;

	index_mail_parse_header(NULL, hdr, mail);
}

int index_mail_get_header_stream(struct mail *_mail,
				 struct mailbox_header_lookup_ctx *_headers,
				 struct istream **stream_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_header_lookup_ctx *headers =
		(struct index_header_lookup_ctx *)_headers;
	struct istream *input;
	string_t *dest;

	i_assert(_headers->box == _mail->box);

	if (mail->data.save_bodystructure_header) {
		/* we have to parse the header. */
		if (index_mail_parse_headers(mail, _headers) < 0)
			return -1;
	}

	dest = str_new(mail->data_pool, 256);
	if (mail_cache_lookup_headers(mail->trans->cache_view, dest,
				      mail->data.seq, headers->idx,
				      headers->count) > 0) {
		mail->mail.stats_cache_hit_count++;
		if (mail->data.filter_stream != NULL)
			i_stream_destroy(&mail->data.filter_stream);
		mail->data.filter_stream =
			i_stream_create_from_data(str_data(dest),
						  str_len(dest));
		*stream_r = mail->data.filter_stream;
		return 0;
	}
	/* not in cache / error */
	p_free(mail->data_pool, dest);

	if (mail_get_stream(&mail->mail.mail, NULL, NULL, &input) < 0)
		return -1;

	if (mail->data.filter_stream != NULL)
		i_stream_destroy(&mail->data.filter_stream);

	index_mail_parse_header_init(mail, _headers);
	mail->data.filter_stream =
		i_stream_create_header_filter(mail->data.stream,
					      HEADER_FILTER_INCLUDE |
					      HEADER_FILTER_HIDE_BODY,
					      headers->name, headers->count,
					      header_cache_callback, mail);
	*stream_r = mail->data.filter_stream;
	return 0;
}

static struct mailbox_header_lookup_ctx *
index_header_lookup_init_real(struct mailbox *box, const char *const headers[])
{
	struct mail_cache_field *fields, header_field = {
		NULL, 0, MAIL_CACHE_FIELD_HEADER, 0,
		MAIL_CACHE_DECISION_TEMP
	};
	struct index_header_lookup_ctx *ctx;
	const char *const *name;
	const char **sorted_headers;
	pool_t pool;
	unsigned int i, count;

	i_assert(*headers != NULL);

	for (count = 0, name = headers; *name != NULL; name++)
		count++;

	/* @UNSAFE: headers need to be sorted for filter stream. */
	sorted_headers = t_new(const char *, count);
	memcpy(sorted_headers, headers, count * sizeof(*sorted_headers));
	qsort(sorted_headers, count, sizeof(*sorted_headers), i_strcasecmp_p);
	headers = sorted_headers;

	/* @UNSAFE */
	fields = t_new(struct mail_cache_field, count);
	for (i = 0; i < count; i++) {
		header_field.name = t_strconcat("hdr.", headers[i], NULL);
		fields[i] = header_field;
	}
	mail_cache_register_fields(box->cache, fields, count);

	pool = pool_alloconly_create("index_header_lookup_ctx", 1024);
	ctx = p_new(pool, struct index_header_lookup_ctx, 1);
	ctx->ctx.box = box;
	ctx->ctx.refcount = 1;
	ctx->pool = pool;
	ctx->count = count;

	ctx->idx = p_new(pool, unsigned int, count);
	ctx->name = p_new(pool, const char *, count + 1);

	/* @UNSAFE */
	for (i = 0; i < count; i++) {
		ctx->idx[i] = fields[i].idx;
		ctx->name[i] = p_strdup(pool, headers[i]);
	}
	ctx->ctx.headers = ctx->name;
	return &ctx->ctx;
}

struct mailbox_header_lookup_ctx *
index_header_lookup_init(struct mailbox *box, const char *const headers[])
{
	struct mailbox_header_lookup_ctx *ctx;

	T_BEGIN {
		ctx = index_header_lookup_init_real(box, headers);
	} T_END;
	return ctx;
}

void index_header_lookup_deinit(struct mailbox_header_lookup_ctx *_ctx)
{
	struct index_header_lookup_ctx *ctx =
		(struct index_header_lookup_ctx *)_ctx;

	pool_unref(&ctx->pool);
}
