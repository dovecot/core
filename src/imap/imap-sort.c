/* Copyright (C) 2002 Timo Sirainen */

/* Implementation of draft-ietf-imapext-sort-10 sorting algorithm.
   Pretty messy code actually, adding any sort types requires care.
   This is pretty fast however and takes only as much memory as needed to be
   reasonably fast. */

#include "common.h"
#include "buffer.h"
#include "hash.h"
#include "ostream.h"
#include "str.h"
#include "imap-base-subject.h"
#include "mail-storage.h"
#include "message-address.h"
#include "imap-sort.h"

#include <stdlib.h>

#define MAX_WANTED_HEADERS 10
#define STRBUF_SIZE 1024

#define IS_SORT_STRING(type) \
	((type) == MAIL_SORT_CC || (type) == MAIL_SORT_FROM || \
	 (type) == MAIL_SORT_SUBJECT || (type) == MAIL_SORT_TO)

#define IS_SORT_TIME(type) \
	((type) == MAIL_SORT_ARRIVAL || (type) == MAIL_SORT_DATE)

struct sort_context {
	struct mail_search_context *search_ctx;
	struct mailbox_transaction_context *t;

	enum mail_sort_type sort_program[MAX_SORT_PROGRAM_SIZE];
	enum mail_sort_type common_mask, cache_mask;

	struct mailbox *box;
	struct ostream *output;
	string_t *str;

	buffer_t *sort_buffer;
	size_t sort_element_size;

	pool_t str_pool;
	struct hash_table *string_table;

	time_t last_arrival, last_date;
	uoff_t last_size;
	char *last_cc, *last_from, *last_subject, *last_to;

	int written, id_is_uid;
};

static void mail_sort_input(struct sort_context *ctx, struct mail *mail);
static void mail_sort_flush(struct sort_context *ctx);

static enum mail_sort_type
mail_sort_normalize(const enum mail_sort_type *input, buffer_t *output)
{
        enum mail_sort_type type, mask = 0;
	int pos, reverse;

	reverse = FALSE;
	for (pos = 0; *input != MAIL_SORT_END; input++) {
		if (*input == MAIL_SORT_REVERSE)
			reverse = !reverse;
		else {
			if ((mask & *input) == 0) {
				if (reverse) {
					type = MAIL_SORT_REVERSE;
					buffer_append(output,
						      &type, sizeof(type));
				}

				buffer_append(output, input, sizeof(*input));
				mask |= *input;
			}

			reverse = FALSE;
		}
	}

	type = MAIL_SORT_END;
	buffer_append(output, &type, sizeof(type));

	return mask;
}

static enum mail_sort_type
mail_sort_get_common_mask(const enum mail_sort_type *sort1,
			  const enum mail_sort_type *sort2,
			  unsigned int *count)
{
	enum mail_sort_type mask = 0;

	*count = 0;
	while (*sort1 == *sort2 && *sort1 != MAIL_SORT_END) {
		if (*sort1 != MAIL_SORT_REVERSE)
			mask |= *sort1;
		sort1++; sort2++; (*count)++;
	}

	return mask;
}

static enum mail_fetch_field
init_sort_elements(struct sort_context *ctx,
		   const char *wanted_headers[MAX_WANTED_HEADERS])
{
	unsigned int i;
        enum mail_fetch_field fields;

	/* figure out what data we'd like to cache */
	ctx->sort_element_size = sizeof(unsigned int);
	ctx->cache_mask = 0;

	for (i = 0; ctx->sort_program[i] != MAIL_SORT_END; i++) {
		enum mail_sort_type type = ctx->sort_program[i];

		if (IS_SORT_STRING(type)) {
			ctx->sort_element_size += sizeof(const char *);

			/* cache the second rule as well, if available */
			if (ctx->cache_mask != 0) {
				ctx->cache_mask |= type;
				break;
			}
			ctx->cache_mask |= type;
		} else if (IS_SORT_TIME(type)) {
			ctx->sort_element_size += sizeof(time_t);
			ctx->cache_mask |= type;
			break;
		} else if (type == MAIL_SORT_SIZE) {
			ctx->sort_element_size += sizeof(uoff_t);
			ctx->cache_mask |= type;
			break;
		}
	}

	fields = 0;
	if (ctx->cache_mask & MAIL_SORT_ARRIVAL)
		fields |= MAIL_FETCH_RECEIVED_DATE;
	if (ctx->cache_mask & MAIL_SORT_DATE)
		fields |= MAIL_FETCH_DATE;
	if (ctx->cache_mask & MAIL_SORT_SIZE)
		fields |= MAIL_FETCH_VIRTUAL_SIZE;

	/* @UNSAFE */
	i_assert(MAX_WANTED_HEADERS > 4);
	i = 0;
	if (ctx->cache_mask & MAIL_SORT_CC)
		wanted_headers[i++] = "cc";
	if (ctx->cache_mask & MAIL_SORT_FROM)
		wanted_headers[i++] = "from";
	if (ctx->cache_mask & MAIL_SORT_TO)
		wanted_headers[i++] = "to";
	if (ctx->cache_mask & MAIL_SORT_SUBJECT)
		wanted_headers[i++] = "subject";
	wanted_headers[i] = NULL;

	if ((ctx->cache_mask & MAIL_SORT_CC) ||
	    (ctx->cache_mask & MAIL_SORT_FROM) ||
	    (ctx->cache_mask & MAIL_SORT_TO) ||
	    (ctx->cache_mask & MAIL_SORT_SUBJECT)) {
		ctx->str_pool = pool_alloconly_create("sort str", 8192);
		ctx->string_table = hash_create(default_pool, ctx->str_pool,
						0, str_hash,
						(hash_cmp_callback_t *)strcmp);
	}

	return fields;
}

static void mail_sort_deinit(struct sort_context *ctx)
{
	mail_sort_flush(ctx);

	if (ctx->string_table != NULL)
		hash_destroy(ctx->string_table);
	if (ctx->str_pool != NULL)
		pool_unref(ctx->str_pool);
	buffer_free(ctx->sort_buffer);

	i_free(ctx->last_cc);
	i_free(ctx->last_from);
	i_free(ctx->last_subject);
	i_free(ctx->last_to);
}

int imap_sort(struct client *client, const char *charset,
	      struct mail_search_arg *args,
	      const enum mail_sort_type *sort_program)
{
	enum mail_sort_type norm_prog[MAX_SORT_PROGRAM_SIZE];
        enum mail_fetch_field wanted_fields;
	const char *wanted_headers[MAX_WANTED_HEADERS];
	struct mailbox_header_lookup_ctx *headers_ctx;
	struct sort_context *ctx;
	struct mail *mail;
	buffer_t *buf;
	unsigned int count;
	int ret;

	ctx = t_new(struct sort_context, 1);

	/* normalize sorting program */
	buf = buffer_create_data(pool_datastack_create(),
				 norm_prog, sizeof(norm_prog));
	mail_sort_normalize(sort_program, buf);
	memcpy(ctx->sort_program, norm_prog, sizeof(ctx->sort_program));

	/* remove the common part from sort program, we already know input is
	   sorted that much so we don't have to worry about it. */
	if (mailbox_search_get_sorting(client->mailbox, norm_prog) < 0)
		return -1;
	ctx->common_mask = mail_sort_get_common_mask(ctx->sort_program,
						     norm_prog, &count);
	if (count > 0) {
		memmove(ctx->sort_program, ctx->sort_program + count,
			sizeof(ctx->sort_program) -
			sizeof(ctx->sort_program[0]) * count);
	}

	memset(wanted_headers, 0, sizeof(wanted_headers));
	wanted_fields = init_sort_elements(ctx, wanted_headers);
	headers_ctx = mailbox_header_lookup_init(client->mailbox,
						 wanted_headers);

	/* initialize searching */
	ctx->t = mailbox_transaction_begin(client->mailbox, FALSE);
	ctx->search_ctx =
		mailbox_search_init(ctx->t, charset, args, norm_prog,
				    wanted_fields, headers_ctx);
	if (ctx->search_ctx == NULL) {
		mailbox_transaction_rollback(ctx->t);
		mailbox_header_lookup_deinit(headers_ctx);
		return -1;
	}

	ctx->box = client->mailbox;
	ctx->output = client->output;
	ctx->sort_buffer = buffer_create_dynamic(system_pool,
						 128 * ctx->sort_element_size,
						 (size_t)-1);

	ctx->str = t_str_new(STRBUF_SIZE);
	str_append(ctx->str, "* SORT");

        ctx->id_is_uid = client->cmd_uid;

	while ((mail = mailbox_search_next(ctx->search_ctx)) != NULL)
		mail_sort_input(ctx, mail);

	mail_sort_flush(ctx);
	ret = mailbox_search_deinit(ctx->search_ctx);

	if (mailbox_transaction_commit(ctx->t, 0) < 0)
		ret = -1;

	if (ctx->written || ret == 0) {
		str_append(ctx->str, "\r\n");
		o_stream_send(client->output, str_data(ctx->str),
			      str_len(ctx->str));
	}

	mailbox_header_lookup_deinit(headers_ctx);
        mail_sort_deinit(ctx);
	return ret;
}

static const char *string_table_get(struct sort_context *ctx, const char *str)
{
	char *value;

	if (str == NULL)
		return NULL;
	if (*str == '\0')
		return "";

	value = hash_lookup(ctx->string_table, str);
	if (value == NULL) {
		value = p_strdup(ctx->str_pool, str);
		hash_insert(ctx->string_table, value, value);
	}

	return value;
}

static const char *get_first_mailbox(struct mail *mail, const char *field)
{
	struct message_address *addr;
	const char *str;

	str = mail->get_header(mail, field);
	if (str == NULL)
		return NULL;

	addr = message_address_parse(pool_datastack_create(),
				     (const unsigned char *) str,
				     (size_t)-1, 1);
	return addr != NULL ? addr->mailbox : NULL;
}

static void mail_sort_check_flush(struct sort_context *ctx, struct mail *mail)
{
	const char *str;
	time_t t;
	uoff_t size;
	int changed = FALSE;

	if (ctx->common_mask & MAIL_SORT_ARRIVAL) {
		t = mail->get_received_date(mail);
		if (t != ctx->last_arrival) {
			ctx->last_arrival = t;
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_CC) {
		str = get_first_mailbox(mail, "cc");
		if (str != NULL)
			str = t_str_ucase(str);

		if (null_strcmp(str, ctx->last_cc) != 0) {
			i_free(ctx->last_cc);
			ctx->last_cc = i_strdup(str);
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_DATE) {
		t = mail->get_date(mail, NULL);
		if (t != ctx->last_date) {
			ctx->last_date = t;
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_FROM) {
		str = get_first_mailbox(mail, "from");
		if (str != NULL)
			str = t_str_ucase(str);

		if (null_strcmp(str, ctx->last_from) != 0) {
			i_free(ctx->last_from);
			ctx->last_from = i_strdup(str);
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_SIZE) {
		size = mail->get_virtual_size(mail);
		if (size != ctx->last_size) {
			ctx->last_size = size;
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_SUBJECT) {
		str = mail->get_header(mail, "subject");
		if (str != NULL) {
			str = imap_get_base_subject_cased(
				pool_datastack_create(), str, NULL);
		}

		if (null_strcmp(str, ctx->last_subject) != 0) {
			i_free(ctx->last_subject);
			ctx->last_subject = i_strdup(str);
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_TO) {
		str = get_first_mailbox(mail, "to");
		if (str != NULL)
			str = t_str_ucase(str);

		if (null_strcmp(str, ctx->last_to) != 0) {
			i_free(ctx->last_to);
			ctx->last_to = i_strdup(str);
			changed = TRUE;
		}
	}

	if (changed)
		mail_sort_flush(ctx);
}

static void mail_sort_input(struct sort_context *ctx, struct mail *mail)
{
	/* @UNSAFE */
	unsigned char *buf;
	unsigned int id;
	time_t t;
	uoff_t size;
	const char *str;
	size_t pos;

	t_push();
	if (ctx->common_mask != 0)
		mail_sort_check_flush(ctx, mail);

	buf = buffer_append_space_unsafe(ctx->sort_buffer,
					 ctx->sort_element_size);
	id = ctx->id_is_uid ? mail->uid : mail->seq;
	memcpy(buf, &id, sizeof(id)); pos = sizeof(id);

	if (ctx->cache_mask & MAIL_SORT_ARRIVAL) {
		if (ctx->common_mask & MAIL_SORT_ARRIVAL)
			t = ctx->last_arrival;
		else
			t = mail->get_received_date(mail);
		memcpy(buf + pos, &t, sizeof(t)); pos += sizeof(t);
	}

	if (ctx->cache_mask & MAIL_SORT_DATE) {
		if (ctx->common_mask & MAIL_SORT_DATE)
			t = ctx->last_date;
		else
			t = mail->get_date(mail, NULL);
		memcpy(buf + pos, &t, sizeof(t)); pos += sizeof(t);
	}

	if (ctx->cache_mask & MAIL_SORT_SIZE) {
		if (ctx->common_mask & MAIL_SORT_SIZE)
			size = ctx->last_size;
		else
			size = mail->get_virtual_size(mail);

		memcpy(buf + pos, &size, sizeof(size)); pos += sizeof(size);
	}

	if (ctx->cache_mask & MAIL_SORT_CC) {
		if (ctx->common_mask & MAIL_SORT_CC)
			str = ctx->last_cc;
		else {
			str = get_first_mailbox(mail, "cc");
			if (str != NULL)
				str = t_str_ucase(str);
		}
		str = string_table_get(ctx, str);

		memcpy(buf + pos, &str, sizeof(const char *));
		pos += sizeof(const char *);
	}

	if (ctx->cache_mask & MAIL_SORT_FROM) {
		if (ctx->common_mask & MAIL_SORT_FROM)
			str = ctx->last_from;
		else {
			str = get_first_mailbox(mail, "from");
			if (str != NULL)
				str = t_str_ucase(str);
		}
		str = string_table_get(ctx, str);

		memcpy(buf + pos, &str, sizeof(const char *));
		pos += sizeof(const char *);
	}

	if (ctx->cache_mask & MAIL_SORT_TO) {
		if (ctx->common_mask & MAIL_SORT_TO)
			str = ctx->last_to;
		else {
			str = get_first_mailbox(mail, "to");
			if (str != NULL)
				str = t_str_ucase(str);
		}
		str = string_table_get(ctx, str);

		memcpy(buf + pos, &str, sizeof(const char *));
		pos += sizeof(const char *);
	}

	if (ctx->cache_mask & MAIL_SORT_SUBJECT) {
		if (ctx->common_mask & MAIL_SORT_SUBJECT)
			str = ctx->last_subject;
		else {
			str = mail->get_header(mail, "subject");

			if (str != NULL) {
				str = imap_get_base_subject_cased(
					pool_datastack_create(), str, NULL);
			}
		}
		str = string_table_get(ctx, str);

		memcpy(buf + pos, &str, sizeof(const char *));
		pos += sizeof(const char *);
	}

	i_assert(pos == ctx->sort_element_size);

	t_pop();
}

static struct sort_context *qsort_context;

static struct mail *get_mail(struct sort_context *ctx, const unsigned char *buf)
{
	unsigned int id = *((unsigned int *) buf);
	uint32_t seq;

	if (!ctx->id_is_uid)
		seq = id;
	else {
		if (mailbox_get_uids(ctx->box, id, id, &seq, &seq) < 0)
			return NULL;
	}
	return mailbox_fetch(ctx->t, seq, 0);

}

static time_t get_time(enum mail_sort_type type, const unsigned char *buf,
		       struct sort_context *ctx)
{
	time_t t;

	if ((ctx->cache_mask & type) == 0) {
		struct mail *mail = get_mail(ctx, buf);

		if (mail == NULL)
			return 0;

		switch (type) {
		case MAIL_SORT_ARRIVAL:
			return mail->get_received_date(mail);
		case MAIL_SORT_DATE:
			t = mail->get_date(mail, NULL);
			if (t == (time_t)-1)
				t = 0;
			return t;
		default:
			i_unreached();
			return 0;
		}
	}

	/* use memcpy() to avoid any alignment problems */
	memcpy(&t, buf + sizeof(unsigned int), sizeof(t));
	return t;
}

static uoff_t get_uofft(enum mail_sort_type type, const unsigned char *buf,
			struct sort_context *ctx)
{
	uoff_t size;

	if ((ctx->cache_mask & type) == 0) {
		struct mail *mail = get_mail(ctx, buf);

		if (mail == NULL)
			return 0;

		i_assert(type == MAIL_SORT_SIZE);

		return mail->get_virtual_size(mail);
	}

	/* use memcpy() to avoid any alignment problems */
	memcpy(&size, buf + sizeof(unsigned int), sizeof(size));
	return size;
}

static const char *get_str(enum mail_sort_type type, const unsigned char *buf,
			   struct sort_context *ctx)
{
	const char *str;
	enum mail_sort_type type2;
	pool_t pool;
	int pos;

	if ((ctx->cache_mask & type) == 0) {
		struct mail *mail = get_mail(ctx, buf);

		if (mail == NULL)
			return NULL;

		switch (type) {
		case MAIL_SORT_SUBJECT:
			str = mail->get_header(mail, "subject");
			if (str == NULL)
				return NULL;

			pool = pool_datastack_create();
			return imap_get_base_subject_cased(pool, str, NULL);
		case MAIL_SORT_CC:
			str = get_first_mailbox(mail, "cc");
			break;
		case MAIL_SORT_FROM:
			str = get_first_mailbox(mail, "from");
			break;
		case MAIL_SORT_TO:
			str = get_first_mailbox(mail, "to");
			break;
		default:
			i_unreached();
		}

		if (str != NULL)
			str = t_str_ucase(str);
		return str;
	}

	/* figure out where it is. pretty ugly. */
	type2 = (ctx->cache_mask & ~type);

	if (type2 == 0)
		pos = 0;
	else if (IS_SORT_TIME(type2))
		pos = sizeof(time_t);
	else if (type2 == MAIL_SORT_SIZE)
		pos = sizeof(uoff_t);
	else {
		if (type == MAIL_SORT_SUBJECT)
			pos = sizeof(const char *);
		else if (type2 != MAIL_SORT_SUBJECT && type > type2)
			pos = sizeof(const char *);
		else
			pos = 0;
	}

	/* use memcpy() to avoid any alignment problems */
	memcpy(&str, buf + pos + sizeof(unsigned int), sizeof(const char *));
	return str;
}

static int mail_sort_qsort_func(const void *p1, const void *p2)
{
	enum mail_sort_type *sorting;
	int ret, reverse = FALSE;

	sorting = qsort_context->sort_program;

	t_push();

	ret = 0;
	for (; *sorting != MAIL_SORT_END && ret == 0; sorting++) {
		if (*sorting == MAIL_SORT_REVERSE) {
			reverse = !reverse;
			continue;
		}

		switch (*sorting) {
		case MAIL_SORT_ARRIVAL:
		case MAIL_SORT_DATE: {
			time_t r1, r2;

			r1 = get_time(*sorting, p1, qsort_context);
			r2 = get_time(*sorting, p2, qsort_context);
			ret = r1 < r2 ? -1 : r1 > r2 ? 1 : 0;
			break;
		}
		case MAIL_SORT_SIZE: {
			uoff_t r1, r2;

			r1 = get_uofft(*sorting, p1, qsort_context);
			r2 = get_uofft(*sorting, p2, qsort_context);
			ret = r1 < r2 ? -1 : r1 > r2 ? 1 : 0;
			break;
		}
		case MAIL_SORT_CC:
		case MAIL_SORT_FROM:
		case MAIL_SORT_TO:
		case MAIL_SORT_SUBJECT:
			ret = null_strcmp(get_str(*sorting, p1, qsort_context),
					  get_str(*sorting, p2, qsort_context));
			break;
		default:
			i_unreached();
		}

		if (reverse) {
			if (ret > 0)
				ret = -1;
			else if (ret < 0)
				ret = 1;
		}

		reverse = FALSE;
	}

	t_pop();

	return ret != 0 ? ret :
		(*((unsigned int *) p1) < *((unsigned int *) p2) ? -1 : 1);
}

static void mail_sort_flush(struct sort_context *ctx)
{
	unsigned char *arr;
	size_t i, count;

	qsort_context = ctx;

	arr = buffer_get_modifyable_data(ctx->sort_buffer, NULL);
	count = buffer_get_used_size(ctx->sort_buffer) / ctx->sort_element_size;
	if (count == 0)
		return;

	qsort(arr, count, ctx->sort_element_size, mail_sort_qsort_func);

	for (i = 0; i < count; i++, arr += ctx->sort_element_size) {
		if (str_len(ctx->str) >= STRBUF_SIZE-MAX_INT_STRLEN) {
			/* flush */
			o_stream_send(ctx->output,
				      str_data(ctx->str), str_len(ctx->str));
			str_truncate(ctx->str, 0);
			ctx->written = TRUE;
		}

		str_printfa(ctx->str, " %u", *((unsigned int *) arr));
	}

	buffer_set_used_size(ctx->sort_buffer, 0);

	if (ctx->string_table != NULL) {
		hash_clear(ctx->string_table, TRUE);
		p_clear(ctx->str_pool);
	}
}
