/* Copyright (C) 2002 Timo Sirainen */

/* Implementation of draft-ietf-imapext-sort-10 sorting algorithm.
   Pretty messy code actually, adding any sort types requires care.
   This is pretty fast however and takes only as much memory as needed to be
   reasonably fast. */

#include "lib.h"
#include "buffer.h"
#include "hash.h"
#include "ostream.h"
#include "imap-base-subject.h"
#include "mail-sort.h"

#include <stdlib.h>

#define IS_SORT_STRING(type) \
	((type) == MAIL_SORT_CC || (type) == MAIL_SORT_FROM || \
	 (type) == MAIL_SORT_SUBJECT || (type) == MAIL_SORT_TO)

#define IS_SORT_TIME(type) \
	((type) == MAIL_SORT_ARRIVAL || (type) == MAIL_SORT_DATE)

struct mail_sort_context {
	enum mail_sort_type output[MAX_SORT_PROGRAM_SIZE];
	enum mail_sort_type common_mask, cache_mask;

	struct ostream *outstream;
	const struct mail_sort_callbacks *callbacks;
	void *func_context;

	buffer_t *sort_buffer;
	size_t sort_element_size;

	pool_t temp_pool, str_pool;
	struct hash_table *string_table;

	time_t last_arrival, last_date;
	uoff_t last_size;
	char *last_cc, *last_from, *last_subject, *last_to;
};

static void mail_sort_flush(struct mail_sort_context *ctx);

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
mail_sort_get_common_mask(const enum mail_sort_type *input,
			  enum mail_sort_type **output)
{
	enum mail_sort_type mask = 0;

	while (*input == **output && *input != MAIL_SORT_END) {
		if (*input != MAIL_SORT_REVERSE)
			mask |= *input;
		input++; (*output)++;
	}

	return mask;
}

struct mail_sort_context *
mail_sort_init(const enum mail_sort_type *input, enum mail_sort_type *output,
	       struct ostream *outstream,
	       const struct mail_sort_callbacks *callbacks, void *context)
{
	/* @UNSAFE */
	struct mail_sort_context *ctx;
	enum mail_sort_type norm_input[MAX_SORT_PROGRAM_SIZE];
	enum mail_sort_type norm_output[MAX_SORT_PROGRAM_SIZE];
	buffer_t *buf;
	int i;

	ctx = i_new(struct mail_sort_context, 1);
	ctx->temp_pool = pool_alloconly_create("sort temp", 8192);
	ctx->outstream = outstream;

	t_push();
	buf = buffer_create_data(data_stack_pool,
				 norm_input, sizeof(norm_input));
	mail_sort_normalize(input, buf);

	buf = buffer_create_data(data_stack_pool,
				 norm_output, sizeof(norm_output));
	mail_sort_normalize(output, buf);
	t_pop();

	/* remove the common part from output, we already know input is sorted
	   that much so we don't have to worry about it. */
	output = norm_output;
        ctx->common_mask = mail_sort_get_common_mask(norm_input, &output);

	for (i = 0; output[i] != MAIL_SORT_END; i++)
		ctx->output[i] = output[i];
	ctx->output[i] = MAIL_SORT_END;

	/* figure out what data we'd like to cache */
	ctx->sort_element_size = sizeof(unsigned int);
	ctx->cache_mask = 0;

	for (i = 0; output[i] != MAIL_SORT_END; i++) {
		if (IS_SORT_STRING(output[i])) {
			ctx->sort_element_size += sizeof(const char *);

			/* cache the second rule as well, if available */
			if (ctx->cache_mask != 0) {
				ctx->cache_mask |= output[i];
				break;
			}
			ctx->cache_mask |= output[i];
		} else if (IS_SORT_TIME(output[i])) {
			ctx->sort_element_size += sizeof(time_t);
			ctx->cache_mask |= output[i];
			break;
		} else if (output[i] == MAIL_SORT_SIZE) {
			ctx->sort_element_size += sizeof(uoff_t);
			ctx->cache_mask |= output[i];
			break;
		}
	}

	if ((ctx->cache_mask & MAIL_SORT_CC) ||
	    (ctx->cache_mask & MAIL_SORT_FROM) ||
	    (ctx->cache_mask & MAIL_SORT_TO) ||
	    (ctx->cache_mask & MAIL_SORT_SUBJECT)) {
		ctx->str_pool = pool_alloconly_create("sort str", 8192);
		ctx->string_table = hash_create(default_pool, ctx->str_pool,
						0, str_hash,
						(hash_cmp_callback_t)strcmp);
	}

	ctx->sort_buffer = buffer_create_dynamic(system_pool,
						 128 * ctx->sort_element_size,
						 (size_t)-1);

	ctx->callbacks = callbacks;
	ctx->func_context = context;
	return ctx;
}

void mail_sort_deinit(struct mail_sort_context *ctx)
{
	mail_sort_flush(ctx);

	if (ctx->string_table != NULL)
		hash_destroy(ctx->string_table);
	if (ctx->str_pool != NULL)
		pool_unref(ctx->str_pool);
	buffer_free(ctx->sort_buffer);
	pool_unref(ctx->temp_pool);

	i_free(ctx->last_cc);
	i_free(ctx->last_from);
	i_free(ctx->last_subject);
	i_free(ctx->last_to);

	i_free(ctx);
}

static const char *string_table_get(struct mail_sort_context *ctx,
				    const char *str)
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

static void mail_sort_check_flush(struct mail_sort_context *ctx,
				  unsigned int id)
{
	const char *str;
	time_t t;
	uoff_t size;
	int changed = FALSE;

	if (ctx->common_mask & MAIL_SORT_ARRIVAL) {
		t = ctx->callbacks->input_time(MAIL_SORT_ARRIVAL, id,
					       ctx->func_context);
		if (t != ctx->last_arrival) {
			ctx->last_arrival = t;
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_CC) {
		str = ctx->callbacks->input_mailbox(MAIL_SORT_CC, id,
						    ctx->func_context);
		str = str_ucase(t_strdup_noconst(str));
		if (strcmp(str, ctx->last_cc) != 0) {
			i_free(ctx->last_cc);
			ctx->last_cc = i_strdup(str);
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_DATE) {
		t = ctx->callbacks->input_time(MAIL_SORT_DATE, id,
					       ctx->func_context);
		if (t != ctx->last_date) {
			ctx->last_date = t;
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_FROM) {
		str = ctx->callbacks->input_mailbox(MAIL_SORT_FROM, id,
						    ctx->func_context);
		str = str_ucase(t_strdup_noconst(str));
		if (strcmp(str, ctx->last_from) != 0) {
			i_free(ctx->last_from);
			ctx->last_from = i_strdup(str);
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_SIZE) {
		size = ctx->callbacks->input_uofft(MAIL_SORT_SIZE, id,
						   ctx->func_context);
		if (size != ctx->last_size) {
			ctx->last_size = size;
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_SUBJECT) {
		str = ctx->callbacks->input_str(MAIL_SORT_SUBJECT, id,
						ctx->func_context);
		p_clear(ctx->temp_pool);
		str = imap_get_base_subject_cased(ctx->temp_pool, str, NULL);

		if (strcmp(str, ctx->last_subject) != 0) {
			i_free(ctx->last_subject);
			ctx->last_subject = i_strdup(str);
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_TO) {
		str = ctx->callbacks->input_mailbox(MAIL_SORT_TO, id,
						    ctx->func_context);
		str = str_ucase(t_strdup_noconst(str));
		if (strcmp(str, ctx->last_to) != 0) {
			i_free(ctx->last_to);
			ctx->last_to = i_strdup(str);
			changed = TRUE;
		}
	}

	if (changed)
		mail_sort_flush(ctx);
}

void mail_sort_input(struct mail_sort_context *ctx, unsigned int id)
{
	/* @UNSAFE */
	unsigned char *buf;
	time_t t;
	uoff_t size;
	const char *str;
	size_t pos;

	t_push();
	if (ctx->common_mask != 0)
		mail_sort_check_flush(ctx, id);

	buf = buffer_append_space(ctx->sort_buffer, ctx->sort_element_size);
	memcpy(buf, &id, sizeof(id)); pos = sizeof(id);

	if (ctx->cache_mask & MAIL_SORT_ARRIVAL) {
		if (ctx->common_mask & MAIL_SORT_ARRIVAL)
			t = ctx->last_arrival;
		else {
			t = ctx->callbacks->input_time(MAIL_SORT_ARRIVAL, id,
						       ctx->func_context);
		}
		memcpy(buf + pos, &t, sizeof(t)); pos += sizeof(t);
	}

	if (ctx->cache_mask & MAIL_SORT_DATE) {
		if (ctx->common_mask & MAIL_SORT_DATE)
			t = ctx->last_date;
		else {
			t = ctx->callbacks->input_time(MAIL_SORT_DATE, id,
						       ctx->func_context);
		}
		memcpy(buf + pos, &t, sizeof(t)); pos += sizeof(t);
	}

	if (ctx->cache_mask & MAIL_SORT_SIZE) {
		if (ctx->common_mask & MAIL_SORT_SIZE)
			size = ctx->last_size;
		else {
			size = ctx->callbacks->input_uofft(MAIL_SORT_SIZE, id,
							   ctx->func_context);
		}

		memcpy(buf + pos, &size, sizeof(size)); pos += sizeof(size);
	}

	if (ctx->cache_mask & MAIL_SORT_CC) {
		if (ctx->common_mask & MAIL_SORT_CC)
			str = ctx->last_cc;
		else {
			str = ctx->callbacks->input_mailbox(MAIL_SORT_CC, id,
							    ctx->func_context);
			if (str != NULL)
				str = str_ucase(t_strdup_noconst(str));
		}
		str = string_table_get(ctx, str);

		memcpy(buf + pos, &str, sizeof(const char *));
		pos += sizeof(const char *);
	}

	if (ctx->cache_mask & MAIL_SORT_FROM) {
		if (ctx->common_mask & MAIL_SORT_FROM)
			str = ctx->last_from;
		else {
			str = ctx->callbacks->input_mailbox(MAIL_SORT_FROM, id,
							    ctx->func_context);
			if (str != NULL)
				str = str_ucase(t_strdup_noconst(str));
		}
		str = string_table_get(ctx, str);

		memcpy(buf + pos, &str, sizeof(const char *));
		pos += sizeof(const char *);
	}

	if (ctx->cache_mask & MAIL_SORT_TO) {
		if (ctx->common_mask & MAIL_SORT_TO)
			str = ctx->last_to;
		else {
			str = ctx->callbacks->input_mailbox(MAIL_SORT_TO, id,
							    ctx->func_context);
			if (str != NULL)
				str = str_ucase(t_strdup_noconst(str));
		}
		str = string_table_get(ctx, str);

		memcpy(buf + pos, &str, sizeof(const char *));
		pos += sizeof(const char *);
	}

	if (ctx->cache_mask & MAIL_SORT_SUBJECT) {
		if (ctx->common_mask & MAIL_SORT_SUBJECT)
			str = ctx->last_subject;
		else {
			str = ctx->callbacks->input_str(MAIL_SORT_SUBJECT, id,
							ctx->func_context);
			p_clear(ctx->temp_pool);
			str = imap_get_base_subject_cased(ctx->temp_pool,
							  str, NULL);
		}
		str = string_table_get(ctx, str);

		memcpy(buf + pos, &str, sizeof(const char *));
		pos += sizeof(const char *);
	}

	i_assert(pos == ctx->sort_element_size);

	t_pop();
}

static struct mail_sort_context *qsort_context;

static time_t get_time(enum mail_sort_type type, const unsigned char *buf,
		       struct mail_sort_context *ctx)
{
	time_t t;

	if ((ctx->cache_mask & type) == 0) {
		return ctx->callbacks->
			input_time(type, *((unsigned int *) buf),
				   ctx->func_context);
	}

	/* use memcpy() to avoid any alignment problems */
	memcpy(&t, buf + sizeof(unsigned int), sizeof(t));
	return t;
}

static time_t get_uofft(enum mail_sort_type type, const unsigned char *buf,
			struct mail_sort_context *ctx)
{
	uoff_t size;

	if ((ctx->cache_mask & type) == 0) {
		return ctx->callbacks->
			input_uofft(type, *((unsigned int *) buf),
				    ctx->func_context);
	}

	/* use memcpy() to avoid any alignment problems */
	memcpy(&size, buf + sizeof(unsigned int), sizeof(size));
	return size;
}
static const char *get_str(enum mail_sort_type type, const unsigned char *buf,
			   struct mail_sort_context *ctx)
{
	const char *str;
	enum mail_sort_type type2;
	int pos;

	if ((ctx->cache_mask & type) == 0) {
		unsigned int id = *((unsigned int *) buf);

		if (type == MAIL_SORT_SUBJECT) {
			str = ctx->callbacks->input_str(MAIL_SORT_SUBJECT, id,
							ctx->func_context);
			p_clear(ctx->temp_pool);
			str = imap_get_base_subject_cased(ctx->temp_pool,
							  str, NULL);
		} else {
			str = ctx->callbacks->input_mailbox(type, id,
							    ctx->func_context);
			if (str != NULL)
				str = str_ucase(t_strdup_noconst(str));

		}
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
	enum mail_sort_type *output;
	int ret, reverse = FALSE;

	output = qsort_context->output;

	t_push();

	ret = 0;
	for (; *output != MAIL_SORT_END && ret == 0; output++) {
		if (*output == MAIL_SORT_REVERSE) {
			reverse = !reverse;
			continue;
		}

		switch (*output) {
		case MAIL_SORT_ARRIVAL:
		case MAIL_SORT_DATE: {
			time_t r1, r2;

			r1 = get_time(*output, p1, qsort_context);
			r2 = get_time(*output, p2, qsort_context);
			ret = r1 < r2 ? -1 : r1 > r2 ? 1 : 0;
			break;
		}
		case MAIL_SORT_SIZE: {
			uoff_t r1, r2;

			r1 = get_uofft(*output, p1, qsort_context);
			r2 = get_uofft(*output, p2, qsort_context);
			ret = r1 < r2 ? -1 : r1 > r2 ? 1 : 0;
			break;
		}
		case MAIL_SORT_CC:
		case MAIL_SORT_FROM:
		case MAIL_SORT_TO:
		case MAIL_SORT_SUBJECT: {
			const char *s1, *s2;

			s1 = get_str(*output, p1, qsort_context);
			s2 = get_str(*output, p2, qsort_context);
			if (s1 == NULL)
				ret = s2 == NULL ? 0 : -1;
			else if (s2 == NULL)
				ret = 1;
			else
				ret = strcmp(s1, s2);
			break;
		}
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

	qsort_context->callbacks->input_reset(qsort_context->func_context);

	t_pop();

	return ret != 0 ? ret :
		(*((unsigned int *) p1) < *((unsigned int *) p2) ? -1 : 1);
}

static void mail_sort_flush(struct mail_sort_context *ctx)
{
	unsigned char *arr;
	size_t i, count;

	qsort_context = ctx;

	arr = buffer_get_modifyable_data(ctx->sort_buffer, NULL);
	count = buffer_get_used_size(ctx->sort_buffer) / ctx->sort_element_size;
	qsort(arr, count, ctx->sort_element_size, mail_sort_qsort_func);

	for (i = 0; i < count; i++, arr += ctx->sort_element_size) {
		unsigned int id = *((unsigned int *) arr);

		t_push();
		o_stream_send(ctx->outstream, " ", 1);
		o_stream_send_str(ctx->outstream, dec2str(id));
		t_pop();
	}

	buffer_set_used_size(ctx->sort_buffer, 0);

	if (ctx->string_table != NULL) {
		hash_clear(ctx->string_table, TRUE);
		p_clear(ctx->str_pool);
	}
}
