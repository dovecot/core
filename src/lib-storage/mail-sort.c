/* Copyright (C) 2002 Timo Sirainen */

/* Implementation of draft-ietf-imapext-sort-10 sorting algorithm */

#include "lib.h"
#include "buffer.h"
#include "ostream.h"
#include "imap-base-subject.h"
#include "mail-sort.h"

#include <stdlib.h>

struct _MailSortContext {
	MailSortType output[MAX_SORT_PROGRAM_SIZE];
	MailSortType common_mask;

	MailSortFuncs funcs;
	void *func_context;

	Buffer *sort_buffer;
	Pool temp_pool;

	time_t last_arrival, last_date;
	uoff_t last_size;
	char *last_cc, *last_from, *last_subject, *last_to;
};

static void mail_sort_flush(MailSortContext *ctx);

static MailSortType
mail_sort_normalize(const MailSortType *input, Buffer *output)
{
        MailSortType type, mask = 0;
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

static MailSortType
mail_sort_get_common_mask(const MailSortType *input,
			  MailSortType **output)
{
	MailSortType mask = 0;

	while (*input == **output && *input != MAIL_SORT_END) {
		if (*input != MAIL_SORT_REVERSE)
			mask |= *input;
		input++; (*output)++;
	}

	return mask;
}

MailSortContext *mail_sort_init(const MailSortType *input, MailSortType *output,
				MailSortFuncs funcs, void *context)
{
	MailSortContext *ctx;
	MailSortType norm_input[MAX_SORT_PROGRAM_SIZE];
	MailSortType norm_output[MAX_SORT_PROGRAM_SIZE];
	Buffer *buf;
	int i;

	ctx = i_new(MailSortContext, 1);

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

	ctx->sort_buffer = buffer_create_dynamic(system_pool,
						 128 * sizeof(unsigned int),
						 (size_t)-1);

	ctx->temp_pool = pool_alloconly_create("Sort", 8192);
	ctx->funcs = funcs;
	ctx->func_context = context;
	return ctx;
}

void mail_sort_deinit(MailSortContext *ctx)
{
	mail_sort_flush(ctx);
	buffer_free(ctx->sort_buffer);
	pool_unref(ctx->temp_pool);

	i_free(ctx->last_cc);
	i_free(ctx->last_from);
	i_free(ctx->last_subject);
	i_free(ctx->last_to);

	i_free(ctx);
}

static int addr_strcmp(const char *s1, const char *s2)
{
	if (s1 == NULL)
		return s2 == NULL ? 0 : -1;
	if (s2 == NULL)
		return 1;

	/* FIXME: maybe create ascii_strcasecmp()? strcasecmp() may compare
	   non-ASCII too if locale is set. We don't do that now though. */
	return strcasecmp(s1, s2);
}

static int subject_cmp(Pool pool, const char *s1, const char *s2)
{
	int ret;

	if (s1 == NULL)
		return s2 == NULL ? 0 : -1;
	if (s2 == NULL)
		return 1;

	p_clear(pool);
	ret = strcmp(imap_get_base_subject_cased(pool, s1),
		     imap_get_base_subject_cased(pool, s2));
	return ret;
}

static void mail_sort_check_flush(MailSortContext *ctx, unsigned int id)
{
	const char *str;
	time_t t;
	uoff_t size;
	int changed = FALSE;

	if (ctx->common_mask & MAIL_SORT_ARRIVAL) {
		t = ctx->funcs.input_time(MAIL_SORT_ARRIVAL, id,
					  ctx->func_context);
		if (t != ctx->last_arrival) {
			ctx->last_arrival = t;
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_CC) {
		str = ctx->funcs.input_str(MAIL_SORT_CC, id,
					   ctx->func_context);
		if (addr_strcmp(str, ctx->last_cc) != 0) {
			i_free(ctx->last_cc);
			ctx->last_cc = i_strdup(str);
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_DATE) {
		t = ctx->funcs.input_time(MAIL_SORT_DATE, id,
					  ctx->func_context);
		if (t != ctx->last_date) {
			ctx->last_date = t;
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_FROM) {
		str = ctx->funcs.input_str(MAIL_SORT_FROM, id,
					   ctx->func_context);
		if (addr_strcmp(str, ctx->last_from) != 0) {
			i_free(ctx->last_from);
			ctx->last_from = i_strdup(str);
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_SIZE) {
		size = ctx->funcs.input_time(MAIL_SORT_SIZE, id,
					     ctx->func_context);
		if (size != ctx->last_size) {
			ctx->last_size = size;
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_SUBJECT) {
		str = ctx->funcs.input_str(MAIL_SORT_SUBJECT, id,
					   ctx->func_context);
		if (subject_cmp(ctx->temp_pool, str, ctx->last_subject) != 0) {
			i_free(ctx->last_subject);
			ctx->last_subject = i_strdup(str);
			changed = TRUE;
		}
	}

	if (ctx->common_mask & MAIL_SORT_TO) {
		str = ctx->funcs.input_str(MAIL_SORT_TO, id,
					   ctx->func_context);
		if (addr_strcmp(str, ctx->last_to) != 0) {
			i_free(ctx->last_to);
			ctx->last_to = i_strdup(str);
			changed = TRUE;
		}
	}

	if (changed)
		mail_sort_flush(ctx);
}

void mail_sort_input(MailSortContext *ctx, unsigned int id)
{
	if (ctx->common_mask != 0)
		mail_sort_check_flush(ctx, id);

	buffer_append(ctx->sort_buffer, &id, sizeof(id));
}

static MailSortContext *mail_sort_qsort_context;

static int mail_sort_qsort_func(const void *p1, const void *p2)
{
	const unsigned int *i1 = p1;
	const unsigned int *i2 = p2;
	MailSortType *output = mail_sort_qsort_context->output;
        MailSortFuncs *funcs = &mail_sort_qsort_context->funcs;
	void *ctx = mail_sort_qsort_context->func_context;
	int ret, reverse = FALSE;

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

			r1 = funcs->input_time(*output, *i1, ctx);
			r2 = funcs->input_time(*output, *i2, ctx);
			ret = r1 < r2 ? -1 : r1 > r2 ? 1 : 0;
			break;
		}
		case MAIL_SORT_SIZE: {
			uoff_t r1, r2;

			r1 = funcs->input_uofft(*output, *i1, ctx);
			r2 = funcs->input_uofft(*output, *i2, ctx);
			ret = r1 < r2 ? -1 : r1 > r2 ? 1 : 0;
			break;
		}
		case MAIL_SORT_CC:
		case MAIL_SORT_FROM:
		case MAIL_SORT_TO: {
			const char *a1, *a2;

			a1 = funcs->input_mailbox(*output, *i1, ctx);
			a2 = funcs->input_mailbox(*output, *i2, ctx);
			ret = addr_strcmp(a1, a2);
			break;
		}
		case MAIL_SORT_SUBJECT:
			ret = subject_cmp(mail_sort_qsort_context->temp_pool,
					  funcs->input_str(*output, *i1, ctx),
					  funcs->input_str(*output, *i2, ctx));
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

	funcs->input_reset(ctx);

	t_pop();

	return ret != 0 ? ret : (*i1 < *i2 ? -1 : 1);
}

static void mail_sort_flush(MailSortContext *ctx)
{
	unsigned int *arr;
	size_t count;

	mail_sort_qsort_context = ctx;

	arr = buffer_get_modifyable_data(ctx->sort_buffer, NULL);
	count = buffer_get_used_size(ctx->sort_buffer) / sizeof(unsigned int);
	qsort(arr, count, sizeof(unsigned int), mail_sort_qsort_func);

	ctx->funcs.output(arr, count, ctx->func_context);
	buffer_set_used_size(ctx->sort_buffer, 0);
}
