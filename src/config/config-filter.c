/* Copyright (C) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "config-filter.h"

struct config_filter_context {
	pool_t pool;
	struct config_filter_parser_list *const *parsers;
};

bool config_filter_match(const struct config_filter *mask,
			 const struct config_filter *filter)
{
	if (mask->service != NULL) {
		if (filter->service == NULL)
			return FALSE;
		if (strcasecmp(filter->service, mask->service) != 0)
			return FALSE;
	}
	/* FIXME: it's not comparing full masks */
	if (mask->remote_bits != 0) {
		if (filter->remote_bits == 0)
			return FALSE;
		if (!net_is_in_network(&filter->remote_net, &mask->remote_net,
				       mask->remote_bits))
			return FALSE;
	}
	if (mask->local_bits != 0) {
		if (filter->local_bits == 0)
			return FALSE;
		if (!net_is_in_network(&filter->local_net, &mask->local_net,
				       mask->local_bits))
			return FALSE;
	}
	return TRUE;
}

bool config_filters_equal(const struct config_filter *f1,
			  const struct config_filter *f2)
{
	if (null_strcmp(f1->service, f2->service) != 0)
		return FALSE;

	if (f1->remote_bits != f2->remote_bits)
		return FALSE;
	if (!net_ip_compare(&f1->remote_net, &f2->remote_net))
		return FALSE;

	if (f1->local_bits != f2->local_bits)
		return FALSE;
	if (!net_ip_compare(&f1->local_net, &f2->local_net))
		return FALSE;

	return TRUE;
}

struct config_filter_context *config_filter_init(pool_t pool)
{
	struct config_filter_context *ctx;

	ctx = p_new(pool, struct config_filter_context, 1);
	ctx->pool = pool;
	return ctx;
}

void config_filter_deinit(struct config_filter_context **_ctx)
{
	struct config_filter_context *ctx = *_ctx;

	*_ctx = NULL;

	pool_unref(&ctx->pool);
}

void config_filter_add_all(struct config_filter_context *ctx,
			   struct config_filter_parser_list *const *parsers)
{
	ctx->parsers = parsers;
}

static int filter_cmp(const struct config_filter *f1,
		      const struct config_filter *f2)
{
	int ret;

	ret = f2->remote_bits - f1->remote_bits;
	if (ret != 0)
		return ret;

	ret = f2->local_bits - f1->local_bits;
	if (ret != 0)
		return ret;

	if (f1->service != NULL)
		return -1;
	else
		return 1;
}

const struct config_setting_parser_list *
config_filter_match_parsers(struct config_filter_context *ctx,
			    const struct config_filter *filter)
{
	struct config_filter_parser_list *best = NULL;
	unsigned int i;

	/* find the filter that best matches what we have.
	   FIXME: this can't really work. we'd want to merge changes from
	   different matches.. requires something larger after all. */
	for (i = 0; ctx->parsers[i] != NULL; i++) {
		if (!config_filter_match(&ctx->parsers[i]->filter, filter))
			continue;

		if (best == NULL ||
		    filter_cmp(&best->filter, &ctx->parsers[i]->filter) > 0)
			best = ctx->parsers[i];
	}
	return best == NULL ? NULL : best->parser_list;
}
