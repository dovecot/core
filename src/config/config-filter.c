/* Copyright (c) 2005-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "settings-parser.h"
#include "config-parser.h"
#include "config-filter.h"

struct config_filter_context {
	pool_t pool;
	struct config_filter_parser *const *parsers;
};

bool config_filter_match(const struct config_filter *mask,
			 const struct config_filter *filter)
{
	if (mask->service != NULL) {
		if (filter->service == NULL)
			return FALSE;
		if (mask->service[0] == '!') {
			/* not service */
			if (strcmp(filter->service, mask->service + 1) == 0)
				return FALSE;
		} else {
			if (strcmp(filter->service, mask->service) != 0)
				return FALSE;
		}
	}
	if (mask->local_host != NULL) {
		if (filter->local_host == NULL)
			return FALSE;
		if (strcmp(filter->local_host, mask->local_host) != 0)
			return FALSE;
	}
	if (mask->remote_host != NULL) {
		if (filter->remote_host == NULL)
			return FALSE;
		if (strcmp(filter->remote_host, mask->remote_host) != 0)
			return FALSE;
	}
	/* FIXME: it's not comparing full masks */
	if (mask->remote_bits != 0 && mask->remote_host == NULL) {
		if (filter->remote_bits == 0)
			return FALSE;
		if (!net_is_in_network(&filter->remote_net, &mask->remote_net,
				       mask->remote_bits))
			return FALSE;
	}
	if (mask->local_bits != 0 && mask->local_host == NULL) {
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

	if (null_strcmp(f1->remote_host, f2->remote_host) != 0)
		return FALSE;
	if (null_strcmp(f1->local_host, f2->local_host) != 0)
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
	unsigned int i;

	*_ctx = NULL;

	for (i = 0; ctx->parsers[i] != NULL; i++)
		config_filter_parsers_free(ctx->parsers[i]->parsers);
	pool_unref(&ctx->pool);
}

void config_filter_add_all(struct config_filter_context *ctx,
			   struct config_filter_parser *const *parsers)
{
	ctx->parsers = parsers;
}

static int
config_filter_parser_cmp(struct config_filter_parser *const *p1,
			 struct config_filter_parser *const *p2)
{
	const struct config_filter *f1 = &(*p1)->filter, *f2 = &(*p2)->filter;

	/* remote and local are first, although it doesn't really
	   matter which one comes first */
	if (f1->local_bits > f2->local_bits)
		return -1;
	if (f1->local_bits < f2->local_bits)
		return 1;

	if (f1->remote_bits > f2->remote_bits)
		return -1;
	if (f1->remote_bits < f2->remote_bits)
		return 1;

	if (f1->service != NULL && f2->service == NULL)
		return -1;
	if (f1->service == NULL && f2->service != NULL)
		return 1;
	return 0;
}

static struct config_filter_parser *const *
config_filter_find_all(struct config_filter_context *ctx,
		       const struct config_filter *filter)
{
	ARRAY_TYPE(config_filter_parsers) matches;
	unsigned int i;

	t_array_init(&matches, 8);
	for (i = 0; ctx->parsers[i] != NULL; i++) {
		if (config_filter_match(&ctx->parsers[i]->filter, filter))
			array_append(&matches, &ctx->parsers[i], 1);
	}
	array_sort(&matches, config_filter_parser_cmp);
	(void)array_append_space(&matches);
	return array_idx(&matches, 0);
}

static bool
config_filter_is_superset(const struct config_filter *sup,
			  const struct config_filter *filter)
{
	/* assume that both of the filters match the same subset, so we don't
	   need to compare IPs and service name. */
	if (sup->local_bits > filter->local_bits)
		return FALSE;
	if (sup->remote_bits > filter->remote_bits)
		return FALSE;
	if (sup->service != NULL && filter->service == NULL)
		return FALSE;
	return TRUE;
}

static int
config_module_parser_apply_changes(struct config_module_parser *dest,
				   const struct config_filter_parser *src,
				   pool_t pool, const char **error_r)
{
	unsigned int i;

	for (i = 0; dest[i].root != NULL; i++) {
		if (settings_parser_apply_changes(dest[i].parser,
						  src->parsers[i].parser, pool,
						  error_r) < 0) {
			*error_r = t_strdup_printf("Conflict in setting %s "
				"found from filter at %s", *error_r,
				src->file_and_line);
			return -1;
		}
	}
	return 0;
}

int config_filter_parsers_get(struct config_filter_context *ctx, pool_t pool,
			      const struct config_filter *filter,
			      struct config_module_parser **parsers_r,
			      const char **error_r)
{
	struct config_filter_parser *const *src;
	struct config_module_parser *dest;
	const char *error, **error_p;
	unsigned int i, count;

	src = config_filter_find_all(ctx, filter);

	/* all of them should have the same number of parsers.
	   duplicate our initial parsers from the first match */
	for (count = 0; src[0]->parsers[count].root != NULL; count++) ;
	dest = p_new(pool, struct config_module_parser, count + 1);
	for (i = 0; i < count; i++) {
		dest[i] = src[0]->parsers[i];
		dest[i].parser =
			settings_parser_dup(src[0]->parsers[i].parser, pool);
	}

	/* apply the changes from rest of the matches */
	for (i = 1; src[i] != NULL; i++) {
		if (config_filter_is_superset(&src[i]->filter,
					      &src[i-1]->filter))
			error_p = NULL;
		else
			error_p = &error;

		if (config_module_parser_apply_changes(dest, src[i], pool,
						       error_p) < 0) {
			config_filter_parsers_free(dest);
			*error_r = error;
			return -1;
		}
	}
	*parsers_r = dest;
	return 0;
}

void config_filter_parsers_free(struct config_module_parser *parsers)
{
	unsigned int i;

	for (i = 0; parsers[i].root != NULL; i++)
		settings_parser_deinit(&parsers[i].parser);
}
