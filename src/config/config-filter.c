/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "settings-parser.h"
#include "master-service-settings.h"
#include "config-parser.h"
#include "config-filter.h"
#include "dns-util.h"

struct config_filter_context {
	pool_t pool;
	struct config_filter_parser *const *parsers;
	ARRAY_TYPE(const_string) errors;
};

static bool config_filter_match_service(const struct config_filter *mask,
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
	return TRUE;
}

static bool
config_filter_match_local_name(const struct config_filter *mask,
			       const char *filter_local_name)
{
	/* Handle multiple names separated by spaces in local_name
	   * Ex: local_name "mail.domain.tld domain.tld mx.domain.tld" { ... } */
	const char *ptr, *local_name = mask->local_name;
	while((ptr = strchr(local_name, ' ')) != NULL) {
		if (dns_match_wildcard(filter_local_name,
		    t_strdup_until(local_name, ptr)) == 0)
			return TRUE;
		local_name = ptr+1;
	}
	return dns_match_wildcard(filter_local_name, local_name) == 0;
}

static bool config_filter_match_rest(const struct config_filter *mask,
				     const struct config_filter *filter)
{
	bool matched;

	if (mask->local_name != NULL) {
		if (filter->local_name == NULL)
			return FALSE;
		T_BEGIN {
			matched = config_filter_match_local_name(mask, filter->local_name);
		} T_END;
		if (!matched)
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

bool config_filter_match(const struct config_filter *mask,
			 const struct config_filter *filter)
{
	if (!config_filter_match_service(mask, filter))
		return FALSE;

	return config_filter_match_rest(mask, filter);
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

	if (null_strcasecmp(f1->local_name, f2->local_name) != 0)
		return FALSE;

	return TRUE;
}

struct config_filter_context *config_filter_init(pool_t pool)
{
	struct config_filter_context *ctx;

	ctx = p_new(pool, struct config_filter_context, 1);
	ctx->pool = pool;
	pool_ref(ctx->pool);
	p_array_init(&ctx->errors, pool, 1);
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

	/* remote and locals are first, although it doesn't really
	   matter which one comes first */
	if (f1->local_name != NULL && f2->local_name == NULL)
		return 1;
	if (f1->local_name == NULL && f2->local_name != NULL)
		return -1;

	if (f1->local_bits > f2->local_bits)
		return 1;
	if (f1->local_bits < f2->local_bits)
		return -1;

	if (f1->remote_bits > f2->remote_bits)
		return 1;
	if (f1->remote_bits < f2->remote_bits)
		return -1;

	if (f1->service != NULL && f2->service == NULL)
		return 1;
	if (f1->service == NULL && f2->service != NULL)
		return -1;
	return 0;
}

struct config_filter_parser *const *
config_filter_find_subset(struct config_filter_context *ctx)
{
	ARRAY_TYPE(config_filter_parsers) matches;
	unsigned int i;

	t_array_init(&matches, 8);
	for (i = 0; ctx->parsers[i] != NULL; i++)
		array_push_back(&matches, &ctx->parsers[i]);

	array_sort(&matches, config_filter_parser_cmp);
	array_append_zero(&matches);
	return array_front(&matches);
}

struct config_module_parser *
config_filter_parsers_dup(struct config_filter_context *ctx, pool_t pool)
{
	const struct config_filter_parser *global_filter;
	struct config_module_parser *dest;
	unsigned int i, count;

	global_filter = ctx->parsers[0];
	for (count = 0; global_filter->parsers[count].root != NULL; count++) ;
	dest = p_new(pool, struct config_module_parser, count + 1);
	for (i = 0; i < count; i++) {
		dest[i] = global_filter->parsers[i];
		dest[i].parser =
			settings_parser_dup(global_filter->parsers[i].parser, pool);
	}
	return dest;
}

void config_filter_add_error(struct config_filter_context *ctx,
			     const char *error)
{
	error = p_strdup(ctx->pool, error);
	array_push_back(&ctx->errors, &error);
}

const ARRAY_TYPE(const_string) *
config_filter_get_errors(struct config_filter_context *ctx)
{
	return &ctx->errors;
}

void config_filter_parsers_free(struct config_module_parser *parsers)
{
	unsigned int i;

	for (i = 0; parsers[i].root != NULL; i++)
		settings_parser_unref(&parsers[i].parser);
}
