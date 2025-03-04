/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "crc32.h"
#include "settings-parser.h"
#include "master-service-settings.h"
#include "config-parser.h"
#include "config-filter.h"
#include "dns-util.h"

static const struct config_filter empty_filter;
static const struct config_filter empty_defaults_filter = {
	.default_settings = TRUE
};

static int config_filter_match_service(const struct config_filter *mask,
				       const struct config_filter *filter)
{
	if (mask->protocol != NULL) {
		if (filter->protocol == NULL)
			return -1;
		if (mask->protocol[0] == '!') {
			/* not protocol */
			if (strcmp(filter->protocol, mask->protocol + 1) == 0)
				return 0;
		} else {
			if (strcmp(filter->protocol, mask->protocol) != 0)
				return 0;
		}
	}
	return 1;
}

static int config_filter_match_rest(const struct config_filter *mask,
				    const struct config_filter *filter)
{
	bool matched;
	int ret = 1;

	if (mask->local_name != NULL) {
		if (filter->local_name == NULL)
			ret = -1;
		else {
			T_BEGIN {
				matched = dns_match_wildcard(filter->local_name,
							     mask->local_name) == 0;
			} T_END;
			if (!matched)
				return 0;
		}
	}
	/* FIXME: it's not comparing full masks */
	if (mask->remote_bits != 0) {
		if (filter->remote_bits == 0)
			ret = -1;
		else if (!net_is_in_network(&filter->remote_net,
					    &mask->remote_net,
					    mask->remote_bits))
			return 0;
	}
	if (mask->local_bits != 0) {
		if (filter->local_bits == 0)
			ret = -1;
		else if (!net_is_in_network(&filter->local_net,
					    &mask->local_net, mask->local_bits))
			return 0;
	}
	return ret;
}

int config_filter_match_no_recurse(const struct config_filter *mask,
				   const struct config_filter *filter)
{
	int ret, ret2;

	if ((ret = config_filter_match_service(mask, filter)) == 0)
		return 0;
	if ((ret2 = config_filter_match_rest(mask, filter)) == 0)
		return 0;
	return ret > 0 && ret2 > 0 ? 1 : -1;
}

bool config_filter_match(const struct config_filter *mask,
			 const struct config_filter *filter)
{
	do {
		if (config_filter_match_no_recurse(mask, filter) <= 0)
			return FALSE;
		mask = mask->parent;
		filter = filter->parent;
	} while (mask != NULL && filter != NULL);
	return mask == NULL && filter == NULL;
}

bool config_filters_equal_no_recursion(const struct config_filter *f1,
				       const struct config_filter *f2)
{
	if (null_strcmp(f1->protocol, f2->protocol) != 0)
		return FALSE;

	if (f1->remote_bits != f2->remote_bits)
		return FALSE;
	if (!net_ip_compare(&f1->remote_net, &f2->remote_net))
		return FALSE;

	if (f1->local_bits != f2->local_bits)
		return FALSE;
	if (!net_ip_compare(&f1->local_net, &f2->local_net))
		return FALSE;

	if (null_strcmp(f1->local_name, f2->local_name) != 0)
		return FALSE;

	if (null_strcmp(f1->filter_name, f2->filter_name) != 0)
		return FALSE;
	if (f1->filter_name_array != f2->filter_name_array)
		return FALSE;
	return TRUE;
}

static bool
config_filters_equal_without_defaults(const struct config_filter *f1,
				      const struct config_filter *f2)
{
	if (!config_filters_equal_no_recursion(f1, f2))
		return FALSE;
	if (f1->parent != NULL || f2->parent != NULL) {
		/* Check the parents' compatibility also. However, it's
		   possible that one of these parents is the empty root filter,
		   while the other parent is NULL. These are actually equal. */
		return config_filters_equal_without_defaults(
			f1->parent != NULL ? f1->parent : &empty_filter,
			f2->parent != NULL ? f2->parent : &empty_filter);
	}
	return TRUE;
}

bool config_filters_equal(const struct config_filter *f1,
			  const struct config_filter *f2)
{
	if (f1->default_settings != f2->default_settings)
		return FALSE;

	/* For the rest of the settings don't check if the parents'
	   default_settings are equal. This makes it easier for callers to
	   do lookups with the wanted default_settings flag. */
	return config_filters_equal_without_defaults(f1, f2);
}

static unsigned int
config_filter_hash_crc(const struct config_filter *filter, uint32_t crc)
{
	if (filter->protocol != NULL)
		crc = crc32_str_more(crc, filter->protocol);
	if (filter->remote_bits > 0) {
		crc = crc32_data_more(crc, &filter->remote_bits,
				      sizeof(filter->remote_bits));
		crc = crc32_data_more(crc, &filter->remote_net,
				      sizeof(filter->remote_net));
	}
	if (filter->local_bits > 0) {
		crc = crc32_data_more(crc, &filter->local_bits,
				      sizeof(filter->local_bits));
		crc = crc32_data_more(crc, &filter->local_net,
				      sizeof(filter->local_net));
	}
	if (filter->local_name != NULL)
		crc = crc32_str_more(crc, filter->local_name);
	if (filter->filter_name != NULL) {
		crc = crc32_str_more(crc, filter->filter_name);
		if (filter->filter_name_array)
			crc = crc32_data_more(crc, "1", 1);
	}
	return filter->parent == NULL ? crc :
		config_filter_hash_crc(filter->parent, crc);
}

unsigned int config_filter_hash(const struct config_filter *filter)
{
	uint32_t crc = filter->default_settings ? 1 : 0;
	return config_filter_hash_crc(filter, crc);
}

bool config_filter_is_empty(const struct config_filter *filter)
{
	return config_filters_equal(filter, &empty_filter);
}

bool config_filter_is_empty_defaults(const struct config_filter *filter)
{
	return config_filters_equal(filter, &empty_defaults_filter);
}

static void
config_filter_get_path_str(string_t **path, const struct config_filter *filter)
{
	if (filter->parent != NULL)
		config_filter_get_path_str(path, filter->parent);
	if (filter->filter_name != NULL) {
		if (*path == NULL)
			*path = t_str_new(128);
		str_append(*path, filter->filter_name);
		str_append_c(*path, '/');
	}
}

const char *config_filter_get_path_prefix(const struct config_filter *filter)
{
	string_t *path = NULL;
	config_filter_get_path_str(&path, filter);
	return path == NULL ? "" : str_c(path);
}
