/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "settings-parser.h"
#include "master-service-settings.h"
#include "config-parser.h"
#include "config-filter.h"
#include "dns-util.h"

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
	do {
		if (!config_filter_match_service(mask, filter))
			return FALSE;

		if (!config_filter_match_rest(mask, filter))
			return FALSE;
		mask = mask->parent;
		filter = filter->parent;
	} while (mask != NULL && filter != NULL);
	return mask == NULL && filter == NULL;
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

	if (null_strcmp(f1->filter_name, f2->filter_name) != 0)
		return FALSE;
	for (;;) {
		f1 = f1->parent;
		f2 = f2->parent;
		if (f1 != NULL && f1->filter_name_array) {
			if (f2 == NULL || !f2->filter_name_array)
				return FALSE;
		} else if (f2 != NULL && f2->filter_name_array) {
			return FALSE;
		} else {
			break;
		}
		if (strcmp(f1->filter_name, f2->filter_name) != 0)
			return FALSE;
	}

	return TRUE;
}
