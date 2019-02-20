/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "smtp-common.h"

/*
 * Capabilities
 */

const struct smtp_capability_name smtp_capability_names[] = {
	{ "AUTH", SMTP_CAPABILITY_AUTH },
	{ "STARTTLS", SMTP_CAPABILITY_STARTTLS },
	{ "PIPELINING", SMTP_CAPABILITY_PIPELINING },
	{ "SIZE", SMTP_CAPABILITY_SIZE },
	{ "ENHANCEDSTATUSCODES", SMTP_CAPABILITY_ENHANCEDSTATUSCODES },
	{ "8BITMIME", SMTP_CAPABILITY_8BITMIME },
	{ "CHUNKING", SMTP_CAPABILITY_CHUNKING },
	{ "BINARYMIME", SMTP_CAPABILITY_BINARYMIME },
	{ "BURL", SMTP_CAPABILITY_BURL },
	{ "DSN", SMTP_CAPABILITY_DSN },
	{ "VRFY", SMTP_CAPABILITY_VRFY },
	{ "ETRN", SMTP_CAPABILITY_ETRN },
	{ "XCLIENT", SMTP_CAPABILITY_XCLIENT },
	{ NULL, 0 }
};

enum smtp_capability smtp_capability_find_by_name(const char *cap_name)
{
	const struct smtp_capability_name *cap;
	unsigned int i;

	for (i = 0; smtp_capability_names[i].name != NULL; i++) {
		cap = &smtp_capability_names[i];

		if (strcasecmp(cap_name, cap->name) == 0)
			return cap->capability;
	}

	return SMTP_CAPABILITY_NONE;
}

/*
 * SMTP proxy data
 */

static void
smtp_proxy_data_merge_extra_fields(pool_t pool, struct smtp_proxy_data *dst,
				   const struct smtp_proxy_data *src)
{
	const struct smtp_proxy_data_field *sefields;
	struct smtp_proxy_data_field *defields;
	unsigned int i;

	if (src->extra_fields_count == 0)
		return;

	sefields = src->extra_fields;
	defields = p_new(pool, struct smtp_proxy_data_field,
			 src->extra_fields_count);
	for (i = 0; i < src->extra_fields_count; i++) {
		defields[i].name = p_strdup(pool, sefields[i].name);
		defields[i].value = p_strdup(pool, sefields[i].value);
	}

	dst->extra_fields = defields;
	dst->extra_fields_count = src->extra_fields_count;
}

void smtp_proxy_data_merge(pool_t pool, struct smtp_proxy_data *dst,
			   const struct smtp_proxy_data *src)
{
	if (src->proto != SMTP_PROXY_PROTOCOL_UNKNOWN)
		dst->proto = src->proto;
	if (src->source_ip.family != 0) {
		dst->source_ip = src->source_ip;
		if (src->source_port != 0)
			dst->source_port = src->source_port;
	}
	if (src->helo != NULL && *src->helo != '\0')
		dst->helo = p_strdup(pool, src->helo);
	if (src->login != NULL && *src->login != '\0')
		dst->login = p_strdup(pool, src->login);
	if (src->ttl_plus_1 > 0)
		dst->ttl_plus_1 = src->ttl_plus_1;
	if (src->timeout_secs > 0)
		dst->timeout_secs = src->timeout_secs;

	smtp_proxy_data_merge_extra_fields(pool, dst, src);
};
