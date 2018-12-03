#ifndef SMTP_COMMON_H
#define SMTP_COMMON_H

#include "net.h"

/*
 * SMTP protocols
 */

enum smtp_protocol {
	SMTP_PROTOCOL_SMTP = 0,
	SMTP_PROTOCOL_LMTP
};

static inline const char *
smtp_protocol_name(enum smtp_protocol proto)
{
	switch (proto) {
	case SMTP_PROTOCOL_SMTP:
		return "smtp";
	case SMTP_PROTOCOL_LMTP:
		return "lmtp";
	default:
		break;
	}
	i_unreached();
}

/* SMTP capabilities */

enum smtp_capability {
	SMTP_CAPABILITY_NONE                = 0,

	SMTP_CAPABILITY_AUTH                = BIT(0),
	SMTP_CAPABILITY_STARTTLS            = BIT(1),
	SMTP_CAPABILITY_PIPELINING          = BIT(2),
	SMTP_CAPABILITY_SIZE                = BIT(3),
	SMTP_CAPABILITY_ENHANCEDSTATUSCODES = BIT(4),
	SMTP_CAPABILITY_8BITMIME            = BIT(5),
	SMTP_CAPABILITY_CHUNKING            = BIT(6),
	SMTP_CAPABILITY_BINARYMIME          = BIT(7),
	SMTP_CAPABILITY_BURL                = BIT(8),
	SMTP_CAPABILITY_DSN                 = BIT(9),
	SMTP_CAPABILITY_VRFY                = BIT(10),
	SMTP_CAPABILITY_ETRN                = BIT(11),
	SMTP_CAPABILITY_XCLIENT             = BIT(12),

	SMTP_CAPABILITY__ORCPT              = BIT(24),
};

struct smtp_capability_name {
	const char *name;
	enum smtp_capability capability;
};

struct smtp_capability_extra {
	const char *name;
	const char *const *params;
};

extern const struct smtp_capability_name smtp_capability_names[];

enum smtp_capability smtp_capability_find_by_name(const char *cap_name);

/*
 * SMTP proxy data
 */

enum smtp_proxy_protocol {
	SMTP_PROXY_PROTOCOL_UNKNOWN = 0,
	SMTP_PROXY_PROTOCOL_SMTP,
	SMTP_PROXY_PROTOCOL_ESMTP,
	SMTP_PROXY_PROTOCOL_LMTP
};

struct smtp_proxy_data_field {
	const char *name;
	const char *value;
};
ARRAY_DEFINE_TYPE(smtp_proxy_data_field, struct smtp_proxy_data_field);

struct smtp_proxy_data {
	/* PROTO */
	enum smtp_proxy_protocol proto;
	/* ADDR */
	struct ip_addr source_ip;
	/* PORT */
	in_port_t source_port;
	/* HELO, LOGIN */
	const char *helo, *login;

	/* TTL: send as this -1, so the default 0 means "don't send it" */
	unsigned int ttl_plus_1;
	/* TIMEOUT: remote is notified that the connection is going to be closed
	   after this many seconds, so it should try to keep lock waits and such
	   lower than this. */
	unsigned int timeout_secs;

	/* additional fields */
	const struct smtp_proxy_data_field *extra_fields;
	unsigned int extra_fields_count;
};

/*
 * SMTP proxy data
 */

void smtp_proxy_data_merge(pool_t pool, struct smtp_proxy_data *dst,
			   const struct smtp_proxy_data *src);

#endif
