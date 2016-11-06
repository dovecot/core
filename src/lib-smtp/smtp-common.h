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
	SMTP_CAPABILITY_AUTH                = 0x0001,
	SMTP_CAPABILITY_STARTTLS            = 0x0002,
	SMTP_CAPABILITY_PIPELINING          = 0x0004,
	SMTP_CAPABILITY_SIZE                = 0x0008,
	SMTP_CAPABILITY_ENHANCEDSTATUSCODES = 0x0010,
	SMTP_CAPABILITY_8BITMIME            = 0x0020,
	SMTP_CAPABILITY_CHUNKING            = 0x0040,
	SMTP_CAPABILITY_BINARYMIME          = 0x0080,
	SMTP_CAPABILITY_BURL                = 0x0100,
	SMTP_CAPABILITY_DSN                 = 0x0200,
	SMTP_CAPABILITY_VRFY                = 0x0400,
	SMTP_CAPABILITY_ETRN                = 0x0800,
	SMTP_CAPABILITY_XCLIENT             = 0x1000
};
struct smtp_capability_name {
	const char *name;
	enum smtp_capability capability;
};
extern const struct smtp_capability_name smtp_capability_names[];

/*
 * SMTP proxy data
 */

enum smtp_proxy_protocol {
	SMTP_PROXY_PROTOCOL_UNKNOWN = 0,
	SMTP_PROXY_PROTOCOL_SMTP,
	SMTP_PROXY_PROTOCOL_ESMTP,
	SMTP_PROXY_PROTOCOL_LMTP
};

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
};

#endif
