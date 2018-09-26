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
