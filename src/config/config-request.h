#ifndef CONFIG_REQUEST_H
#define CONFIG_REQUEST_H

#include "config-filter.h"

enum config_dump_flags {
	CONFIG_DUMP_FLAG_DEFAULTS	= 0x01
};

typedef void config_request_callback_t(const char *key, const char *value,
				       bool list, void *context);

void config_request_handle(const struct config_filter *filter,
			   const char *module, enum config_dump_flags flags,
			   config_request_callback_t *callback, void *context);

#endif
