#ifndef CONFIG_REQUEST_H
#define CONFIG_REQUEST_H

#include "config-filter.h"

enum config_dump_scope {
	/* Dump all settings */
	CONFIG_DUMP_SCOPE_ALL,
	/* Dump all that have explicitly been set */
	CONFIG_DUMP_SCOPE_SET,
	/* Dump only settings that differ from defaults */
	CONFIG_DUMP_SCOPE_CHANGED
};

typedef void config_request_callback_t(const char *key, const char *value,
				       bool list, void *context);

void config_request_handle(const struct config_filter *filter,
			   const char *module, enum config_dump_scope scope,
			   config_request_callback_t *callback, void *context);

#endif
