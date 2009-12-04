#ifndef FTS_SQUAT_PLUGIN_H
#define FTS_SQUAT_PLUGIN_H

#include "fts-api-private.h"

struct module;

extern const char *fts_squat_plugin_dependencies[];
extern struct fts_backend fts_backend_squat;

void fts_squat_plugin_init(struct module *module);
void fts_squat_plugin_deinit(void);

#endif
