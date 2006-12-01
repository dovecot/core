#ifndef __FTS_SQUAT_PLUGIN_H
#define __FTS_SQUAT_PLUGIN_H

#include "fts-api-private.h"

extern struct fts_backend fts_backend_squat;

void fts_squat_plugin_init(void);
void fts_squat_plugin_deinit(void);

#endif
