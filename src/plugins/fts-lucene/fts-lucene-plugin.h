#ifndef FTS_LUCENE_PLUGIN_H
#define FTS_LUCENE_PLUGIN_H

#include "fts-api-private.h"

extern struct fts_backend fts_backend_lucene;

void fts_lucene_plugin_init(struct module *module);
void fts_lucene_plugin_deinit(void);

#endif
