#ifndef FTS_SOLR_PLUGIN_H
#define FTS_SOLR_PLUGIN_H

#include "fts-api-private.h"

extern struct fts_backend fts_backend_solr;

void fts_solr_plugin_init(void);
void fts_solr_plugin_deinit(void);

#endif
