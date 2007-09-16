#ifndef FTS_LUCENE_PLUGIN_H
#define FTS_LUCENE_PLUGIN_H

#include "fts-api-private.h"

#define LUCENE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_lucene_storage_module)

extern struct fts_backend fts_backend_lucene;
extern MODULE_CONTEXT_DEFINE(fts_lucene_storage_module,
			     &mail_storage_module_register);

void fts_lucene_plugin_init(void);
void fts_lucene_plugin_deinit(void);

#endif
