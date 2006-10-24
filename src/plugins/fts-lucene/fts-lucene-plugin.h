#ifndef __FTS_LUCENE_PLUGIN_H
#define __FTS_LUCENE_PLUGIN_H

#include "fts-api-private.h"

#define LUCENE_CONTEXT(obj) \
	*((void **)array_idx_modifiable(&(obj)->module_contexts, \
					fts_lucene_storage_module_id))

extern struct fts_backend fts_backend_lucene;
extern unsigned int fts_lucene_storage_module_id;

void fts_lucene_plugin_init(void);
void fts_lucene_plugin_deinit(void);

#endif
