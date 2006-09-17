/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "fts-lucene-plugin.h"

void fts_lucene_plugin_init(void)
{
	fts_backend_register(&fts_backend_lucene);
}

void fts_lucene_plugin_deinit(void)
{
	fts_backend_unregister(fts_backend_lucene.name);
}
