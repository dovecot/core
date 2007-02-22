/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "mail-storage-private.h"
#include "fts-lucene-plugin.h"

const char *fts_lucene_plugin_version = PACKAGE_VERSION;

unsigned int fts_lucene_storage_module_id;

void fts_lucene_plugin_init(void)
{
	fts_lucene_storage_module_id = mail_storage_module_id++;
	fts_backend_register(&fts_backend_lucene);
}

void fts_lucene_plugin_deinit(void)
{
	fts_backend_unregister(fts_backend_lucene.name);
}
