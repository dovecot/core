/* Copyright (c) 2006-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fts-solr-plugin.h"

const char *fts_solr_plugin_version = PACKAGE_VERSION;

void fts_solr_plugin_init(void)
{
	fts_backend_register(&fts_backend_solr);
}

void fts_solr_plugin_deinit(void)
{
	fts_backend_unregister(fts_backend_solr.name);
}
