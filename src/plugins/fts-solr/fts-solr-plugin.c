/* Copyright (c) 2006-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fts-solr-plugin.h"

#include <stdlib.h>

const char *fts_solr_plugin_version = PACKAGE_VERSION;
struct fts_solr_settings fts_solr_settings;

static void fts_solr_plugin_init_settings(const char *str)
{
	struct fts_solr_settings *set = &fts_solr_settings;
	const char *const *tmp;

	if (str == NULL)
		str = "";

	for (tmp = t_strsplit_spaces(str, " "); *tmp != NULL; tmp++) {
		if (strncmp(*tmp, "url=", 4) == 0) {
			i_free(set->url);
			set->url = i_strdup(*tmp + 4);
		} else if (strcmp(*tmp, "debug") == 0) {
			set->debug = TRUE;
		} else if (strcmp(*tmp, "break-imap-search") == 0) {
			set->substring_search = TRUE;
		} else if (strcmp(*tmp, "default_ns=") == 0) {
			i_free(set->default_ns_prefix);
			set->default_ns_prefix = i_strdup(*tmp + 11);
		} else {
			i_fatal("fts_solr: Invalid setting: %s", *tmp);
		}
	}
	if (set->url == NULL)
		i_fatal("fts_solr: url setting missing");
}

void fts_solr_plugin_init(void)
{
	fts_solr_plugin_init_settings(getenv("FTS_SOLR"));
	fts_backend_register(&fts_backend_solr);
}

void fts_solr_plugin_deinit(void)
{
	i_free(fts_solr_settings.url);
	fts_backend_unregister(fts_backend_solr.name);
}
