/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fts-squat-plugin.h"

const char *fts_squat_plugin_version = DOVECOT_VERSION;

void fts_squat_plugin_init(struct module *module ATTR_UNUSED)
{
	fts_backend_register(&fts_backend_squat);
}

void fts_squat_plugin_deinit(void)
{
	fts_backend_unregister(fts_backend_squat.name);
}

const char *fts_squat_plugin_dependencies[] = { "fts", NULL };
