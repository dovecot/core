#ifndef FTS_SOLR_PLUGIN_H
#define FTS_SOLR_PLUGIN_H

#include "module-context.h"
#include "mail-user.h"
#include "fts-api-private.h"

#define FTS_SOLR_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_solr_user_module)

struct fts_solr_settings {
	const char *url, *default_ns_prefix;
	bool use_libfts;
	bool debug;
	bool limit_mime_hdr;
	bool skip_mime_hdr_fieldname;
};

struct fts_solr_user {
	union mail_user_module_context module_ctx;
	struct fts_solr_settings set;
};

extern const char *fts_solr_plugin_dependencies[];
extern struct fts_backend fts_backend_solr;
extern struct fts_backend fts_backend_solr_old;
extern MODULE_CONTEXT_DEFINE(fts_solr_user_module, &mail_user_module_register);
extern struct http_client *solr_http_client;

void fts_solr_plugin_init(struct module *module);
void fts_solr_plugin_deinit(void);

#endif
