#ifndef FTS_SOLR_PLUGIN_H
#define FTS_SOLR_PLUGIN_H

#include "module-context.h"
#include "mail-user.h"
#include "fts-api-private.h"
#include "fts-solr-settings.h"

#define FTS_SOLR_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_solr_user_module)
#define FTS_SOLR_USER_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, fts_solr_user_module)

struct fts_solr_user {
	union mail_user_module_context module_ctx;
	const struct fts_solr_settings *set;
};

extern const char *fts_solr_plugin_dependencies[];
extern struct fts_backend fts_backend_solr;
extern MODULE_CONTEXT_DEFINE(fts_solr_user_module, &mail_user_module_register);
extern struct http_client *solr_http_client;

int fts_solr_mail_user_get(struct mail_user *user, struct event *event,
			   struct fts_solr_user **fuser_r,
			   const char **error_r);

void fts_solr_plugin_init(struct module *module);
void fts_solr_plugin_deinit(void);

#endif
