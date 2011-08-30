#ifndef PASSDB_TEMPLATE_H
#define PASSDB_TEMPLATE_H

#define STATIC_PASS_SCHEME "PLAIN"

struct passdb_template *passdb_template_build(pool_t pool, const char *args);
void passdb_template_export(struct passdb_template *tmpl,
			    struct auth_request *auth_request);
bool passdb_template_remove(struct passdb_template *tmpl,
			    const char *key, const char **value_r);

#endif
