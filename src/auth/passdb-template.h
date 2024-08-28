#ifndef PASSDB_TEMPLATE_H
#define PASSDB_TEMPLATE_H

#define STATIC_PASS_SCHEME "PLAIN"

struct passdb_template *passdb_template_build(pool_t pool, const char *args);
int passdb_template_export(struct passdb_template *tmpl,
			   struct auth_request *auth_request,
			   const char **error_r);
bool passdb_template_is_empty(struct passdb_template *tmpl);

void passdb_template_free(struct passdb_template **_tmpl);

const char *const *passdb_template_get_args(struct passdb_template *tmpl, unsigned int *count_r);

#endif
