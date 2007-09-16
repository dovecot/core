#ifndef USERDB_STATIC_H
#define USERDB_STATIC_H

struct userdb_static_template *
userdb_static_template_build(pool_t pool, const char *userdb_name,
			     const char *args);
bool userdb_static_template_isset(struct userdb_static_template *tmpl,
				  const char *key);
bool userdb_static_template_remove(struct userdb_static_template *tmpl,
				   const char *key, const char **value_r);
void userdb_static_template_export(struct userdb_static_template *tmpl,
				   struct auth_request *auth_request);

#endif
