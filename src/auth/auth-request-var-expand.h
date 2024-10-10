#ifndef AUTH_REQUEST_VAR_EXPAND_H
#define AUTH_REQUEST_VAR_EXPAND_H

typedef const char *
auth_request_escape_func_t(const char *string,
			   const struct auth_request *auth_request);

#define AUTH_REQUEST_VAR_TAB_USER_IDX 0
#define AUTH_REQUEST_VAR_TAB_COUNT 29
extern const struct var_expand_table
auth_request_var_expand_static_tab[AUTH_REQUEST_VAR_TAB_COUNT+1];

extern const struct var_expand_provider auth_request_var_expand_providers[];

const struct var_expand_table *
auth_request_get_var_expand_table(const struct auth_request *auth_request);
struct var_expand_table *
auth_request_get_var_expand_table_full(const struct auth_request *auth_request,
				       const char *username,
				       unsigned int *count);

int auth_request_var_expand(string_t *dest, const char *str,
			    const struct auth_request *auth_request,
			    auth_request_escape_func_t *escape_func,
			    const char **error_r);
int auth_request_var_expand_with_table(string_t *dest, const char *str,
				       const struct auth_request *auth_request,
				       const struct var_expand_table *table,
				       auth_request_escape_func_t *escape_func,
				       const char **error_r);
int t_auth_request_var_expand(const char *str,
			      const struct auth_request *auth_request,
			      auth_request_escape_func_t *escape_func,
			      const char **value_r, const char **error_r);

const char *auth_request_str_escape(const char *string,
				    const struct auth_request *request);

void auth_request_event_set_var_expand(struct auth_request *auth_request);

#endif
