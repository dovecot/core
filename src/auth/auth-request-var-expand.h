#ifndef AUTH_REQUEST_VAR_EXPAND_H
#define AUTH_REQUEST_VAR_EXPAND_H

typedef const char *
auth_request_escape_func_t(const char *string,
			   const struct auth_request *auth_request);

#define AUTH_REQUEST_VAR_TAB_USER_IDX 0
#define AUTH_REQUEST_VAR_TAB_USERNAME_IDX 1
#define AUTH_REQUEST_VAR_TAB_DOMAIN_IDX 2
#define AUTH_REQUEST_VAR_TAB_COUNT 38
extern const struct var_expand_table
auth_request_var_expand_static_tab[AUTH_REQUEST_VAR_TAB_COUNT+1];

extern const struct var_expand_func_table auth_request_var_funcs_table[];

const struct var_expand_table *
auth_request_get_var_expand_table(const struct auth_request *auth_request,
				  auth_request_escape_func_t *escape_func)
	ATTR_NULL(2);
struct var_expand_table *
auth_request_get_var_expand_table_full(const struct auth_request *auth_request,
				       auth_request_escape_func_t *escape_func,
				       unsigned int *count) ATTR_NULL(2);

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

#endif
