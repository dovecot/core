#ifndef EXPANSION_H
#define EXPANSION_H 1

enum var_expand_parameter_value_type {
	VAR_EXPAND_PARAMETER_VALUE_TYPE_STRING,
	VAR_EXPAND_PARAMETER_VALUE_TYPE_INT,
	VAR_EXPAND_PARAMETER_VALUE_TYPE_VARIABLE,
	VAR_EXPAND_PARAMETER_VALUE_TYPE_COUNT
};

union var_expand_parameter_value {
	const char *str;
	intmax_t num;
};

struct var_expand_parameter {
	struct var_expand_parameter *next;
	const char *key;
	int idx;
	enum var_expand_parameter_value_type value_type;
	union var_expand_parameter_value value;
};

struct var_expand_filter {
	const char *name;
	var_expand_filter_func_t *const filter;
};

bool var_expand_execute_stmt(struct var_expand_state *state,
			 const struct var_expand_statement *stmt,
			 bool first, const char **error_r);
int var_expand_find_filter(const char *name, var_expand_filter_func_t **fn_r);

int expansion_filter_if(const struct var_expand_statement *stmt, struct var_expand_state *state,
			const char **error_r);
int
expansion_filter_encrypt(const struct var_expand_statement *stmt,
			 struct var_expand_state *state, const char **error_r);
int
expansion_filter_decrypt(const struct var_expand_statement *stmt,
			 struct var_expand_state *state, const char **error_r);

void expansion_filter_crypt_set_functions(var_expand_filter_func_t *encrypt,
					  var_expand_filter_func_t *decrypt);

#endif
