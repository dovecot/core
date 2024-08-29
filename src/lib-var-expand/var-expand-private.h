#ifndef VAR_EXPAND_PRIVATE_H
#define VAR_EXPAND_PRIVATE_H 1

#include "var-expand.h"

/* Macro for filters to error our with unsupported key */
#define ERROR_UNSUPPORTED_KEY(key) STMT_START { \
	*error_r = t_strdup_printf("Unsupported key '%s'", key); \
	return -1; \
} STMT_END

/* Macro for filters to error out with too many positional parameters */
#define ERROR_TOO_MANY_UNNAMED_PARAMETERS STMT_START { \
	*error_r = "Too many positional parameters"; \
	return -1; \
} STMT_END

/* Error out if filter did not get parameters at all */
#define ERROR_IF_NO_PARAMETERS \
STMT_START { if (stmt->params == NULL) { \
	*error_r = "Missing parameters"; \
	return -1; \
} } STMT_END

/* Error out if filter got any parameters */
#define ERROR_IF_ANY_PARAMETERS \
STMT_START { if (stmt->params != NULL) { \
	const char *key = var_expand_parameter_key(stmt->params); \
	if (key != NULL) { \
		ERROR_UNSUPPORTED_KEY(key); \
	} else { \
		ERROR_TOO_MANY_UNNAMED_PARAMETERS; \
	} \
} } STMT_END

/* Error out if transfer is not set. */
#define ERROR_IF_NO_TRANSFER_TO(action) \
STMT_START { if (!state->transfer_set) { \
	*error_r = t_strdup_printf("No value to %s", action); \
	return -1; \
} } STMT_END

struct var_expand_state;
struct var_expand_parameter_iter_context;
struct var_expand_statement;
struct var_expand_parameter;

enum var_expand_statement_operator {
	VAR_EXPAND_STATEMENT_OPER_PLUS = 0,
	VAR_EXPAND_STATEMENT_OPER_MINUS,
	VAR_EXPAND_STATEMENT_OPER_STAR,
	VAR_EXPAND_STATEMENT_OPER_SLASH,
	VAR_EXPAND_STATEMENT_OPER_MODULO,
	VAR_EXPAND_STATEMENT_OPER_COUNT
};

struct var_expand_program {
	pool_t pool;
	struct var_expand_program *next;
	struct var_expand_statement *first;
	const char *const *variables;
	bool only_literal:1;
};

struct var_expand_state {
	/* Parameters for var_expand_program_execute */
	const struct var_expand_params *params;
	string_t *result;
	/* used for delayed first variable error */
	char *delayed_error;

	/* use transfer helpers */
	string_t *transfer;
	bool transfer_set:1;
	bool transfer_binary:1;
};

struct var_expand_statement {
	struct var_expand_statement *next;
	const char *function;
	const struct var_expand_parameter *params, *ptr;
};

typedef int var_expand_filter_func_t(const struct var_expand_statement *stmt,
				 struct var_expand_state *state, const char **error_r);

/* Parameter accessors */
const char *var_expand_parameter_key(const struct var_expand_parameter *param);
int var_expand_parameter_idx(const struct var_expand_parameter *param);

int var_expand_parameter_number(const struct var_expand_parameter *param,
				bool convert, intmax_t *value_r);
int var_expand_parameter_string(const struct var_expand_parameter *param,
				bool convert, const char **value_r);
int var_expand_parameter_from_state(struct var_expand_state *state, bool number,
				    const struct var_expand_parameter **param_r);

/* Require number or variable containing number */
int var_expand_parameter_number_or_var(const struct var_expand_state *state,
				       const struct var_expand_parameter *param,
				       intmax_t *value_r, const char **error_r);
int var_expand_parameter_bool_or_var(const struct var_expand_state *state,
				     const struct var_expand_parameter *param,
				     bool *value_r, const char **error_r);

/* Require string or variable containing string */
int var_expand_parameter_string_or_var(const struct var_expand_state *state,
				       const struct var_expand_parameter *param,
				       const char **value_r, const char **error_r);

/* Get string (or number as string) or variable as string */
int var_expand_parameter_any_or_var(const struct var_expand_state *state,
				    const struct var_expand_parameter *param,
				    const char **value_r, const char **error_r);

/* Iterator for accessing parameters */
struct var_expand_parameter_iter_context *
var_expand_parameter_iter_init(const struct var_expand_statement *stmt);
bool var_expand_parameter_iter_more(struct var_expand_parameter_iter_context *ctx);
const struct var_expand_parameter *
var_expand_parameter_iter_next(struct var_expand_parameter_iter_context *ctx);

void var_expand_parameter_dump(string_t *dest, const struct var_expand_parameter *par);

/* Looks up variable from state, if not found, returns -1 */
int var_expand_state_lookup_variable(const struct var_expand_state *state,
				     const char *name, const char **result_r,
				     const char **error_r);
/* Sets the transfer data in state */
void var_expand_state_set_transfer_data(struct var_expand_state *state,
					const void *value, size_t len);
/* Sets the transfer data in state as binary */
void var_expand_state_set_transfer_binary(struct var_expand_state *state,
					  const void *value, size_t len);

/* Sets the transfer data to provided string in state */
void var_expand_state_set_transfer(struct var_expand_state *state, const char *value);

/* Unsets transfer data */
void var_expand_state_unset_transfer(struct var_expand_state *state);

void var_expand_register_filter(const char *name, var_expand_filter_func_t *const filter);
bool var_expand_is_filter(const char *name);
void var_expand_unregister_filter(const char *name);

#endif
