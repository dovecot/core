/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strnum.h"
#include "var-expand-private.h"
#include "expansion.h"

struct var_expand_parameter_iter_context {
	const struct var_expand_parameter *ptr;
};

const char *var_expand_parameter_key(const struct var_expand_parameter *param)
{
	return param->key;
}

int var_expand_parameter_idx(const struct var_expand_parameter *param)
{
	return param->idx;
}

int var_expand_parameter_number_or_var(const struct var_expand_state *state,
				       const struct var_expand_parameter *param,
				       intmax_t *value_r, const char **error_r)
{
	if (param == NULL) {
		*error_r = "Missing parameter";
		return -1;
	}

	if (param->value_type == VAR_EXPAND_PARAMETER_VALUE_TYPE_VARIABLE) {
		const char *result;
		if (var_expand_state_lookup_variable(state, param->value.str,
						     &result, error_r) < 0)
			return -1;
		else if (str_to_intmax(result, value_r) < 0) {
			*error_r = t_strdup_printf("'%s' (in %s) is not a number",
						   result, param->value.str);
			return -1;
		}
	} else if (param->value_type != VAR_EXPAND_PARAMETER_VALUE_TYPE_INT) {
		*error_r = t_strdup_printf("'%s' is not a number", param->value.str);
		return -1;
	} else {
		*value_r = param->value.num;
	}
	return 0;
}

int var_expand_parameter_bool_or_var(const struct var_expand_state *state,
				     const struct var_expand_parameter *param,
				     bool *value_r, const char **error_r)
{
	intmax_t value;
	if (var_expand_parameter_number_or_var(state, param, &value, error_r) < 0)
		return -1;
	if (value == 0) {
		*value_r = FALSE;
	} else if (value == 1) {
		*value_r = TRUE;
	} else {
		*error_r = t_strdup_printf("'%s' is not 0 or 1", param->value.str);
		return -1;
	}
	return 0;
}

int var_expand_parameter_string_or_var(const struct var_expand_state *state,
				       const struct var_expand_parameter *param,
				       const char **value_r, const char **error_r)
{
	if (param == NULL) {
		*error_r = "Missing parameter";
		return -1;
	}
	if (param->value_type == VAR_EXPAND_PARAMETER_VALUE_TYPE_VARIABLE) {
		if (var_expand_state_lookup_variable(state, param->value.str,
						     value_r, error_r) < 0)
			return -1;
	} else if (param->value_type == VAR_EXPAND_PARAMETER_VALUE_TYPE_INT) {
		*error_r = t_strdup_printf("%jd is not a string",
					   param->value.num);
		return -1;
	} else {
		*value_r = param->value.str;
	}
	return 0;
}

int var_expand_parameter_any_or_var(const struct var_expand_state *state,
				    const struct var_expand_parameter *param,
				    const char **value_r, const char **error_r)
{
	if (param == NULL) {
		*error_r = "Missing parameter";
		return -1;
	}
	if (param->value_type == VAR_EXPAND_PARAMETER_VALUE_TYPE_VARIABLE) {
		if (var_expand_state_lookup_variable(state, param->value.str,
						     value_r, error_r) < 0)
			return -1;
	} else if (param->value_type == VAR_EXPAND_PARAMETER_VALUE_TYPE_INT) {
		*value_r = t_strdup_printf("%jd", param->value.num);
	} else {
		*value_r = param->value.str;
	}
	return 0;
}

struct var_expand_parameter_iter_context *
var_expand_parameter_iter_init(const struct var_expand_statement *stmt)
{
	struct var_expand_parameter_iter_context *ctx =
		t_new(struct var_expand_parameter_iter_context, 1);
	ctx->ptr = stmt->params;
	return ctx;
}

bool var_expand_parameter_iter_more(struct var_expand_parameter_iter_context *ctx)
{
	return ctx->ptr != NULL;
}

const struct var_expand_parameter *
var_expand_parameter_iter_next(struct var_expand_parameter_iter_context *ctx)
{
	i_assert(ctx->ptr != NULL);
	const struct var_expand_parameter *par = ctx->ptr;
	ctx->ptr = ctx->ptr->next;
	return par;
}

void var_expand_parameter_dump(string_t *dest, const struct var_expand_parameter *par)
{
	if (par->idx > -1)
		str_printfa(dest, "\t - %d ", par->idx);
	else
		str_printfa(dest, "\t - %s ", par->key);
	switch (par->value_type) {
	case VAR_EXPAND_PARAMETER_VALUE_TYPE_STRING:
		str_printfa(dest, "'%s'", par->value.str);
		break;
	case VAR_EXPAND_PARAMETER_VALUE_TYPE_INT:
		str_printfa(dest, "%ld", par->value.num);
		break;
	case VAR_EXPAND_PARAMETER_VALUE_TYPE_VARIABLE:
		str_append(dest, par->value.str);
		break;
	case VAR_EXPAND_PARAMETER_VALUE_TYPE_COUNT:
		i_unreached();
	}
	str_append_c(dest, '\n');
}


int var_expand_parameter_number(const struct var_expand_parameter *param,
				bool convert, intmax_t *value_r)
{
	if (param->value_type == VAR_EXPAND_PARAMETER_VALUE_TYPE_INT) {
		*value_r = param->value.num;
		return 0;
	} else if (convert && param->value_type == VAR_EXPAND_PARAMETER_VALUE_TYPE_STRING)
		return str_to_intmax(param->value.str, value_r);

	return -1;
}

int var_expand_parameter_string(const struct var_expand_parameter *param,
				bool convert, const char **value_r)
{
	if (param->value_type == VAR_EXPAND_PARAMETER_VALUE_TYPE_STRING) {
		*value_r = param->value.str;
		return 0;
	} else if (convert && param->value_type == VAR_EXPAND_PARAMETER_VALUE_TYPE_INT) {
		*value_r = t_strdup_printf("%jd", param->value.num);
		return 0;
	}
	return -1;
}

int
var_expand_parameter_from_state(struct var_expand_state *state, bool number,
				const struct var_expand_parameter **param_r)
{
	if (!state->transfer_set)
		return -1;
	struct var_expand_parameter *par = t_new(struct var_expand_parameter, 1);
	par->idx = -1;
	if (number) {
		par->value_type = VAR_EXPAND_PARAMETER_VALUE_TYPE_INT;
		if (str_to_intmax(str_c(state->transfer), &par->value.num) < 0)
			return -1;
	} else {
		par->value_type = VAR_EXPAND_PARAMETER_VALUE_TYPE_STRING;
		par->value.str = t_strdup(str_c(state->transfer));
	}
	*param_r = par;
	return 0;
}
