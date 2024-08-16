/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hex-binary.h"
#include "var-expand-private.h"
#include "var-expand-parser-private.h"
#include "var-expand-parser.h"
#include "expansion.h"

extern void var_expand_parser_lex_init_extra(void*, void*);

static const struct var_expand_params empty_params = {
};

int var_expand_program_create(const char *str,
			      struct var_expand_program **program_r,
			      const char **error_r)
{
	int ret;
	struct var_expand_parser_state state;
	i_zero(&state);
	pool_t pool =
		pool_alloconly_create(MEMPOOL_GROWING"var expand program", 1024);
	state.p = state.plist = p_new(pool, struct var_expand_program, 1);
	state.p->pool = pool;
	p_array_init(&state.variables, pool, 1);

	T_BEGIN {
		state.str = NULL;
		state.pool =
			pool_alloconly_create(MEMPOOL_GROWING"var expand parser", 32768);
		p_array_init(&state.variables, pool, 1);
		state.input = str;
		state.left = strlen(str);
		var_expand_parser_lex_init_extra(&state, &state.scanner);
		/* 0 = OK, everything else = something went wrong */
		ret = var_expand_parser_parse(&state);
		state.error = t_strdup(state.error);
	} T_END_PASS_STR_IF(ret != 0, &state.error);

	array_append_space(&state.variables);
	state.plist->variables = array_front(&state.variables);
	i_assert(state.plist->variables != NULL);
	pool_unref(&state.pool);

	if (ret != 0) {
		*error_r = state.error;
		var_expand_program_free(&state.plist);
	} else {
		*program_r = state.plist;
	}
	i_assert(ret == 0 || *error_r != NULL);

	return ret == 0 ? 0 : -1;
}

void var_expand_program_dump(const struct var_expand_program *prog, string_t *dest)
{
	while (prog != NULL) {
		struct var_expand_statement *stmt = prog->first;
		while (stmt != NULL) {
			const char *or_var = "";
			if (stmt == prog->first && !prog->only_literal)
				or_var = " or variable";
			str_printfa(dest, "function%s %s\n", or_var, stmt->function);
			struct var_expand_parameter_iter_context *ctx =
				var_expand_parameter_iter_init(stmt);
			while (var_expand_parameter_iter_more(ctx)) {
				const struct var_expand_parameter *par =
					var_expand_parameter_iter_next(ctx);
				var_expand_parameter_dump(dest, par);
			}
			stmt = stmt->next;
		}
		prog = prog->next;
	}
}

int var_expand_program_execute(string_t *dest, const struct var_expand_program *program,
			       const struct var_expand_params *params, const char **error_r)
 {
	int ret = 0;
	struct var_expand_state state;
	i_zero(&state);

	if (params == NULL)
		params = &empty_params;

	i_assert((params->table == NULL && params->tables_arr == NULL) ||
		 (params->table != NULL && params->tables_arr == NULL) ||
		 (params->table == NULL && params->tables_arr != NULL));

	i_assert((params->providers == NULL && params->providers_arr == NULL) ||
		 (params->providers != NULL && params->providers_arr == NULL) ||
		 (params->providers == NULL && params->providers_arr != NULL));

	size_t num_tables = 0;
	if (params->tables_arr != NULL)
		while (params->tables_arr[num_tables] != NULL)
			num_tables++;
	size_t num_providers = 0;
	if (params->providers_arr != NULL)
		while (params->providers_arr[num_providers] != NULL)
		     num_providers++;
	size_t num_contexts = I_MAX(num_tables, num_providers);

	/* ensure contexts are properly terminated. */
	i_assert(params->contexts == NULL ||
		 params->contexts[num_contexts] == var_expand_contexts_end);

	state.params = params;
	state.result = str_new(default_pool, 32);
	state.transfer = str_new(default_pool, 32);

	*error_r = NULL;

	while (program != NULL) {
		const struct var_expand_statement *stmt = program->first;
		if (stmt == NULL) {
			/* skip empty programs */
			program = program->next;
			continue;
		}
		T_BEGIN {
			while (stmt != NULL) {
				bool first = stmt == program->first;
				if (!var_expand_execute_stmt(&state, stmt,
							     first, error_r)) {
					ret = -1;
					break;
				}
				stmt = stmt->next;
			}
		} T_END_PASS_STR_IF(ret < 0, error_r);
		if (ret < 0)
			break;
		if (state.transfer_binary)
			var_expand_state_set_transfer(&state, binary_to_hex(state.transfer->data, state.transfer->used));
		if (state.transfer_set) {
			if (!program->only_literal && params->escape_func != NULL) {
				str_append(state.result,
					   params->escape_func(str_c(state.transfer),
							       params->escape_context));
			} else
				str_append_str(state.result, state.transfer);
		} else {
			*error_r = t_strdup(state.delayed_error);
			ret = -1;
			break;
		}
		var_expand_state_unset_transfer(&state);
		program = program->next;
	};
	str_free(&state.transfer);
	i_free(state.delayed_error);
	/* only write to dest on success */
	if (ret == 0)
		str_append_str(dest, state.result);
	str_free(&state.result);
	i_assert(ret == 0 || *error_r != NULL);

	return ret;
}

const char *const *
var_expand_program_variables(const struct var_expand_program *program)
{
	return program->variables;
}

void var_expand_program_free(struct var_expand_program **_program)
{
	struct var_expand_program *program = *_program;
	if (program == NULL)
		return;
	*_program = NULL;

	pool_unref(&program->pool);
}
