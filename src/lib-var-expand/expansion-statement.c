/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "var-expand-private.h"
#include "expansion.h"

bool var_expand_execute_stmt(struct var_expand_state *state,
			     const struct var_expand_statement *stmt,
			     bool first, const char **error_r)
{
	const char *error;
	char *delayed_error = NULL;
	var_expand_filter_func_t *fn;

	/* We allow first function to be either variable or function,
	   so that you can do simple lookups, like %{variable}.
	   Also we prefer variables first, to avoid cumbersome things like
	   having to write lookup('domain') every time you wanted domain.
	*/
	if (first) {
		const char *value = NULL;
		if (var_expand_state_lookup_variable(state, stmt->function,
						     &value, &error) < 0) {
			/* ignore this error now, but leave transfer unset. */
			/* allows default to pick this up */
			var_expand_state_unset_transfer(state);
			i_free(delayed_error);
			delayed_error = i_strdup(error);
		} else {
			i_assert(value != NULL);
			var_expand_state_set_transfer(state, value);
			return TRUE;
		}
	}

	if (var_expand_find_filter(stmt->function, &fn) == 0) {
		int ret;
		T_BEGIN {
			ret = (*fn)(stmt, state, &error);
		} T_END_PASS_STR_IF(ret < 0, &error);
		i_free(delayed_error);
		/* this is to allow e.g. default to work correctly */
		if (ret < 0) {
			var_expand_state_unset_transfer(state);
			if (state->delayed_error != NULL) {
				*error_r = t_strdup(state->delayed_error);
				return FALSE;
			}
			delayed_error =
				i_strdup_printf("%s: %s", stmt->function, error);
		}
		/* this was already handled in the first branch, so just ignore
		   the error here */
	} else if (!first) {
		i_free(delayed_error);
		*error_r = t_strdup_printf("No such function '%s'", stmt->function);
		return FALSE;
	}

	i_free(state->delayed_error);
	state->delayed_error = delayed_error;
	return TRUE;
}
