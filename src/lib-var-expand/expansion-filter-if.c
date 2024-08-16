/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "var-expand-private.h"
#include "expansion.h"
#include "wildcard-match.h"

#include <regex.h>

enum var_expand_if_op {
	OP_UNKNOWN,
	OP_NUM_EQ,
	OP_NUM_LT,
	OP_NUM_LE,
	OP_NUM_GT,
	OP_NUM_GE,
	OP_NUM_NE,
/* put all numeric comparisons before this line */
	OP_STR_EQ,
	OP_STR_LT,
	OP_STR_LE,
	OP_STR_GT,
	OP_STR_GE,
	OP_STR_NE,
	OP_STR_LIKE,
	OP_STR_NOT_LIKE,
	OP_STR_REGEXP,
	OP_STR_NOT_REGEXP,
/* keep this as last */
	OP_COUNT
};

static enum var_expand_if_op var_expand_if_str_to_comp(const char *op)
{
	const char *ops[] = {
		NULL,
		"==",
		"<",
		"<=",
		">",
		">=",
		"!=",
		"eq",
		"lt",
		"le",
		"gt",
		"ge",
		"ne",
		"*",
		"!*",
		"~",
		"!~",
	};
	static_assert_array_size(ops, OP_COUNT);
	for (enum var_expand_if_op i = 1; i < OP_COUNT; i++) {
		i_assert(ops[i] != NULL);
		if (strcmp(op, ops[i]) == 0)
			return i;
	}
	return OP_UNKNOWN;
}

static int
fn_if_cmp(struct var_expand_state *state, const struct var_expand_parameter *p_lhs,
	  enum var_expand_if_op op, const struct var_expand_parameter *p_rhs,
	  bool *result_r, const char **error_r)
{
	bool neg = FALSE;
	if (op < OP_STR_EQ) {
		intmax_t a;
		intmax_t b;
		if (var_expand_parameter_number_or_var(state, p_lhs, &a, error_r) < 0) {
			*error_r = t_strdup_printf("Left-hand side: %s", *error_r);
			return -1;
		} else if (var_expand_parameter_number_or_var(state, p_rhs, &b, error_r) < 0) {
			*error_r = t_strdup_printf("Right-hand side: %s", *error_r);
			return -1;
		}
		switch (op) {
		case OP_NUM_EQ:
			*result_r = a == b;
			return 0;
		case OP_NUM_LT:
			*result_r = a < b;
			return 0;
		case OP_NUM_LE:
			*result_r = a <= b;
			return 0;
		case OP_NUM_GT:
			*result_r = a > b;
			return 0;
		case OP_NUM_GE:
			*result_r = a >= b;
			return 0;
		case OP_NUM_NE:
			*result_r = a != b;
			return 0;
		default:
			i_panic("Missing numeric comparator %u", op);
		}
	}

	const char *lhs, *rhs;
	if (var_expand_parameter_string_or_var(state, p_lhs, &lhs, error_r) < 0) {
		*error_r = t_strdup_printf("Left-hand side %s", *error_r);
		return -1;
	} else if (var_expand_parameter_string_or_var(state, p_rhs, &rhs, error_r) < 0) {
		*error_r = t_strdup_printf("Right-hand side %s", *error_r);
		return -1;
	}

	switch (op) {
	case OP_STR_EQ:
		*result_r = strcmp(lhs,rhs) == 0;
		return 0;
	case OP_STR_LT:
		*result_r = strcmp(lhs,rhs) < 0;
		return 0;
	case OP_STR_LE:
		*result_r = strcmp(lhs,rhs) <= 0;
		return 0;
	case OP_STR_GT:
		*result_r = strcmp(lhs,rhs) > 0;
		return 0;
	case OP_STR_GE:
		*result_r = strcmp(lhs,rhs) >= 0;
		return 0;
	case OP_STR_NE:
		*result_r = strcmp(lhs,rhs) != 0;
		return 0;
	case OP_STR_LIKE:
		*result_r = wildcard_match(lhs, rhs);
		return 0;
	case OP_STR_NOT_LIKE:
		*result_r = !wildcard_match(lhs, rhs);
		return 0;
	case OP_STR_NOT_REGEXP:
		neg = TRUE;
		/* fall through */
	case OP_STR_REGEXP: {
		int ec;
		bool res;
		regex_t reg;
		if ((ec = regcomp(&reg, rhs, REG_EXTENDED)) != 0) {
			size_t size;
			char *errbuf;
			size = regerror(ec, &reg, NULL, 0);
			errbuf = t_malloc_no0(size);
			(void)regerror(ec, &reg, errbuf, size);
			*error_r = t_strdup_printf("regexp() failed: %s",
						   errbuf);
			return -1;
		}
		if ((ec = regexec(&reg, lhs, 0, 0, 0)) != 0) {
			i_assert(ec == REG_NOMATCH);
			res = FALSE;
		} else {
			res = TRUE;
		}
		regfree(&reg);
		/* this should be same as neg.
		   if NOT_REGEXP, neg == TRUE and res should be FALSE
		   if REGEXP, ned == FALSE, and res should be TRUE
		 */
		*result_r = res != neg;
		return 0;
	}
	default:
		i_panic("Missing generic comparator %u", op);
	}
}

int expansion_filter_if(const struct var_expand_statement *stmt,
			struct var_expand_state *state,
			const char **error_r)
{
	const char *_op;
	bool use_first_as_lhs = !state->transfer_set;

	const struct var_expand_parameter *p_lhs = NULL;
	const struct var_expand_parameter *p_rhs = NULL;
	const struct var_expand_parameter *p_true = NULL;
	const struct var_expand_parameter *p_false = NULL;

	enum {
		STATE_LHS = 0,
		STATE_OP,
		STATE_RHS,
		STATE_TRUE,
		STATE_FALSE,
		STATE_DONE,
	} parse_state;

	if (use_first_as_lhs)
		parse_state = STATE_LHS;
	else
		parse_state = STATE_OP;

	struct var_expand_parameter_iter_context *ctx =
		var_expand_parameter_iter_init(stmt);
	while (var_expand_parameter_iter_more(ctx)) {
		const struct var_expand_parameter *par =
			var_expand_parameter_iter_next(ctx);
		const char *key = var_expand_parameter_key(par);
		if (key != NULL) {
			ERROR_UNSUPPORTED_KEY(key);
		}
		switch (parse_state) {
		case STATE_LHS:	p_lhs = par; break;
		case STATE_OP:
			if (var_expand_parameter_string_or_var(state, par, &_op, error_r) < 0) {
				*error_r = t_strdup_printf("Comparator: %s", *error_r);
				return -1;
			}
			break;
		case STATE_RHS: p_rhs = par; break;
		case STATE_TRUE: p_true = par; break;
		case STATE_FALSE: p_false = par; break;
		case STATE_DONE: ERROR_TOO_MANY_UNNAMED_PARAMETERS;
		}
		parse_state++;
	}

	if (parse_state != STATE_DONE) {
		*error_r = "Missing parameters";
		return -1;
	}

	enum var_expand_if_op op = var_expand_if_str_to_comp(_op);

	if (op == OP_UNKNOWN) {
		*error_r = t_strdup_printf("Unsupported comparator '%s'", _op);
		return -1;
	}

	if (!use_first_as_lhs) {
		if (var_expand_parameter_from_state(state, op < OP_STR_EQ,
						    &p_lhs) < 0) {
			if (op < OP_STR_EQ) {
				*error_r = "Input is not a number";
			} else  {
				*error_r = "No value to use as left-hand in if";
			}
			return -1;
		}
	}

	i_assert(p_lhs != NULL);

	bool result;
	if (fn_if_cmp(state, p_lhs, op, p_rhs, &result, error_r) < 0)
		return -1;
	const struct var_expand_parameter *res = result ? p_true : p_false;
	const char *value;

	if (var_expand_parameter_any_or_var(state, res, &value, error_r) < 0) {
		*error_r = t_strdup_printf("%s: %s",
					   result ? "True branch" : "False branch",
					   *error_r);
		return -1;
	}

	var_expand_state_set_transfer(state, value);

	return 0;
}
