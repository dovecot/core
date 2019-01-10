/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "var-expand.h"
#include "var-expand-private.h"
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
	const char *ops[OP_COUNT] = {
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
	for(enum var_expand_if_op i = 1; i < OP_COUNT; i++) {
		i_assert(ops[i] != NULL);
		if (strcmp(op, ops[i]) == 0)
			return i;
	}
	return OP_UNKNOWN;
}

static int var_expand_if_comp(const char *lhs, const char *_op, const char *rhs,
			      bool *result_r, const char **error_r)
{
	bool neg = FALSE;
	enum var_expand_if_op op = var_expand_if_str_to_comp(_op);

	*result_r = FALSE;
	if (op == OP_UNKNOWN) {
		*error_r = t_strdup_printf("if: Unsupported comparator '%s'", _op);
		return -1;
	}

	if (op < OP_STR_EQ) {
		intmax_t a;
		intmax_t b;
		if (str_to_intmax(lhs, &a) < 0) {
			*error_r = t_strdup_printf("if: %s (lhs) is not a number", lhs);
			return -1;
		}
		if (str_to_intmax(rhs, &b) < 0) {
			*error_r = t_strdup_printf("if: %s (rhs) is not a number", rhs);
			return -1;
		}
		switch(op) {
		case OP_NUM_EQ:
			*result_r = a==b;
			return 0;
		case OP_NUM_LT:
			*result_r = a<b;
			return 0;
		case OP_NUM_LE:
			*result_r = a<=b;
			return 0;
		case OP_NUM_GT:
			*result_r = a>b;
			return 0;
		case OP_NUM_GE:
			*result_r = a>=b;
			return 0;
		case OP_NUM_NE:
			*result_r = a!=b;
			return 0;
		default:
			i_panic("Missing numeric comparator %u", op);
		}
	}

	switch(op) {
	case OP_STR_EQ:
		*result_r = strcmp(lhs,rhs)==0;
		return 0;
	case OP_STR_LT:
		*result_r = strcmp(lhs,rhs)<0;
		return 0;
	case OP_STR_LE:
		*result_r = strcmp(lhs,rhs)<=0;
		return 0;
	case OP_STR_GT:
		*result_r = strcmp(lhs,rhs)>0;
		return 0;
	case OP_STR_GE:
		*result_r = strcmp(lhs,rhs)>=0;
		return 0;
	case OP_STR_NE:
		*result_r = strcmp(lhs,rhs)!=0;
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
			size_t siz;
			char *errbuf;
			siz = regerror(ec, &reg, NULL, 0);
			errbuf = t_malloc_no0(siz);
			(void)regerror(ec, &reg, errbuf, siz);
			*error_r = t_strdup_printf("if: regex failed: %s",
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

int var_expand_if(struct var_expand_context *ctx,
		  const char *key, const char *field,
		  const char **result_r, const char **error_r)
{
	/* in case the original input had :, we need to fix that
	   by concatenating the key and field together. */
	const char *input = t_strconcat(key, ":", field, NULL);
	const char *p = strchr(input, ';');
	const char *par_end;
	string_t *parbuf;
	const char *const *parms;
	unsigned int depth = 0;
	int ret;
	bool result, escape = FALSE, maybe_var = FALSE;

	if (p == NULL) {
		*error_r = "if: missing parameter(s)";
		return -1;
	}
	ARRAY_TYPE(const_string) params;
	t_array_init(&params, 6);

	parbuf = t_str_new(64);
	/* we need to skip any %{} parameters here, so we can split the string
	   correctly from , without breaking any inner expansions */
	for(par_end = p+1; *par_end != '\0'; par_end++) {
		if (*par_end == '\\') {
			escape = TRUE;
			continue;
		} else if (escape) {
			str_append_c(parbuf, *par_end);
			escape = FALSE;
			continue;
		}
		if (*par_end == '%') {
			maybe_var = TRUE;
		} else if (maybe_var && *par_end == '{') {
			depth++;
			maybe_var = FALSE;
		} else if (depth > 0 && *par_end == '}') {
			depth--;
		} else if (depth == 0 && *par_end == ';') {
			const char *par = str_c(parbuf);
			array_append(&params, &par, 1);
			parbuf = t_str_new(64);
			continue;
		/* if there is a unescaped : at top level it means
		   that the key + arguments end here. it's probably
		   a by-product of the t_strconcat at top of function,
		   which is best handled here. */
		} else if (depth == 0 && *par_end == ':') {
			break;
		}
		str_append_c(parbuf, *par_end);
	}

	if (str_len(parbuf) > 0) {
		const char *par = str_c(parbuf);
		array_append(&params, &par, 1);
	}

	if (array_count(&params) != 5) {
		if (array_count(&params) == 4) {
			const char *empty = "";
			array_append(&params, &empty, 1);
		} else {
			*error_r = t_strdup_printf("if: requires four or five parameters, got %u",
						   array_count(&params));
			return -1;
		}
	}

	array_append_zero(&params);
	parms = array_first(&params);
	t_array_init(&params, 6);

	for(;*parms != NULL; parms++) {
		/* expand the parameters */
		string_t *param = t_str_new(64);
		if ((ret = var_expand_with_funcs(param, *parms, ctx->table,
						 ctx->func_table, ctx->context,
						 error_r)) <= 0) {
			return ret;
		}
		const char *p = str_c(param);
		array_append(&params, &p, 1);
	}

	i_assert(array_count(&params) == 5);

	/* execute comparison */
	const char *const *args = array_first(&params);
	if (var_expand_if_comp(args[0], args[1], args[2], &result, error_r)<0)
		return -1;
	*result_r = result ? args[3] : args[4];
	return 1;
}

