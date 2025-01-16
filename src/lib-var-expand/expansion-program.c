/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
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

/* Export code */

/* Encodes numbers in 7-bit bytes, using 8th to indicate
   that the number continues. Uses little endian encoding
   to allow this. */
static void export_number(string_t *dest, intmax_t number)
{
	unsigned char b;

	/* fast path - store any non-negative number that's smaller than
	   127 as number + 1, including 0. */
	if (number >= 0 && number < 0x7f) {
		b = number + 1;
		str_append_c(dest, b);
		return;
	}

	/* Store sign with 0x80, so we can differentiate
	   from fast path. */
	if (number < 0) {
		str_append_c(dest, 0x80 | '-');
		number = -number;
	} else
		str_append_c(dest, 0x80 | '+');

	/* Store the number in 7 byte chunks
	   so we can use the 8th bit for indicating
	   whether the number continues. */
	while (number > 0) {
		if (number > 0x7f)
			b = 0x80;
		else
			b = 0x0;
		b |= number & 0x7f;
		number >>= 7;
		str_append_c(dest, b);
	}
}

static void var_expand_program_export_one(const struct var_expand_program *program,
					  string_t *dest)
{
	const struct var_expand_statement *stmt = program->first;
	while (stmt != NULL) {
		str_append(dest, stmt->function);
		str_append_c(dest, '\1');
		const struct var_expand_parameter *param = stmt->params;
		while (param != NULL) {
			if (param->key != NULL)
				str_append(dest, param->key);
			str_append_c(dest, '\1');
			switch (param->value_type) {
			case VAR_EXPAND_PARAMETER_VALUE_TYPE_STRING:
				str_append_c(dest, 's');
				str_append_tabescaped(dest, param->value.str);
				str_append_c(dest, '\r');
				break;
			case VAR_EXPAND_PARAMETER_VALUE_TYPE_INT:
				str_append_c(dest, 'i');
				export_number(dest, param->value.num);
				break;
			case VAR_EXPAND_PARAMETER_VALUE_TYPE_VARIABLE:
				str_append_c(dest, 'v');
				str_append_tabescaped(dest, param->value.str);
				str_append_c(dest, '\r');
				break;
			default:
				i_unreached();
			}
			param = param->next;
			if (param != NULL)
				str_append_c(dest, '\1');
		}
		str_append_c(dest, '\t');
		stmt = stmt->next;
		if (stmt != NULL)
			str_append_c(dest, '\1');
		else
			str_append_c(dest, '\t');
	}
	const char *const *vars = program->variables;

	for (; vars != NULL && *vars != NULL; vars++) {
		/* ensure variable has no \1 in name */
		i_assert(strchr(*vars, '\1') == NULL);
		str_append(dest, *vars);
		str_append_c(dest, '\1');
	}
	str_append_c(dest, '\t');
}

void var_expand_program_export_append(string_t *dest,
				      const struct var_expand_program *program)
{
	i_assert(program != NULL);
	i_assert(dest != NULL);

	while (program != NULL) {
		if (program->only_literal) {
			i_assert(program->first->params->value_type ==
				 VAR_EXPAND_PARAMETER_VALUE_TYPE_STRING);
			str_append_c(dest, '\1');
			str_append_tabescaped(dest, program->first->params->value.str);
			str_append_c(dest, '\r');
		} else {
			str_append_c(dest, '\2');
			var_expand_program_export_one(program, dest);
		}

		program = program->next;
	}
}

const char *var_expand_program_export(const struct var_expand_program *program)
{
	string_t *dest = t_str_new(64);
	var_expand_program_export_append(dest, program);
	return str_c(dest);
}

/* Import code */

static int extract_name(char *data, size_t size,
			const char **value_r, const char **error_r)
{
	char *ptr = memchr(data, '\1', size);
	if (ptr == NULL) {
		*error_r = "Missing end of name";
		return -1;
	}
	size_t len = ptr - data;
	if (len == 0) {
		*value_r = NULL;
		return 1;
	}
	*value_r = data;
	*ptr = '\0';
	return len + 1;

}

static int extract_value(char *data, size_t size,
			 const char **value_r, const char **error_r)
{
	char *ptr = memchr(data, '\r', size);
	if (ptr == NULL) {
		*error_r = "Missing end of string";
		return -1;
	}
	size_t len = ptr - data;
	*ptr = '\0';
	*value_r = str_tabunescape(data);
	/* make sure we end up in right place. */
	return len + 1;
}

static int extract_number(const char *data, size_t size, intmax_t *value_r,
			  const char **error_r)
{
	const unsigned char *ptr = (const unsigned char*)data;
	bool negative;
	size_t len = 1;

	if ((*ptr & 0x80) == 0) {
		/* fast path for small positive number */
		intmax_t number = *ptr;
		*value_r = number - 1;
		return 1;
	}

	const char sign = *ptr - 0x80;
	if (sign == '+') {
		negative = FALSE;
	} else if (sign == '-') {
		negative = TRUE;
	} else {
		*error_r = "Unknown number";
		return -1;
	}
	ptr++;

	intmax_t value = 0;
	intmax_t shift = 0;

	/* a number can be at most 9 bytes */
	for (size_t i = 0; i < I_MIN(size, 9); i++) {
		len++;
		value |= ((*(ptr) & 0x7fLL) << shift);
		/* if high byte is set, the number continues */
		if ((*ptr & 0x80) == 0)
			break;
		shift += 7;
		ptr++;
	}

	if ((*ptr & 0x80) != 0) {
		*error_r = "Unfinished number";
		return -1;
	}

	if (negative)
		value = -value;

	*value_r = value;

	return len;
}

#define ADVANCE_INPUT(count) \
	if (unlikely(size < (size_t)count)) { \
		*error_r = "Premature end of data"; \
		return -1; \
	}\
	data = data + (count); \
	size = size - (size_t)(count);

static int var_expand_program_import_stmt(char *data, size_t size,
					  struct var_expand_program *program,
					  const char **error_r)
{
	const char *name;
	const char *value;
	size_t orig_size = size;

	/* normal program, starts with filter name */
	int ret = extract_name(data, size, &name, error_r);
	if (ret < 0)
		return -1;
	if (name == NULL) {
		*error_r = "missing function name";
		return -1;
	}
	ADVANCE_INPUT(ret);

	struct var_expand_statement *stmt =
		p_new(program->pool, struct var_expand_statement, 1);

	if (program->first == NULL)
		program->first = stmt;
	else {
		 struct var_expand_statement *ptr = program->first;
		 while (ptr->next != NULL) ptr = ptr->next;
		 ptr->next = stmt;
	}

	stmt->function = name;
	struct var_expand_parameter *prev = NULL;
	int idx = -1;

	while (size > 0 && *data != '\t') {
		struct var_expand_parameter *param =
			p_new(program->pool, struct var_expand_parameter, 1);
		/* check if it's named parameter */
		if (*data == '\1') {
			param->idx = ++idx;
			ADVANCE_INPUT(1);
		} else {
			ret = extract_name(data, size,
					   &name, error_r);
			if (ret < 0)
				return -1;
			ADVANCE_INPUT(ret);
			param->key = name;
		}

		/* check the parameter type */
		switch (*data) {
		case 's':
			param->value_type =
				VAR_EXPAND_PARAMETER_VALUE_TYPE_STRING;
			break;
		case 'i':
			param->value_type =
				VAR_EXPAND_PARAMETER_VALUE_TYPE_INT;
			break;
		case 'v':
			param->value_type =
				VAR_EXPAND_PARAMETER_VALUE_TYPE_VARIABLE;
			break;
		default:
			*error_r = "Unsupported parameter type";
			return -1;
		}
		ADVANCE_INPUT(1);

		if (param->value_type == VAR_EXPAND_PARAMETER_VALUE_TYPE_STRING ||
		    param->value_type == VAR_EXPAND_PARAMETER_VALUE_TYPE_VARIABLE) {
			ret = extract_value(data, size,
					    &value, error_r);
			if (ret < 0)
				return -1;
			ADVANCE_INPUT(ret);
			param->value.str = value;
		} else if (param->value_type == VAR_EXPAND_PARAMETER_VALUE_TYPE_INT) {
			ret = extract_number(data, size, &param->value.num,
					     error_r);
			if (ret < 0)
				return -1;

			ADVANCE_INPUT(ret);
		} else {
			*error_r = "Unsupported value type";
			return -1;
		}

		if (prev == NULL)
			stmt->params = param;
		else
			prev->next = param;
		prev = param;

		if (*data == '\t') {
			break;
		} else if (*data == '\1') {
			ADVANCE_INPUT(1);
		} else {
			*error_r = "Missing parameter end";
			return -1;
		}
	}

	if (*data != '\t')
		*error_r = "Missing parameter statement end";

	ADVANCE_INPUT(1);

	return orig_size - size;
}

static int var_expand_program_import_one(char **_data, size_t *_size,
					 struct var_expand_program *program,
					 const char **error_r)
{
	char *data = *_data;
	size_t size = *_size;
	const char *value;
	int ret;

	/* Only literal */
	if (*data == '\1') {
		ADVANCE_INPUT(1);
		ret = extract_value(data, size, &value, error_r);
		if (ret < 0)
			return -1;
		ADVANCE_INPUT(ret);

		/* just literal data */
		struct var_expand_statement *stmt =
			p_new(program->pool, struct var_expand_statement, 1);
		struct var_expand_parameter *param =
			p_new(program->pool, struct var_expand_parameter, 1);
		param->idx = 0;
		param->value_type = VAR_EXPAND_PARAMETER_VALUE_TYPE_STRING;
		param->value.str = value;
		stmt->params = param;
		stmt->function = "literal";
		program->first = stmt;
		program->only_literal = TRUE;
	/* A full program */
	} else if (*data == '\2') {
		ADVANCE_INPUT(1);
		while (*data != '\t' && size > 0) {
			int ret = var_expand_program_import_stmt(data, size, program, error_r);
			if (ret < 0)
				return -1;
			ADVANCE_INPUT(ret);
			if (*data == '\t') {
				ADVANCE_INPUT(1);
				break;
			} else if (*data != '\1') {
				*error_r = "Missing statement end";
				return -1;
			}
			ADVANCE_INPUT(1);
		}
		/* And finally there should be variables */
		if (*data != '\t') {
			const char *ptr = memchr(data, '\t', size);
			if (ptr == NULL) {
				*error_r = "Missing variables end";
				return -1;
			}
			size_t len = ptr - data;
			program->variables = (const char *const *)
				p_strsplit(program->pool, data, "\1");
			ADVANCE_INPUT(len + 1);
		} else {
			ADVANCE_INPUT(1);
		}
	} else {
		*error_r = "Unknown input";
		return -1;
	}
	*_data = data;
	*_size = size;

	return 0;
}

int var_expand_program_import_sized(const char *data, size_t size,
				    struct var_expand_program **program_r,
				    const char **error_r)
{
	i_assert(data != NULL);

	/* The absolute minimum program is \2 \t or \1 \r. */
	if (size < 2) {
		*error_r = "Too short";
		return -1;
	}

	pool_t pool = pool_alloconly_create(MEMPOOL_GROWING"var expand program", size);
	struct var_expand_program *prev = NULL;
	struct var_expand_program *first = NULL;
	int ret;
	char *copy_data = p_strndup(pool, data, size);

	while (size > 0) {
		struct var_expand_program *program =
			p_new(pool, struct var_expand_program, 1);
		program->pool = pool;
		T_BEGIN {
			ret = var_expand_program_import_one(&copy_data, &size,
							    program, error_r);
		} T_END;
		if (ret < 0)
			break;
		if (first == NULL)
			first = program;
		if (prev != NULL)
			prev->next = program;
		prev = program;
	}

	if (ret < 0)
		pool_unref(&pool);
	else
		*program_r = first;

	return ret;
}

int var_expand_program_import(const char *data,
			      struct var_expand_program **program_r,
			      const char **error_r)
{
	i_assert(data != NULL);
	return var_expand_program_import_sized(data, strlen(data), program_r,
					       error_r);
}
