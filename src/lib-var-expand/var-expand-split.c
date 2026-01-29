/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "var-expand-private.h"
#include "var-expand-split.h"
#include "expansion.h"

void var_expand_program_template(pool_t pool, const struct var_expand_program *program,
				 const char *placeholder,
			         const char **template_r,
			         ARRAY_TYPE(const_expansion_program) *parts_r)
{
	string_t *dest = str_new(pool, 32);
	while (program != NULL) {
		if (program->only_literal) {
			const char *literal = program->first->params->value.str;
			str_append(dest, literal);
		} else {
			str_append(dest, placeholder);
			array_push_back(parts_r, &program);
		}
		program = program->next;
	}
	*template_r = str_c(dest);
}

void var_expand_program_split(pool_t pool, const struct var_expand_program *program,
			      const char *placeholder, const char *sep,
			      const char *const **template_r,
			      ARRAY_TYPE(const_expansion_program) *parts_r)
{
	ARRAY_TYPE(const_string) literals;
	p_array_init(&literals, pool, 1);
	while (program != NULL) {
		if (program->only_literal) {
			const char *literal = program->first->params->value.str;
			const char *const *split = (const char *const *)
				p_strsplit_spaces(pool, literal, sep);
			array_append(&literals, split, str_array_length(split));
		} else {
			array_push_back(&literals, &placeholder);
			array_push_back(parts_r, &program);
		}
		program = program->next;
	}
	array_append_zero(&literals);
	*template_r = array_idx(&literals, 0);
}
