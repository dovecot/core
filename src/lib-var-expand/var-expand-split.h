#ifndef VAR_EXPAND_SPLIT_H
#define VAR_EXPAND_SPLIT_H 1

ARRAY_DEFINE_TYPE(const_expansion_program, const struct var_expand_program*);

void var_expand_program_split(pool_t pool, const struct var_expand_program *program,
			      const char *placeholder, const char *sep,
			      const char *const **template_r,
			      ARRAY_TYPE(const_expansion_program) *parts_r);

void var_expand_program_template(pool_t pool, const struct var_expand_program *program,
			         const char *placeholder,
			         const char **template_r,
			         ARRAY_TYPE(const_expansion_program) *parts_r);

#endif
