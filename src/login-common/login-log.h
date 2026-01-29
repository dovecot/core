#ifndef LOGIN_LOG_H
#define LOGIN_LOG_H 1

struct login_log_settings {
	struct var_expand_program *program;
	const char *const *template;
	ARRAY_TYPE(const_expansion_program) elements;
};

#endif
