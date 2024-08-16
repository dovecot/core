#ifndef VAR_EXPAND_PARSER_PRIVATE_H
#define VAR_EXPAND_PARSER_PRIVATE_H 1

#define VAR_EXPAND_PARSER_STYPE struct var_expand_parser_state
struct var_expand_parser_state {
	pool_t pool;
        const char *input;
	size_t left;
        size_t input_pos;
	string_t *str;
	void* scanner;

	struct var_expand_program *plist;
	struct var_expand_program *pp;
	struct var_expand_program *p;
	bool failed;
	const char *error;

	/* temp vars */
	struct var_expand_parameter *params;
	int idx;
	const char *funcname;
	const char *key;
	const char *value;
	enum var_expand_statement_operator oper;
	intmax_t number;
	ARRAY_TYPE(const_string) variables;
};

#endif
