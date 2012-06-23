#ifndef VAR_EXPAND_H
#define VAR_EXPAND_H

struct var_expand_table {
	char key;
	const char *value;
	const char *long_key;
};

struct var_expand_func_table {
	const char *key;
	/* %{key:data}, or data is "" with %{key}, */
	const char *(*func)(const char *data, void *context);
};

/* Expand % variables in src and append the string in dest.
   table must end with key = 0. */
void var_expand(string_t *dest, const char *str,
		const struct var_expand_table *table);
/* Like var_expand(), but support also callback functions for
   variable expansion. */
void var_expand_with_funcs(string_t *dest, const char *str,
			   const struct var_expand_table *table,
			   const struct var_expand_func_table *func_table,
			   void *func_context) ATTR_NULL(3, 4, 5);

/* Returns the actual key character for given string, ie. skip any modifiers
   that are before it. The string should be the data after the '%' character. */
char var_get_key(const char *str) ATTR_PURE;
/* Similar to var_get_key(), but works for long keys as well. For single char
   keys size=1, while for e.g. %{key} size=3 and idx points to 'k'. */
void var_get_key_range(const char *str, unsigned int *idx_r,
		       unsigned int *size_r);
/* Returns TRUE if key variable is used in the string. long_key may be NULL. */
bool var_has_key(const char *str, char key, const char *long_key) ATTR_PURE;

const struct var_expand_table *
var_expand_table_build(char key, const char *value, char key2, ...);

#endif
