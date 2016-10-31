#ifndef VAR_EXPAND_H
#define VAR_EXPAND_H

struct var_expand_table {
	char key;
	const char *value;
	const char *long_key;
};

struct var_expand_func_table {
	const char *key;
	/* %{key:data}, or data is "" with %{key}.
	   Returns 1 on success, 0 if data is invalid, -1 on temporary error. */
	int (*func)(const char *data, void *context,
		    const char **value_r, const char **error_r);
};

/* Expand % variables in src and append the string in dest.
   table must end with key = 0. Returns 1 on success, 0 if the format string
   contained invalid/unknown %variables, -1 if one of the functions returned
   temporary error. Even in case of errors the dest string is still written as
   fully as possible. */
int var_expand(string_t *dest, const char *str,
	       const struct var_expand_table *table,
	       const char **error_r);
/* Like var_expand(), but support also callback functions for
   variable expansion. */
int var_expand_with_funcs(string_t *dest, const char *str,
			  const struct var_expand_table *table,
			  const struct var_expand_func_table *func_table,
			  void *func_context, const char **error_r) ATTR_NULL(3, 4, 5);

/* Returns the actual key character for given string, ie. skip any modifiers
   that are before it. The string should be the data after the '%' character.
   For %{long_variable}, '{' is returned. */
char var_get_key(const char *str) ATTR_PURE;
/* Similar to var_get_key(), but works for long keys as well. For single char
   keys size=1, while for e.g. %{key} size=3 and idx points to 'k'. */
void var_get_key_range(const char *str, unsigned int *idx_r,
		       unsigned int *size_r);
/* Returns TRUE if key variable is used in the string.
   If key is '\0', it's ignored. If long_key is NULL, it's ignored. */
bool var_has_key(const char *str, char key, const char *long_key) ATTR_PURE;

#endif
