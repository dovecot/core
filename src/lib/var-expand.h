#ifndef __VAR_EXPAND_H
#define __VAR_EXPAND_H

struct var_expand_table {
	char key;
	const char *value;
};

/* Expand % variables in src and append the string in dest.
   table must end with key = 0. */
void var_expand(string_t *dest, const char *str,
		const struct var_expand_table *table);

#endif
