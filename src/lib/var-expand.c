/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"

struct var_expand_modifier {
	char key;
	const char *(*func)(const char *);
};

static const struct var_expand_modifier modifiers[] = {
	{ 'L', t_str_lcase },
	{ 'U', t_str_ucase },
	{ 'E', str_escape },
	{ '\0', NULL }
};

void var_expand(string_t *dest, const char *str,
		const struct var_expand_table *table)
{
        const struct var_expand_modifier *m;
        const struct var_expand_table *t;
	const char *var;
	unsigned int width;
	const char *(*modifier)(const char *);

	for (; *str != '\0'; str++) {
		if (*str != '%')
			str_append_c(dest, *str);
		else {
			str++;
			width = 0;
			while (*str >= '0' && *str <= '9') {
				width = width*10 + (*str - '0');
				str++;
			}

			modifier = NULL;
			for (m = modifiers; m->key != '\0'; m++) {
				if (m->key == *str) {
					modifier = m->func;
					str++;
					break;
				}
			}

			if (*str == '\0')
				break;

			var = NULL;
			for (t = table; t->key != '\0'; t++) {
				if (t->key == *str) {
					var = t->value != NULL ? t->value : "";
					break;
				}
			}

			if (var == NULL) {
				/* not found */
				if (*str == '%')
					var = "%";
			}

			if (var != NULL) {
				if (modifier != NULL)
					var = modifier(var);
				if (width == 0)
					str_append(dest, var);
				else
					str_append_n(dest, var, width);
			}
		}
	}
}
