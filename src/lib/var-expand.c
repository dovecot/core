/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"

#include <stdlib.h>

struct var_expand_modifier {
	char key;
	const char *(*func)(const char *);
};

static const char *str_hex(const char *str)
{
	unsigned long long l;

	l = strtoull(str, NULL, 10);
	return t_strdup_printf("%llx", l);
}

#define MAX_MODIFIER_COUNT 10
static const struct var_expand_modifier modifiers[] = {
	{ 'L', t_str_lcase },
	{ 'U', t_str_ucase },
	{ 'E', str_escape },
	{ 'X', str_hex },
	{ '\0', NULL }
};

void var_expand(string_t *dest, const char *str,
		const struct var_expand_table *table)
{
        const struct var_expand_modifier *m;
        const struct var_expand_table *t;
	const char *var;
	unsigned int offset, width;
	const char *(*modifier[MAX_MODIFIER_COUNT])(const char *);
	unsigned int i, modifier_count;
	int zero_padding = FALSE;

	for (; *str != '\0'; str++) {
		if (*str != '%')
			str_append_c(dest, *str);
		else {
			str++;

			/* [<offset>.]<width>[<modifiers>]<variable> */
			width = 0;
			if (*str == '0') {
				zero_padding = TRUE;
				str++;
			}
			while (*str >= '0' && *str <= '9') {
				width = width*10 + (*str - '0');
				str++;
			}

			if (*str != '.')
				offset = 0;
			else {
				offset = width;
				width = 0;
				str++;
				while (*str >= '0' && *str <= '9') {
					width = width*10 + (*str - '0');
					str++;
				}
			}

                        modifier_count = 0;
			while (modifier_count < MAX_MODIFIER_COUNT) {
				modifier[modifier_count] = NULL;
				for (m = modifiers; m->key != '\0'; m++) {
					if (m->key == *str) {
						/* @UNSAFE */
						modifier[modifier_count] =
							m->func;
						str++;
						break;
					}
				}
				if (modifier[modifier_count] == NULL)
					break;
				modifier_count++;
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
				for (; *var != '\0' && offset > 0; offset--)
					var++;
				for (i = 0; i < modifier_count; i++)
					var = modifier[i](var);
				if (width == 0)
					str_append(dest, var);
				else if (!zero_padding)
					str_append_n(dest, var, width);
				else {
					/* %05d -like padding */
					size_t len = strlen(var);
					while (len < width) {
						str_append_c(dest, '0');
						width--;
					}
					str_append(dest, var);
				}
			}
		}
	}
}

char var_get_key(const char *str)
{
	const struct var_expand_modifier *m;

	/* [<offset>.]<width>[<modifiers>]<variable> */
	while (*str >= '0' && *str <= '9')
		str++;

	if (*str == '.') {
		str++;
		while (*str >= '0' && *str <= '9')
			str++;
	}

	do {
		for (m = modifiers; m->key != '\0'; m++) {
			if (m->key == *str) {
				str++;
				break;
			}
		}
	} while (m->key != '\0');

	return *str;
}
