/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "var-expand.h"

void var_expand(string_t *dest, const char *str,
		const char *user, const char *home)
{
	const char *var;
	unsigned int width;

	for (; *str != '\0'; str++) {
		if (*str != '%')
			str_append_c(dest, *str);
		else {
			width = 0;
			while (str[1] >= '0' && str[1] <= '9') {
				width = width*10 + (str[1] - '0');
				str++;
			}

			switch (str[1]) {
			case '%':
				var = "%";
				break;
			case 'u':
				var = user;
				break;
			case 'h':
				var = home;
				break;
			case 'n':
				var = t_strcut(user, '@');
				break;
			case 'd':
				var = strchr(user, '@');
				if (var != NULL) var++;
				break;
			default:
				str_append_c(dest, '%');
				if (str[1] != '\0')
					str_append_c(dest, str[1]);
				var = NULL;
				break;
			}

			if (str[1] != '\0')
				str++;

			if (var != NULL) {
				if (width == 0)
					str_append(dest, var);
				else
					str_append_n(dest, var, width);
			}
		}
	}
}
