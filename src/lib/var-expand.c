/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "md5.h"
#include "hash.h"
#include "hex-binary.h"
#include "hostpid.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"

#include <stdlib.h>
#include <ctype.h>

#define TABLE_LAST(t) \
	((t)->key == '\0' && (t)->long_key == NULL)

struct var_expand_context {
	int offset;
	unsigned int width;
	bool zero_padding;
};

struct var_expand_modifier {
	char key;
	const char *(*func)(const char *, struct var_expand_context *);
};

static const char *
m_str_lcase(const char *str, struct var_expand_context *ctx ATTR_UNUSED)
{
	return t_str_lcase(str);
}

static const char *
m_str_ucase(const char *str, struct var_expand_context *ctx ATTR_UNUSED)
{
	return t_str_ucase(str);
}

static const char *
m_str_escape(const char *str, struct var_expand_context *ctx ATTR_UNUSED)
{
	return str_escape(str);
}

static const char *
m_str_hex(const char *str, struct var_expand_context *ctx ATTR_UNUSED)
{
	unsigned long long l;

	l = strtoull(str, NULL, 10);
	return t_strdup_printf("%llx", l);
}

static const char *
m_str_reverse(const char *str, struct var_expand_context *ctx ATTR_UNUSED)
{
	size_t len = strlen(str);
	char *p, *rev;

	rev = t_malloc(len + 1);
	rev[len] = '\0';

	for (p = rev + len - 1; *str != '\0'; str++)
		*p-- = *str;
	return rev;
}

static const char *m_str_hash(const char *str, struct var_expand_context *ctx)
{
	unsigned int value = str_hash(str);
	string_t *hash = t_str_new(20);

	if (ctx->width != 0) {
		value %= ctx->width;
		ctx->width = 0;
	}

	str_printfa(hash, "%x", value);
	while ((int)str_len(hash) < ctx->offset)
		str_insert(hash, 0, "0");
        ctx->offset = 0;

	return str_c(hash);
}

static const char *
m_str_md5(const char *str, struct var_expand_context *ctx ATTR_UNUSED)
{
	unsigned char digest[16];

	md5_get_digest(str, strlen(str), digest);

	return binary_to_hex(digest, sizeof(digest));
}

static const char *
m_str_ldap_dn(const char *str, struct var_expand_context *ctx ATTR_UNUSED)
{
	string_t *ret = t_str_new(256);

	while (*str) {
		if (*str == '.')
			str_append(ret, ",dc=");
		else
			str_append_c(ret, *str);
		str++;
	}

	return str_free_without_data(&ret);
}

static const char *
m_str_trim(const char *str, struct var_expand_context *ctx ATTR_UNUSED)
{
	unsigned int len;

	len = strlen(str);
	while (len > 0 && i_isspace(str[len-1]))
		len--;
	return t_strndup(str, len);
}

#define MAX_MODIFIER_COUNT 10
static const struct var_expand_modifier modifiers[] = {
	{ 'L', m_str_lcase },
	{ 'U', m_str_ucase },
	{ 'E', m_str_escape },
	{ 'X', m_str_hex },
	{ 'R', m_str_reverse },
	{ 'H', m_str_hash },
	{ 'M', m_str_md5 },
	{ 'D', m_str_ldap_dn },
	{ 'T', m_str_trim },
	{ '\0', NULL }
};

static const char *
var_expand_long(const struct var_expand_table *table,
		const void *key_start, unsigned int key_len)
{
        const struct var_expand_table *t;
	const char *value = NULL;

	for (t = table; !TABLE_LAST(t); t++) {
		if (t->long_key != NULL &&
		    strncmp(t->long_key, key_start, key_len) == 0 &&
		    t->long_key[key_len] == '\0') {
			return t->value != NULL ? t->value : "";
		}
	}

	/* built-in variables: */
	T_BEGIN {
		const char *key = t_strndup(key_start, key_len);

		switch (key_len) {
		case 3:
			if (strcmp(key, "pid") == 0)
				value = my_pid;
			break;
		case 8:
			if (strcmp(key, "hostname") == 0)
				value = my_hostname;
			break;
		}
		if (strncmp(key, "env:", 4) == 0)
			value = getenv(key + 4);
	} T_END;
	return value;
}

void var_expand(string_t *dest, const char *str,
		const struct var_expand_table *table)
{
        const struct var_expand_modifier *m;
        const struct var_expand_table *t;
	const char *var;
        struct var_expand_context ctx;
	const char *(*modifier[MAX_MODIFIER_COUNT])
		(const char *, struct var_expand_context *);
	const char *end;
	unsigned int i, len, modifier_count;

	memset(&ctx, 0, sizeof(ctx));
	for (; *str != '\0'; str++) {
		if (*str != '%')
			str_append_c(dest, *str);
		else {
			int sign = 1;

			str++;
			memset(&ctx, 0, sizeof(ctx));

			/* [<offset>.]<width>[<modifiers>]<variable> */
			if (*str == '-') {
				sign = -1;
				str++;
			}
			if (*str == '0') {
				ctx.zero_padding = TRUE;
				str++;
			}
			while (*str >= '0' && *str <= '9') {
				ctx.width = ctx.width*10 + (*str - '0');
				str++;
			}

			if (*str == '.') {
				ctx.offset = sign * (int)ctx.width;
				ctx.width = 0;
				str++;

				/* if offset was prefixed with zero (or it was
				   plain zero), just ignore that. zero padding
				   is done with the width. */
				ctx.zero_padding = FALSE;
				if (*str == '0') {
					ctx.zero_padding = TRUE;
					str++;
				}

				while (*str >= '0' && *str <= '9') {
					ctx.width = ctx.width*10 + (*str - '0');
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
			if (*str == '{' && (end = strchr(str, '}')) != NULL) {
				/* %{long_key} */
				len = end - (str + 1);
				var = var_expand_long(table, str+1, len);
				if (var != NULL)
					str = end;
			} else {
				for (t = table; !TABLE_LAST(t); t++) {
					if (t->key == *str) {
						var = t->value != NULL ?
							t->value : "";
						break;
					}
				}
			}

			if (var == NULL) {
				/* not found */
				if (*str == '%')
					var = "%";
			}

			if (var != NULL) {
				for (i = 0; i < modifier_count; i++)
					var = modifier[i](var, &ctx);

				if (ctx.offset < 0) {
					/* if offset is < 0 then we want to
					   start at the end */
					size_t len = strlen(var);

					if (len > (size_t)-ctx.offset)
						var += len + ctx.offset;
				} else {
					while (*var != '\0' && ctx.offset > 0) {
						ctx.offset--;
						var++;
					}
				}
				if (ctx.width == 0)
					str_append(dest, var);
				else if (!ctx.zero_padding)
					str_append_n(dest, var, ctx.width);
				else {
					/* %05d -like padding. no truncation. */
					size_t len = strlen(var);
					while (len < ctx.width) {
						str_append_c(dest, '0');
						ctx.width--;
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
	while ((*str >= '0' && *str <= '9') || *str == '-')
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

static bool var_has_long_key(const char **str, const char *long_key)
{
	const char *start, *end;

	start = strchr(*str, '{');
	i_assert(start != NULL);

	end = strchr(++start, '}');
	if (end == NULL)
		return FALSE;

	if (strncmp(start, long_key, end-start) == 0 &&
	    long_key[end-start] == '\0')
		return TRUE;

	*str = end;
	return FALSE;
}

bool var_has_key(const char *str, char key, const char *long_key)
{
	char c;

	for (; *str != '\0'; str++) {
		if (*str == '%' && str[1] != '\0') {
			str++;
			c = var_get_key(str);
			if (c == key)
				return TRUE;

			if (c == '{' && long_key != NULL) {
				if (var_has_long_key(&str, long_key))
					return TRUE;
			}
		}
	}
	return FALSE;
}

const struct var_expand_table *
var_expand_table_build(char key, const char *value, char key2, ...)
{
	ARRAY_DEFINE(variables, struct var_expand_table);
	struct var_expand_table *var;
	va_list args;

	i_assert(key != '\0');

	t_array_init(&variables, 16);
	var = array_append_space(&variables);
	var->key = key;
	var->value = value;

	va_start(args, key2);
	for (key = key2; key != '\0'; key = va_arg(args, int)) {
		var = array_append_space(&variables);
		var->key = key;
		var->value = va_arg(args, const char *);
	}
	va_end(args);

	/* 0, NULL entry */
	(void)array_append_space(&variables);
	return array_idx(&variables, 0);
}
