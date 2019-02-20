/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "md5.h"
#include "hash.h"
#include "hex-binary.h"
#include "base64.h"
#include "hostpid.h"
#include "hmac.h"
#include "pkcs5.h"
#include "hash-method.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "var-expand-private.h"

#include <unistd.h>
#include <ctype.h>

#define TABLE_LAST(t) \
	((t)->key == '\0' && (t)->long_key == NULL)

struct var_expand_modifier {
	char key;
	const char *(*func)(const char *, struct var_expand_context *);
};

static ARRAY(struct var_expand_extension_func_table) var_expand_extensions;

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

	if (str_to_ullong(str, &l) < 0)
		l = 0;
	return t_strdup_printf("%llx", l);
}

static const char *
m_str_reverse(const char *str, struct var_expand_context *ctx ATTR_UNUSED)
{
	size_t len = strlen(str);
	char *p, *rev;

	rev = t_malloc_no0(len + 1);
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
m_str_newhash(const char *str, struct var_expand_context *ctx)
{
	string_t *hash = t_str_new(20);
	unsigned char result[MD5_RESULTLEN];
	unsigned int i;
	uint64_t value = 0;

	md5_get_digest(str, strlen(str), result);
	for (i = 0; i < sizeof(value); i++) {
		value <<= 8;
		value |= result[i];
	}

	if (ctx->width != 0) {
		value %= ctx->width;
		ctx->width = 0;
	}

	str_printfa(hash, "%x", (unsigned int)value);
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

	while (*str != '\0') {
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
	size_t len;

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
	{ 'N', m_str_newhash },
	{ 'M', m_str_md5 },
	{ 'D', m_str_ldap_dn },
	{ 'T', m_str_trim },
	{ '\0', NULL }
};

static int
var_expand_short(const struct var_expand_table *table, char key,
		 const char **var_r, const char **error_r)
{
	const struct var_expand_table *t;

	if (table != NULL) {
		for (t = table; !TABLE_LAST(t); t++) {
			if (t->key == key) {
				*var_r = t->value != NULL ? t->value : "";
				return 1;
			}
		}
	}

	/* not found */
	if (key == '%') {
		*var_r = "%";
		return 1;
	}
	if (*error_r == NULL)
		*error_r = t_strdup_printf("Unknown variable '%%%c'", key);
	return 0;
}

static int
var_expand_hash(struct var_expand_context *ctx,
		const char *key, const char *field,
		const char **result_r, const char **error_r)
{
	enum {
		FORMAT_HEX,
		FORMAT_HEX_UC,
		FORMAT_BASE64
	} format = FORMAT_HEX;

	const char *p = strchr(key, ';');
	const char *const *args = NULL;
	const char *algo = key;
	const char *value;
	int ret;

	if (p != NULL) {
		algo = t_strcut(key, ';');
		args = t_strsplit(p+1, ",");
	}

	const struct hash_method *method;
	if (strcmp(algo, "pkcs5") == 0) {
		method = hash_method_lookup("sha256");
	} else if ((method = hash_method_lookup(algo)) == NULL) {
		return 0;
	}

	string_t *field_value = t_str_new(64);
	string_t *salt = t_str_new(64);
	string_t *tmp = t_str_new(method->digest_size);

	if ((ret = var_expand_long(ctx, field, strlen(field),
				   &value, error_r)) < 1) {
		return ret;
	}

	str_append(field_value, value);

	/* default values */
	unsigned int rounds = 1;
	unsigned int truncbits = 0;

	if (strcmp(algo, "pkcs5") == 0) {
		rounds = 2048;
		str_append(salt, field);
	}

	while(args != NULL && *args != NULL) {
		const char *k = t_strcut(*args, '=');
		const char *value = strchr(*args, '=');
		if (value == NULL) {
			args++;
			continue;
		} else {
			value++;
		}
		if (strcmp(k, "rounds") == 0) {
			if (str_to_uint(value, &rounds)<0) {
				*error_r = t_strdup_printf(
					"Cannot parse hash arguments:"
					"'%s' is not number for rounds",
					value);
				return -1;
			}
			if (rounds < 1) {
				*error_r = t_strdup_printf(
					"Cannot parse hash arguments:"
					"rounds must be at least 1");
				return -1;
			}
		} else if (strcmp(k, "truncate") == 0) {
			if (str_to_uint(value, &truncbits)<0) {
				*error_r = t_strdup_printf(
					"Cannot parse hash arguments:"
					"'%s' is not number for truncbits",
					value);
				return -1;
			}
			truncbits = I_MIN(truncbits, method->digest_size*8);
		} else if (strcmp(k, "salt") == 0) {
			str_truncate(salt, 0);
			if (var_expand_with_funcs(salt, value, ctx->table,
						  ctx->func_table, ctx->context,
						  error_r) < 0) {
				return -1;
			}
			break;
		} else if (strcmp(k, "format") == 0) {
			if (strcmp(value, "hex") == 0) {
				format = FORMAT_HEX;
			} else if (strcmp(value, "hexuc") == 0){
				format = FORMAT_HEX_UC;
			} else if (strcmp(value, "base64") == 0) {
				format = FORMAT_BASE64;
			} else {
				*error_r = t_strdup_printf(
					"Cannot parse hash arguments:"
					"'%s' is not supported format",
					value);
				return -1;
			}
		}
		args++;
	}

	str_truncate(tmp, 0);

	if (strcmp(algo, "pkcs5") == 0) {
		if (pkcs5_pbkdf(PKCS5_PBKDF2, method,
				field_value->data, field_value->used,
				salt->data, salt->used,
				rounds, HMAC_MAX_CONTEXT_SIZE, tmp) != 0) {
			*error_r = "Cannot hash: PKCS5_PBKDF2 failed";
			return -1;
		}
	} else {
		void *context = t_malloc_no0(method->context_size);

		str_append_str(tmp, field_value);

		for(;rounds>0;rounds--) {
			method->init(context);
			if (salt->used > 0)
				method->loop(context, salt->data, salt->used);
			method->loop(context, tmp->data, tmp->used);
			unsigned char *digest =
				buffer_get_modifiable_data(tmp, NULL);
			method->result(context, digest);
			if (tmp->used != method->digest_size)
				buffer_set_used_size(tmp, method->digest_size);
		}
	}

	if (truncbits > 0)
		buffer_truncate_rshift_bits(tmp, truncbits);

	switch(format) {
		case FORMAT_HEX:
			*result_r = binary_to_hex(tmp->data, tmp->used);
			return 1;
		case FORMAT_HEX_UC:
			*result_r = binary_to_hex(tmp->data, tmp->used);
			return 1;
		case FORMAT_BASE64: {
			string_t *dest = t_str_new(64);
			base64_encode(tmp->data, tmp->used, dest);
			*result_r = str_c(dest);
			return 1;
		}
	}

	i_unreached();
}

static int
var_expand_func(const struct var_expand_func_table *func_table,
		const char *key, const char *data, void *context,
		const char **var_r, const char **error_r)
{
	const char *value = NULL;
	int ret;

	if (strcmp(key, "env") == 0) {
		value = getenv(data);
		*var_r = value != NULL ? value : "";
		return 1;
	}
	if (func_table != NULL) {
		for (; func_table->key != NULL; func_table++) {
			if (strcmp(func_table->key, key) == 0) {
				ret = func_table->func(data, context, &value, error_r);
				*var_r = value != NULL ? value : "";
				return ret;
			}
		}
	}
	if (*error_r == NULL)
		*error_r = t_strdup_printf("Unknown variable '%%%s'", key);
	*var_r = t_strdup_printf("UNSUPPORTED_VARIABLE_%s", key);
	return 0;
}

static int
var_expand_try_extension(struct var_expand_context *ctx,
			 const char *key, const char *data,
			 const char **var_r, const char **error_r)
{
	int ret;
	const char *sep = strchr(key, ';');

	if (sep == NULL) sep = key + strlen(key);

	/* try with extensions */
	const struct var_expand_extension_func_table *f;
	array_foreach(&var_expand_extensions, f) {
		/* ensure we won't match abbreviations */
		size_t len = sep-key;
		if (strncasecmp(key, f->key, len) == 0 && f->key[len] == '\0')
			return f->func(ctx, key, data, var_r, error_r);
	}
	if ((ret = var_expand_func(ctx->func_table, key, data,
				   ctx->context, var_r, error_r)) == 0) {
		*error_r = t_strdup_printf("Unknown variable '%%%s'", key);
	}
	return ret;
}


int
var_expand_long(struct var_expand_context *ctx,
		const void *key_start, size_t key_len,
		const char **var_r, const char **error_r)
{
	const struct var_expand_table *t;
	const char *key, *value = NULL;
	int ret = 1;

	if (ctx->table != NULL) {
		for (t = ctx->table; !TABLE_LAST(t); t++) {
			if (t->long_key != NULL &&
			    strncmp(t->long_key, key_start, key_len) == 0 &&
			    t->long_key[key_len] == '\0') {
				*var_r = t->value != NULL ? t->value : "";
				return 1;
			}
		}
	}
	key = t_strndup(key_start, key_len);

	/* built-in variables: */
	switch (key_len) {
	case 3:
		if (strcmp(key, "pid") == 0)
			value = my_pid;
		else if (strcmp(key, "uid") == 0)
			value = dec2str(geteuid());
		else if (strcmp(key, "gid") == 0)
			value = dec2str(getegid());
		break;
	case 8:
		if (strcmp(key, "hostname") == 0)
			value = my_hostname;
		break;
	}

	if (value == NULL) {
		const char *data = strchr(key, ':');

		if (data != NULL)
			key = t_strdup_until(key, data++);
		else
			data = "";

		ret = var_expand_try_extension(ctx, key, data, &value, error_r);

		if (ret <= 0 && value == NULL) {
			value = "";
		}
	}
	*var_r = value;
	return ret;
}

int var_expand_with_funcs(string_t *dest, const char *str,
			  const struct var_expand_table *table,
			  const struct var_expand_func_table *func_table,
			  void *context, const char **error_r)
{
	const struct var_expand_modifier *m;
	const char *var;
	struct var_expand_context ctx;
	const char *(*modifier[MAX_MODIFIER_COUNT])
		(const char *, struct var_expand_context *);
	const char *end;
	unsigned int i, modifier_count;
	size_t len;
	int ret, final_ret = 1;

	*error_r = NULL;

	i_zero(&ctx);
	ctx.table = table;
	ctx.func_table = func_table;
	ctx.context = context;

	for (; *str != '\0'; str++) {
		if (*str != '%')
			str_append_c(dest, *str);
		else {
			int sign = 1;

			str++;

			/* reset per-field modifiers */
			ctx.offset = 0;
			ctx.width = 0;
			ctx.zero_padding = FALSE;

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
				ctx.offset = sign * ctx.width;
				sign = 1;
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
				if (*str == '-') {
					sign = -1;
					str++;
				}

				while (*str >= '0' && *str <= '9') {
					ctx.width = ctx.width*10 + (*str - '0');
					str++;
				}
				ctx.width = sign * ctx.width;
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
				unsigned int ctr = 1;
				bool escape = FALSE;
				end = str;
				while(*++end != '\0' && ctr > 0) {
					if (!escape && *end == '\\') {
						escape = TRUE;
						continue;
					}
					if (escape) {
						escape = FALSE;
						continue;
					}
					if (*end == '{') ctr++;
					if (*end == '}') ctr--;
				}
				if (ctr == 0)
					/* it needs to come back a bit */
					end--;
				/* if there is no } it will consume rest of the
				   string */
				len = end - (str + 1);
				ret = var_expand_long(&ctx, str+1, len,
						      &var, error_r);
				i_assert(var != NULL);
				str = end;
			} else {
				ret = var_expand_short(ctx.table, *str,
						       &var, error_r);
			}
			if (final_ret > ret)
				final_ret = ret;

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
				else if (!ctx.zero_padding) {
					if (ctx.width < 0)
						ctx.width = strlen(var) - (-ctx.width);
					str_append_max(dest, var, ctx.width);
				} else {
					/* %05d -like padding. no truncation. */
					ssize_t len = strlen(var);
					while (len < ctx.width) {
						str_append_c(dest, '0');
						ctx.width--;
					}
					str_append(dest, var);
				}
			}
		}
	}
	return final_ret;
}

int var_expand(string_t *dest, const char *str,
	       const struct var_expand_table *table, const char **error_r)
{
	return var_expand_with_funcs(dest, str, table, NULL, NULL, error_r);
}

static bool
var_get_key_range_full(const char *str, unsigned int *idx_r,
		       unsigned int *size_r)
{
	const struct var_expand_modifier *m;
	unsigned int i = 0;

	/* [<offset>.]<width>[<modifiers>]<variable> */
	while ((str[i] >= '0' && str[i] <= '9') || str[i] == '-')
		i++;

	if (str[i] == '.') {
		i++;
		while ((str[i] >= '0' && str[i] <= '9') || str[i] == '-')
			i++;
	}

	do {
		for (m = modifiers; m->key != '\0'; m++) {
			if (m->key == str[i]) {
				i++;
				break;
			}
		}
	} while (m->key != '\0');

	if (str[i] != '{') {
		/* short key */
		*idx_r = i;
		*size_r = str[i] == '\0' ? 0 : 1;
		return FALSE;
	} else {
		unsigned int depth = 1;
		bool escape = FALSE;
		/* long key */
		*idx_r = ++i;
		for (; str[i] != '\0'; i++) {
			if (!escape && str[i] == '\\') {
				escape = TRUE;
				continue;
			}
			if (escape) {
				escape = FALSE;
				continue;
			}
			if (str[i] == '{')
				depth++;
			if (str[i] == '}') {
				if (--depth==0)
					break;
			}
		}
		*size_r = i - *idx_r;
		return TRUE;
	}
}

char var_get_key(const char *str)
{
	unsigned int idx, size;

	if (var_get_key_range_full(str, &idx, &size))
		return '{';
	return str[idx];
}

void var_get_key_range(const char *str, unsigned int *idx_r,
		       unsigned int *size_r)
{
	(void)var_get_key_range_full(str, idx_r, size_r);
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
			if (c == key && key != '\0')
				return TRUE;

			if (c == '{' && long_key != NULL) {
				if (var_has_long_key(&str, long_key))
					return TRUE;
			}
		}
	}
	return FALSE;
}

void var_expand_extensions_deinit(void)
{
	array_free(&var_expand_extensions);
}

void var_expand_extensions_init(void)
{
	i_array_init(&var_expand_extensions, 32);

	/* put all hash methods there */
	for(const struct hash_method **meth = hash_methods;
	    *meth != NULL;
	    meth++) {
		struct var_expand_extension_func_table *func =
			array_append_space(&var_expand_extensions);
		func->key = (*meth)->name;
		func->func = var_expand_hash;
	}

	/* pkcs5 */
	struct var_expand_extension_func_table *func =
		array_append_space(&var_expand_extensions);
	func->key = "pkcs5";
	func->func = var_expand_hash;

	/* if */
	func = array_append_space(&var_expand_extensions);
	func->key = "if";
	func->func = var_expand_if;
}

void
var_expand_register_func_array(const struct var_expand_extension_func_table *funcs)
{
	for(const struct var_expand_extension_func_table *ptr = funcs;
	    ptr->key != NULL;
	    ptr++) {
		i_assert(*ptr->key != '\0');
		array_push_front(&var_expand_extensions, ptr);
	}
}

void
var_expand_unregister_func_array(const struct var_expand_extension_func_table *funcs)
{
	for(const struct var_expand_extension_func_table *ptr = funcs;
	    ptr->key != NULL;
	    ptr++) {
		i_assert(ptr->func != NULL);
		for(unsigned int i = 0; i < array_count(&var_expand_extensions); i++) {
			const struct var_expand_extension_func_table *func =
				array_idx(&var_expand_extensions, i);
			if (strcasecmp(func->key, ptr->key) == 0) {
				array_delete(&var_expand_extensions, i, 1);
			}
		}
	}
}

struct var_expand_table *
var_expand_merge_tables(pool_t pool, const struct var_expand_table *a,
			const struct var_expand_table *b)
{
	ARRAY(struct var_expand_table) table;
	size_t a_size = var_expand_table_size(a);
	size_t b_size = var_expand_table_size(b);
	p_array_init(&table, pool, a_size + b_size + 1);
	for(size_t i=0; i<a_size; i++) {
		struct var_expand_table *entry =
			array_append_space(&table);
		entry->key = a[i].key;
		entry->value = p_strdup(pool, a[i].value);
		entry->long_key = p_strdup(pool, a[i].long_key);
	}
	for(size_t i=0; i<b_size; i++) {
		struct var_expand_table *entry =
			array_append_space(&table);
		entry->key = b[i].key;
		entry->value = p_strdup(pool, b[i].value);
		entry->long_key = p_strdup(pool, b[i].long_key);
	}
	array_append_zero(&table);
	return array_front_modifiable(&table);
}
