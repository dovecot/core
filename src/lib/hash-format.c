/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "base64.h"
#include "hex-binary.h"
#include "str.h"
#include "hash-method.h"
#include "hash-format.h"

enum hash_encoding {
	HASH_ENCODING_HEX,
	HASH_ENCODING_HEX_SHORT,
	HASH_ENCODING_BASE64
};

struct hash_format_list {
	struct hash_format_list *next;

	const struct hash_method *method;
	void *context;
	unsigned int bits;
	enum hash_encoding encoding;
};

struct hash_format {
	pool_t pool;
	const char *str;

	struct hash_format_list *list, **pos;
};

static int
hash_format_parse(const char *str, unsigned int *idxp,
		  const struct hash_method **method_r,
		  unsigned int *bits_r, const char **error_r)
{
	const char *name, *end, *bitsp;
	unsigned int bits, i = *idxp;

	/* we should have "hash_name}" or "hash_name:bits}" */
	end = strchr(str+i, '}');
	if (end == NULL) {
		*error_r = "Missing '}'";
		return -1;
	}
	*idxp = end - str;
	name = t_strdup_until(str+i, end);

	bitsp = strchr(name, ':');
	if (bitsp != NULL)
		name = t_strdup_until(name, bitsp++);

	*method_r = hash_method_lookup(name);
	if (*method_r == NULL) {
		*error_r = t_strconcat("Unknown hash method: ", name, NULL);
		return -1;
	}

	bits = (*method_r)->digest_size * 8;
	if (bitsp != NULL) {
		if (str_to_uint(bitsp, &bits) < 0 ||
		    bits == 0 || bits > (*method_r)->digest_size*8) {
			*error_r = t_strconcat("Invalid :bits number: ",
					       bitsp, NULL);
			return -1;
		}
		if ((bits % 8) != 0) {
			*error_r = t_strconcat(
				"Currently :bits must be divisible by 8: ",
				bitsp, NULL);
			return -1;
		}
	}
	*bits_r = bits;
	return 0;
}

static int
hash_format_string_analyze(struct hash_format *format, const char *str,
			   const char **error_r)
{
	struct hash_format_list *list;
	unsigned int i;

	for (i = 0; str[i] != '\0'; i++) {
		if (str[i] != '%')
			continue;
		i++;

		list = p_new(format->pool, struct hash_format_list, 1);
		list->encoding = HASH_ENCODING_HEX;
		*format->pos = list;
		format->pos = &list->next;

		if (str[i] == 'B') {
			list->encoding = HASH_ENCODING_BASE64;
			i++;
		} else if (str[i] == 'X') {
			list->encoding = HASH_ENCODING_HEX_SHORT;
			i++;
		}
		if (str[i++] != '{') {
			*error_r = "No '{' after '%'";
			return -1;
		}
		if (hash_format_parse(str, &i, &list->method,
				      &list->bits, error_r) < 0)
			return -1;
		list->context = p_malloc(format->pool,
					 list->method->context_size);
		list->method->init(list->context);
	}
	return 0;
}

int hash_format_init(const char *format_string, struct hash_format **format_r,
		     const char **error_r)
{
	struct hash_format *format;
	pool_t pool;
	int ret;

	pool = pool_alloconly_create("hash format", 1024);
	format = p_new(pool, struct hash_format, 1);
	format->pool = pool;
	format->str = p_strdup(pool, format_string);
	format->pos = &format->list;
	T_BEGIN {
		ret = hash_format_string_analyze(format, format_string,
						 error_r);
		if (ret < 0)
			*error_r = p_strdup(format->pool, *error_r);
	} T_END;
	if (ret < 0) {
		*error_r = t_strdup(*error_r);
		return -1;
	}
	*format_r = format;
	return 0;
}

void hash_format_loop(struct hash_format *format,
		      const void *data, size_t size)
{
	struct hash_format_list *list;

	for (list = format->list; list != NULL; list = list->next)
		list->method->loop(list->context, data, size);
}

static void
hash_format_digest(string_t *dest, const struct hash_format_list *list,
		   const unsigned char *digest)
{
	unsigned int i, orig_len, size = list->bits / 8;
	
	i_assert(list->bits % 8 == 0);

	switch (list->encoding) {
	case HASH_ENCODING_HEX:
		binary_to_hex_append(dest, digest, size);
		break;
	case HASH_ENCODING_HEX_SHORT:
		orig_len = str_len(dest);
		binary_to_hex_append(dest, digest, size);
		/* drop leading zeros, except if it's the only one */
		for (i = orig_len; i < str_len(dest); i++) {
			if (str_data(dest)[i] != '0')
				break;
		}
		if (i == str_len(dest)) i--;
		str_delete(dest, orig_len, i-orig_len);
		break;
	case HASH_ENCODING_BASE64:
		orig_len = str_len(dest);
		base64_encode(digest, size, dest);
		/* drop trailing '=' chars */
		while (str_len(dest) > orig_len &&
		       str_data(dest)[str_len(dest)-1] == '=')
			str_truncate(dest, str_len(dest)-1);
		break;
	}
}

void hash_format_deinit(struct hash_format **_format, string_t *dest)
{
	struct hash_format *format = *_format;
	struct hash_format_list *list;
	const char *p;
	unsigned char *digest;
	unsigned int i, max_digest_size = 0;

	*_format = NULL;

	for (list = format->list; list != NULL; list = list->next) {
		if (max_digest_size < list->method->digest_size)
			max_digest_size = list->method->digest_size;
	}
	digest = p_malloc(format->pool, max_digest_size);

	list = format->list;
	for (i = 0; format->str[i] != '\0'; i++) {
		if (format->str[i] != '%') {
			str_append_c(dest, format->str[i]);
			continue;
		}

		/* we already verified that the string is ok */
		i_assert(list != NULL);
		list->method->result(list->context, digest);
		hash_format_digest(dest, list, digest);
		list = list->next;

		p = strchr(format->str+i, '}');
		i_assert(p != NULL);
		i = p - format->str;
	}

	pool_unref(&format->pool);
}

void hash_format_deinit_free(struct hash_format **_format)
{
	struct hash_format *format = *_format;

	*_format = NULL;
	pool_unref(&format->pool);
}
