/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "rfc822-parser.h"
#include "strfuncs.h"
#include "strnum.h"
#include "rfc2231-parser.h"
#include "charset-utf8.h"

#include <limits.h>

/* https://www.rfc-editor.org/rfc/rfc2231
   https://www.rfc-editor.org/rfc/rfc822

   RFC 2231 parameters use key*<n>[*]=value pairs. This means the following
   examples are valid and will produce the same pair key=value0value1value2 (or
   key*=value0value1value2):

    - key*0=value0; key*1=value1; key*2=value2
    - key*2=value2; key*1=value1; key*0=value0
    - key*2*=value2; key*1=value1; key*0*=value0
    - key*=value0value1value2

   In addition, non-extended and non-continued key=value parameters need to
   continue being supported.

   The RFC2231 document calls these indexed parameters "continued
   parameters". We call them indexed here.

   This implementation tries to avoid some pitfalls by putting pairs in two
   groups: 1) the results list and 2) a list of indexed pairs. The former will
   initially contain unextended pairs and extended but unindexed pairs. The
   latter will contain only extended indexed pairs. After merging the extended
   indexed pairs, they will be inserted into the results list if a pair with the
   same key does not already exist in there. This results in some input pairs
   being rejected if the key is a duplicate of one already in the results
   list. In short, this implementation will prefer unindexed parameters over
   indexed ones. Example:

     - key*0=value0; key*=value; key*1=value1   -> key=value
     - key=value; key*=value                    -> key=value
     - key=value; key*0=value0; key*1=value1    -> key=value

   The RFC does not mention much regarding invalid inputs or how to handle
   them. So this implementation does a best-effort "garbage-in garbage-out" sort
   of thing. */

static inline int _decode_hex_digit(const unsigned char digit)
{
	if (digit >= '0' && digit <= '9')
		return digit - '0';
	else if (digit >= 'a' && digit <= 'f')
		return digit - 'a' + 0x0a;
	else if (digit >= 'A' && digit <= 'F')
		return digit - 'A' + 0x0A;
	return -1;
}

static inline bool _decode_percent_encoding(const unsigned char digit_a,
					    const unsigned char digit_b,
					    unsigned char *result_r)
{
	int decoded = _decode_hex_digit(digit_a);
	if (decoded < 0)
		return FALSE;
	*result_r = decoded;
	decoded = _decode_hex_digit(digit_b);
	if (decoded < 0)
		return FALSE;
	*result_r = (*result_r << 4) + decoded;
	return TRUE;
}

static string_t *rfc2231_decode_value(const char *value)
{
	string_t *str = t_str_new(64);
	const char *plast = value;
	const char *p;
	while ((p = strchr(plast, '%')) != NULL) {
		/* Append whatever we've seen so far. */
		str_append_data(str, plast, (p - plast));
		unsigned char ch;
		if (*(p+1) == '\0' || *(p+2) == '\0' ||
		    !_decode_percent_encoding(*(p+1), *(p+2), &ch))
			return NULL;
		plast = p + 3;
		str_append_data(str, &ch, 1);
	}
	/* Append whatever remains. */
	str_append(str, plast);
	return str;
}

struct rfc2231_parameter {
	const char *key, *value;
	unsigned int idx;
	bool extended;
};

static int rfc2231_parameter_cmp(const struct rfc2231_parameter *r1,
				 const struct rfc2231_parameter *r2)
{
	int ret = strcmp(r1->key, r2->key);
	if (ret != 0)
		return ret;
	if (r1->idx < r2->idx)
		return -1;
	else if (r1->idx > r2->idx)
		return 1;
	return 0;
}

static bool result_contains(const ARRAY_TYPE(const_string) *result,
			    const char *key)
{
	unsigned int count;
	const char *const *p = array_get(result, &count);
	i_assert((count % 2) == 0);
	for (unsigned int i = 0; i < count; i += 2) {
		if (strcasecmp(key, p[i]) == 0)
			return TRUE;
	}
	return FALSE;
}

static void result_append(ARRAY_TYPE(const_string) *result,
			  const char *key, const char *value)
{
	if (!result_contains(result, key)) {
		array_push_back(result, &key);
		array_push_back(result, &value);
	}
}

static const char *reconstruct_rfc2231_key(const struct rfc2231_parameter *param,
					   const bool with_extended)
{
	return t_strdup_printf(
		with_extended && param->extended ? "%s*%i*" : "%s*%i",
		param->key,
		param->idx);
}

static const char *find_charset(const char *value, const char **end_r)
{
	/* Note that it is perfectly permissible to leave either the character
	   set or language field blank.  Note also that the single quote
	   delimiters MUST be present even when one of the field values is
	   omitted.  This is done when either character set, language, or both
	   are not relevant to the parameter value at hand. */
	const char *end = strchr(value, '\'');
	if (end == NULL)
		return NULL;
	const char *const charset_r = t_strdup_until(value, end);

	/* We don't do anything with the language info but the format has to be
	   valid, otherwise even the character set - which we have already
	   parsed - is invalid. */
	end = strchr(end + 1, '\'');
	if (end == NULL)
		return NULL;

	*end_r = end + 1;
	return charset_r;
}

static const char *value_to_utf8(const char *charset,
				 const char *value)
{
	string_t *utf8_r = t_str_new(128);
	enum charset_result result;
	if (charset_to_utf8_str(charset, NULL, value, utf8_r, &result) < 0 ||
	    result != CHARSET_RET_OK)
		return NULL;
	return str_c(utf8_r);
}

static const char *rfc2231_decode_charset_value(const char *value,
						const char **charset_r)
{
	if (*charset_r == NULL)
		*charset_r = find_charset(value, &value);

	if (*charset_r != NULL && strcmp(*charset_r, "") != 0) {
		string_t *tmp = rfc2231_decode_value(value);
		const char *decoded = tmp == NULL ? value : str_c(tmp);

		/* Charset is valid and not empty. */
		const char *const utf8 = value_to_utf8(*charset_r, decoded);
		if (utf8 != NULL)
			value = utf8;
	}
	return value;
}

int rfc2231_parse(struct rfc822_parser_context *ctx,
		  const char *const **result_r)
{
	ARRAY_TYPE(const_string) result;
	ARRAY(struct rfc2231_parameter) rfc2231_params_arr;
	struct rfc2231_parameter rfc2231_param;
	const char *key, *p, *p2;
	string_t *str;
	unsigned int i, j, count, next, next_idx;
	bool ok, broken = FALSE;
	const char *prev_replacement_str;
	int ret;

	/* Temporarily replace the nul_replacement_char while we're parsing
	   the content-params. It'll be restored before we return. */
	prev_replacement_str = ctx->nul_replacement_str;
	ctx->nul_replacement_str = RFC822_NUL_REPLACEMENT_STR;

	/* Get a list of all parameters. RFC 2231 uses key*<n>[*]=value pairs,
	   which we want to merge to a key[*]=value pair. Save them to a
	   separate array. */
	i_zero(&rfc2231_param);
	t_array_init(&result, 8);
	t_array_init(&rfc2231_params_arr, 8);
	str = t_str_new(64);
	while ((ret = rfc822_parse_content_param(ctx, &key, str)) != 0) {
		if (ret < 0) {
			/* try to continue anyway.. */
			broken = TRUE;
			if (ctx->data >= ctx->end)
				break;
			ctx->data++;
			continue;
		}
		p = strchr(key, '*');
		if (p != NULL) {
			p2 = p;
			bool is_indexed = str_parse_uint(
				p + 1, &rfc2231_param.idx, &p) != -1;

			if (*p == '*') {
				rfc2231_param.extended = TRUE;
				p++;
			} else {
				rfc2231_param.extended = FALSE;
			}
			if (*p == '\0') {
				const char *tmp_key = t_strdup_until(key, p2);
				const char *tmp_val = t_strdup(str_c(str));

				if (is_indexed) {
					rfc2231_param.key = tmp_key;
					rfc2231_param.value = tmp_val;
					array_push_back(&rfc2231_params_arr,
							&rfc2231_param);
				} else {
					if (rfc2231_param.extended) {
						const char *charset = NULL;
						tmp_val = rfc2231_decode_charset_value(
							tmp_val, &charset);
					}
					result_append(&result, tmp_key, tmp_val);
				}
			} else {
				p = NULL;
			}
		}
		if (p == NULL)
			result_append(&result, key, t_strdup(str_c(str)));
	}
	ctx->nul_replacement_str = prev_replacement_str;

	if (array_count(&rfc2231_params_arr) == 0) {
		/* No RFC 2231 parameters */
		array_append_zero(&result); /* NULL-terminate */
		*result_r = array_front(&result);
		return broken ? -1 : 0;
	}

	/* Sort keys primarily by their name and secondarily by their index. */
	array_sort(&rfc2231_params_arr, rfc2231_parameter_cmp);
	const struct rfc2231_parameter *rfc2231_params =
		array_get(&rfc2231_params_arr, &count);

	/* Merge the RFC 2231 parameters. If any indexes are missing, fallback
	   to assuming these aren't RFC 2231 encoded parameters. */
	for (i = 0; i < count; i = next) {
		ok = TRUE;
		next_idx = 0;
		for (j = i; j < count; j++) {
			if (strcasecmp(rfc2231_params[i].key,
				       rfc2231_params[j].key) != 0)
				break;
			if (rfc2231_params[j].idx != next_idx) {
				/* missing indexes */
				ok = FALSE;
			}
			next_idx++;
		}
		next = j;

		if (!ok) {
			/* Some indexes are missing so we can assume the keys
			   are unindexed but might be extended. */
			for (j = i; j < next; j++) {
				const char *val = rfc2231_params[j].value;
				bool with_extended = TRUE;
				if (rfc2231_params[j].extended) {
					/* Since these values are now assumed to
					   be unrelated - due to their indexing
					   being invalid, we don't really care
					   about the charset being set, or being
					   available only in the first
					   segment. We treat them as unrelated
					   and independent parameters. */
					const char *charset = NULL;
					val = rfc2231_decode_charset_value(val, &charset);
					with_extended = FALSE;
				}
				result_append(
					&result,
					reconstruct_rfc2231_key(
						&rfc2231_params[j],
						with_extended),
					val);
			}
			continue;
		}

		/* we have valid indexing */
		str_truncate(str, 0);

		const char *charset = NULL;
		for (j = i; j < next; j++) {
			const char *val = rfc2231_params[j].value;
			/* We expect rfc2231_params[j]'s value to contain the
			   charset and language info:

			   (4) The first segment of a continuation MUST be
			   encoded if language and character set information are
			   given.

			   (5) If the first segment of a continued parameter
			   value is encoded the language and character set field
			   delimiters MUST be present even when the fields are
			   left blank. */
			if (rfc2231_params[j].extended)
				val = rfc2231_decode_charset_value(val, &charset);
			str_append(str, val);
		}
		key = rfc2231_params[i].key;
		result_append(&result, key, t_strdup(str_c(str)));
	}
	array_append_zero(&result); /* NULL-terminate */
	*result_r = array_front(&result);
	return broken ? -1 : 0;
}
