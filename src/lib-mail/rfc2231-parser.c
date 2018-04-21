/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "rfc822-parser.h"
#include "rfc2231-parser.h"


struct rfc2231_parameter {
	const char *key, *value;
	unsigned int idx;
	bool extended;
};

static int rfc2231_parameter_cmp(const struct rfc2231_parameter *r1,
				 const struct rfc2231_parameter *r2)
{
	int ret;

	ret = strcmp(r1->key, r2->key);
	if (ret != 0)
		return ret;

	return r1->idx < r2->idx ? -1 :
		(r1-> idx > r2->idx ? 1 : 0);
}

static void rfc2231_escape(string_t *dest, const char *src)
{
	for (; *src != '\0'; src++) {
		if (*src == '%')
			str_append(dest, "%25");
		else
			str_append_c(dest, *src);
	}
}

int rfc2231_parse(struct rfc822_parser_context *ctx,
		  const char *const **result_r)
{
	ARRAY_TYPE(const_string) result;
	ARRAY(struct rfc2231_parameter) rfc2231_params_arr;
	struct rfc2231_parameter rfc2231_param;
	const struct rfc2231_parameter *rfc2231_params;
	const char *key, *p, *p2;
	string_t *str;
	unsigned int i, j, count, next, next_idx;
	bool ok, have_extended, broken = FALSE;
	char prev_replacement_char;
	int ret;

	/* Temporarily replace the nul_replacement_char while we're parsing
	   the content-params. It'll be restored before we return. */
	prev_replacement_char = ctx->nul_replacement_char;
	ctx->nul_replacement_char = RFC822_NUL_REPLACEMENT_CHAR;

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
			if (p[1] != '\0') {
				p++;
				rfc2231_param.idx = 0;
				for (; *p >= '0' && *p <= '9'; p++) {
					rfc2231_param.idx =
						rfc2231_param.idx*10 + *p - '0';
				}
			}
			if (*p != '*')
				rfc2231_param.extended = FALSE;
			else {
				rfc2231_param.extended = TRUE;
				p++;
			}
			if (*p != '\0')
				p = NULL;
			else {
				rfc2231_param.key = t_strdup_until(key, p2);
				rfc2231_param.value = t_strdup(str_c(str));
				array_append(&rfc2231_params_arr,
					     &rfc2231_param, 1);
			}
		}
		if (p == NULL) {
			const char *value = t_strdup(str_c(str));
			array_append(&result, &key, 1);
			array_append(&result, &value, 1);
		}
	}
	ctx->nul_replacement_char = prev_replacement_char;

	if (array_count(&rfc2231_params_arr) == 0) {
		/* No RFC 2231 parameters */
		array_append_zero(&result); /* NULL-terminate */
		*result_r = array_idx(&result, 0);
		return broken ? -1 : 0;
	}

	/* Merge the RFC 2231 parameters. Since their order isn't guaranteed to
	   be ascending, start by sorting them. */
	array_sort(&rfc2231_params_arr, rfc2231_parameter_cmp);
	rfc2231_params = array_get(&rfc2231_params_arr, &count);

	/* keys are now sorted primarily by their name and secondarily by
	   their index. If any indexes are missing, fallback to assuming
	   these aren't RFC 2231 encoded parameters. */
	for (i = 0; i < count; i = next) {
		ok = TRUE;
		have_extended = FALSE;
		next_idx = 0;
		for (j = i; j < count; j++) {
			if (strcasecmp(rfc2231_params[i].key,
				       rfc2231_params[j].key) != 0)
				break;
			if (rfc2231_params[j].idx != next_idx) {
				/* missing indexes */
				ok = FALSE;
			}
			if (rfc2231_params[j].extended)
				have_extended = TRUE;
			next_idx++;
		}
		next = j;

		if (!ok) {
			/* missing indexes */
			for (j = i; j < next; j++) {
				key = t_strdup_printf(
					rfc2231_params[j].extended ?
					"%s*%u*" : "%s*%u",
					rfc2231_params[j].key,
					rfc2231_params[j].idx);
				array_append(&result, &key, 1);
				array_append(&result,
					     &rfc2231_params[j].value, 1);
			}
		} else {
			/* everything was successful */
			str_truncate(str, 0);
			if (!rfc2231_params[i].extended && have_extended)
				str_append(str, "''");
			for (j = i; j < next; j++) {
				if (!rfc2231_params[j].extended &&
				    have_extended) {
					rfc2231_escape(str,
						       rfc2231_params[j].value);
				} else {
					str_append(str,
						   rfc2231_params[j].value);
				}
			}
			key = rfc2231_params[i].key;
			if (have_extended)
				key = t_strconcat(key, "*", NULL);
			const char *value = t_strdup(str_c(str));
			array_append(&result, &key, 1);
			array_append(&result, &value, 1);
		}
	}
	array_append_zero(&result); /* NULL-terminate */
	*result_r = array_idx(&result, 0);
	return broken ? -1 : 0;
}
