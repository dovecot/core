/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "base64.h"
#include "hash-method.h"
#include "hex-binary.h"
#include "str.h"
#include "strescape.h"
#include "str-sanitize.h"
#include "var-expand-private.h"
#include "expansion.h"

#include <ctype.h>
#include <regex.h>

ARRAY_DEFINE_TYPE(var_expand_filter, struct var_expand_filter);
static ARRAY_TYPE(var_expand_filter) dyn_filters = ARRAY_INIT;

static int fn_lookup(const struct var_expand_statement *stmt,
		     struct var_expand_state *state, const char **error_r)
{
	const struct var_expand_parameter *par = stmt->params;
	if (par == NULL) {
		*error_r = "Missing name to lookup";
		return -1;
	}

	const char *key = var_expand_parameter_key(par);
	if (key != NULL)
		ERROR_UNSUPPORTED_KEY(key);

	var_expand_state_unset_transfer(state);

	const char *value;
	if (var_expand_parameter_string_or_var(state, par, &key, error_r) < 0)
		return -1;

	if (var_expand_state_lookup_variable(state, key, &value, error_r) == 0) {
		var_expand_state_set_transfer(state, value);
		return 0;
	} else {
		return -1;
	}
}

static int fn_lower(const struct var_expand_statement *stmt,
		    struct var_expand_state *state, const char **error_r)
{
	ERROR_IF_ANY_PARAMETERS;
	ERROR_IF_NO_TRANSFER_TO("lower");

	char *value = str_c_modifiable(state->transfer);
	str_lcase(value);
	return 0;
}

static int fn_upper(const struct var_expand_statement *stmt,
		    struct var_expand_state *state, const char **error_r)
{
	ERROR_IF_ANY_PARAMETERS;
	ERROR_IF_NO_TRANSFER_TO("upper");

	char *value = str_c_modifiable(state->transfer);
	str_ucase(value);
	return 0;
}

static int fn_default(const struct var_expand_statement *stmt,
		      struct var_expand_state *state, const char **error_r)
{
	if (state->transfer_set && state->transfer->used > 0)
		return 0;

	/* allow default without parameters to expand into literal empty */
	const char *value;
	const char *key;
	if (stmt->params == NULL)
		value = "";
	else if ((key = var_expand_parameter_key(stmt->params)) != NULL)
		ERROR_UNSUPPORTED_KEY(key);
	else if (var_expand_parameter_any_or_var(state, stmt->params, &value,
						   error_r) < 0)
		return -1;
	else if (stmt->params->next != NULL)
		ERROR_TOO_MANY_UNNAMED_PARAMETERS;

	var_expand_state_set_transfer(state, value);

	return 0;
}

static int fn_literal(const struct var_expand_statement *stmt,
		      struct var_expand_state *state,
		      const char **error_r)
{
	const char *value;

	ERROR_IF_NO_PARAMETERS;
	const char *key = var_expand_parameter_key(stmt->params);
	if (key != NULL)
		ERROR_UNSUPPORTED_KEY(key);

	if (var_expand_parameter_any_or_var(state, stmt->params, &value, error_r) < 0)
		return -1;
	var_expand_state_set_transfer(state, value);
	return 0;
}

static int fn_calculate(const struct var_expand_statement *stmt,
			struct var_expand_state *state, const char **error_r)
{
	ERROR_IF_NO_PARAMETERS;

	struct var_expand_parameter_iter_context *ctx =
		var_expand_parameter_iter_init(stmt);

	enum var_expand_statement_operator oper =
		VAR_EXPAND_STATEMENT_OPER_COUNT;
	intmax_t right;

	while (var_expand_parameter_iter_more(ctx)) {
		const struct var_expand_parameter *par =
			var_expand_parameter_iter_next(ctx);
		const char *key = var_expand_parameter_key(par);
		if (key != NULL)
			ERROR_UNSUPPORTED_KEY(key);

		switch (var_expand_parameter_idx(par)) {
		case 0:
			if (var_expand_parameter_number(par, FALSE, &right) < 0) {
				*error_r = "Missing operator";
				return -1;
			}
			oper = right;
			break;
		case 1:
			if (var_expand_parameter_number_or_var(state, par, &right,
							       error_r) < 0)
				return -1;
			break;
		default:
			ERROR_TOO_MANY_UNNAMED_PARAMETERS;
		}
	}

	ERROR_IF_NO_TRANSFER_TO("calculate");
	intmax_t value;

	/* special case for the society of config file prettification:
	   binary input can be treated as 64 bit unsigned integer
	   for modulo operations only. */
	if (state->transfer_binary && oper == VAR_EXPAND_STATEMENT_OPER_MODULO) {
		if (right < 0) {
			*error_r = "Binary modulo must be positive integer";
			return -1;
		}
		uintmax_t tmp = 0;
		const unsigned char *input = state->transfer->data;
		for (size_t i = state->transfer->used - I_MIN(state->transfer->used, sizeof(tmp));
		     i < state->transfer->used; i++) {
			tmp <<= 8;
			tmp |= input[i];
		}
		tmp %= right;
		var_expand_state_set_transfer(state, dec2str(tmp));
		return 0;
	}

	/* transfer must be number */
	if (str_to_intmax(str_c(state->transfer), &value) < 0) {
		*error_r = "Input is not a number";
		return -1;
	}

	switch (oper) {
	case VAR_EXPAND_STATEMENT_OPER_PLUS:
		value += right;
		break;
	case VAR_EXPAND_STATEMENT_OPER_MINUS:
		value -= right;
		break;
	case VAR_EXPAND_STATEMENT_OPER_STAR:
		value *= right;
		break;
	case VAR_EXPAND_STATEMENT_OPER_SLASH:
		if (right == 0) {
			*error_r = "Division by zero";
			return -1;
		}
		value /= right;
		break;
	case VAR_EXPAND_STATEMENT_OPER_MODULO:
		if (right == 0) {
			*error_r = "Modulo by zero";
			return -1;
		}
		value %= right;
		break;
	case VAR_EXPAND_STATEMENT_OPER_COUNT:
	default:
		i_unreached();
	}

	/* Should usually use var_expand_state_set_transfer
	   but this way it avoids a t_strdup_printf round. */
	var_expand_state_unset_transfer(state);
	str_printfa(state->transfer, "%jd", value);
	state->transfer_set = TRUE;
	return 0;
}

static int fn_concat(const struct var_expand_statement *stmt,
		     struct var_expand_state *state, const char **error_r)
{
	ERROR_IF_NO_PARAMETERS;

	string_t *result = t_str_new(32);

	/* start with transfer */
	if (state->transfer_set)
		str_append_data(result, state->transfer->data, state->transfer->used);

	struct var_expand_parameter_iter_context *ctx =
		var_expand_parameter_iter_init(stmt);

	while (var_expand_parameter_iter_more(ctx)) {
		const struct var_expand_parameter *par =
			var_expand_parameter_iter_next(ctx);
		const char *value;
		const char *key = var_expand_parameter_key(par);
		if (key != NULL)
			ERROR_UNSUPPORTED_KEY(key);
		if (var_expand_parameter_any_or_var(state, par, &value, error_r) < 0)
			return -1;
		str_append(result, value);
	}

	var_expand_state_set_transfer_data(state, result->data, result->used);
	return 0;
}

static int fn_hash_algo(const struct var_expand_statement *stmt, const char *algo,
			bool algo_from_param, struct var_expand_state *state,
			const char **error_r)
{
	const struct hash_method *method;

	method = hash_method_lookup(algo);
	if (method == NULL) {
		*error_r = t_strdup_printf("Unsupported algorithm '%s'",
					   algo);
		return -1;
	}

	intmax_t rounds = 1;
	const char *salt = "";

	struct var_expand_parameter_iter_context * ctx =
		var_expand_parameter_iter_init(stmt);
	while (var_expand_parameter_iter_more(ctx)) {
		const struct var_expand_parameter *par =
			var_expand_parameter_iter_next(ctx);
		const char *key = var_expand_parameter_key(par);
		/* if called as hash(), allow algorithm as idx 0 */
		if (key == NULL) {
			if (!algo_from_param || var_expand_parameter_idx(par) > 0)
				ERROR_TOO_MANY_UNNAMED_PARAMETERS;
			if (var_expand_parameter_idx(par) == 0)
				continue;
		}
		i_assert(key != NULL);
		if (strcmp(key, "rounds") == 0) {
			if (var_expand_parameter_number_or_var(state, par,
							       &rounds, error_r) < 0)
				return -1;
		} else if (strcmp(key, "salt") == 0) {
			if (var_expand_parameter_string_or_var(state, par,
							       &salt, error_r) < 0)
				return -1;
		} else
			ERROR_UNSUPPORTED_KEY(key);
	}

	ERROR_IF_NO_TRANSFER_TO(algo_from_param ? "hash" : algo);

	buffer_t *input = t_buffer_create(state->transfer->used);
	buffer_append(input, state->transfer->data, state->transfer->used);

	for (int i = 0; i < rounds; i++) {
		unsigned char ctx[method->context_size];
		unsigned char result[method->digest_size];

		method->init(ctx);
		if (salt != NULL)
			method->loop(ctx, salt, strlen(salt));
		method->loop(ctx, input->data, input->used);
		method->result(ctx, result);
		buffer_set_used_size(input, 0);
		buffer_append(input, result, sizeof(result));
	}

	var_expand_state_set_transfer_binary(state, input->data, input->used);

	return 0;
}

static int fn_hash(const struct var_expand_statement *stmt,
		   struct var_expand_state *state, const char **error_r)
{
	ERROR_IF_NO_PARAMETERS;

	const struct var_expand_parameter *par = stmt->params;
	const char *algo;

	if (var_expand_parameter_idx(par) == -1) {
		*error_r = "No algorithm as first parameter";
		return -1;
	} else if (var_expand_parameter_string_or_var(state, par, &algo, error_r) < 0)
		return -1;

	return fn_hash_algo(stmt, algo, TRUE, state, error_r);
}


static int fn_md5(const struct var_expand_statement *stmt,
		  struct var_expand_state *state, const char **error_r)
{
	return fn_hash_algo(stmt, "md5", FALSE, state, error_r);
}

static int fn_sha1(const struct var_expand_statement *stmt,
		   struct var_expand_state *state, const char **error_r)
{
	return fn_hash_algo(stmt, "sha1", FALSE, state, error_r);
}

static int fn_sha256(const struct var_expand_statement *stmt,
		     struct var_expand_state *state, const char **error_r)
{
	return fn_hash_algo(stmt, "sha256", FALSE, state, error_r);
}

static int fn_sha384(const struct var_expand_statement *stmt,
		     struct var_expand_state *state, const char **error_r)
{
	return fn_hash_algo(stmt, "sha384", FALSE, state, error_r);
}

static int fn_sha512(const struct var_expand_statement *stmt,
		     struct var_expand_state *state, const char **error_r)
{
	return fn_hash_algo(stmt, "sha512", FALSE, state, error_r);
}

static int fn_base64(const struct var_expand_statement *stmt,
		     struct var_expand_state *state, const char **error_r)
{
	enum base64_encode_flags flags = 0;
	const struct base64_scheme *scheme = &base64_scheme;
	struct var_expand_parameter_iter_context *ctx =
		var_expand_parameter_iter_init(stmt);
	while (var_expand_parameter_iter_more(ctx)) {
		const struct var_expand_parameter *par =
			var_expand_parameter_iter_next(ctx);
		const char *key = var_expand_parameter_key(par);
		if (key == NULL)
			ERROR_TOO_MANY_UNNAMED_PARAMETERS;
		bool value;
		if (strcmp(key, "pad") == 0) {
			if (var_expand_parameter_bool_or_var(state, par,
							     &value, error_r) < 0)
				return -1;
			if (!value)
				flags |= BASE64_ENCODE_FLAG_NO_PADDING;
		} else if (strcmp(key, "url") == 0) {
			if (var_expand_parameter_bool_or_var(state, par,
							     &value, error_r) < 0)
				return -1;
			if (value)
				scheme = &base64url_scheme;
		} else
			ERROR_UNSUPPORTED_KEY(key);
	}

	ERROR_IF_NO_TRANSFER_TO("base64");

	buffer_t *result =
		t_base64_scheme_encode(scheme, flags, UINT_MAX,
				       state->transfer->data, state->transfer->used);
	var_expand_state_set_transfer(state, str_c(result));
	return 0;
}

static int fn_unbase64(const struct var_expand_statement *stmt,
		       struct var_expand_state *state, const char **error_r)
{
	enum base64_decode_flags flags = 0;
	const struct base64_scheme *scheme = &base64_scheme;
	struct var_expand_parameter_iter_context *ctx =
		var_expand_parameter_iter_init(stmt);
	while (var_expand_parameter_iter_more(ctx)) {
		const struct var_expand_parameter *par =
			var_expand_parameter_iter_next(ctx);
		const char *key = var_expand_parameter_key(par);
		if (key == NULL)
			ERROR_TOO_MANY_UNNAMED_PARAMETERS;
		intmax_t value;
		if (strcmp(key, "pad") == 0) {
			if (var_expand_parameter_number_or_var(state, par,
							       &value, error_r) < 0)
				return -1;
			if (value == 0)
				flags |= BASE64_ENCODE_FLAG_NO_PADDING;
			else if (value == 1)
				; /* do nothing */
			else {
				*error_r = "Supported values for pad are 0 or 1";
				return -1;
			}
		} else if (strcmp(key, "url") == 0) {
			if (var_expand_parameter_number_or_var(state, par,
							       &value, error_r) < 0)
				return -1;
			if (value == 0)
				; /* do nothing */
			else if (value == 1)
				scheme = &base64url_scheme;
			else {
				*error_r = "Supported values for url are 0 or 1";
				return -1;
			}
		} else
			ERROR_UNSUPPORTED_KEY(key);
	}

	ERROR_IF_NO_TRANSFER_TO("unbase64");

	buffer_t *result =
		t_base64_scheme_decode(scheme, flags, state->transfer->data,
				       state->transfer->used);
	var_expand_state_set_transfer_binary(state, result->data, result->used);
	return 0;
}

static int fn_hex(const struct var_expand_statement *stmt,
		  struct var_expand_state *state, const char **error_r)
{
	uintmax_t number;
	intmax_t width = 0;

	struct var_expand_parameter_iter_context *iter =
		var_expand_parameter_iter_init(stmt);
	while (var_expand_parameter_iter_more(iter)) {
		const struct var_expand_parameter *par =
			var_expand_parameter_iter_next(iter);
		const char *key = var_expand_parameter_key(par);
		if (key != NULL)
			ERROR_UNSUPPORTED_KEY(key);
		if (var_expand_parameter_idx(par) != 0)
			ERROR_TOO_MANY_UNNAMED_PARAMETERS;
		if (var_expand_parameter_number_or_var(state, par, &width, error_r) < 0)
			return -1;
	}

	ERROR_IF_NO_TRANSFER_TO("hex");

	if (str_to_uintmax(str_c(state->transfer), &number) < 0) {
		*error_r = "Input is not a number";
		return -1;
	}

	str_truncate(state->transfer, 0);
	str_printfa(state->transfer, "%jx", number);

	if (width < 0) {
		width = -width;
		while (str_len(state->transfer) < (size_t)width)
			str_append_c(state->transfer, '0');
		str_truncate(state->transfer, width);
	} else if (width > 0) {
		while (str_len(state->transfer) < (size_t)width)
			str_insert(state->transfer, 0, "0");
		str_delete(state->transfer, 0, str_len(state->transfer) - width);
	}

	return 0;
}

static int fn_unhex(const struct var_expand_statement *stmt,
		    struct var_expand_state *state, const char **error_r)
{
	ERROR_IF_ANY_PARAMETERS;
	ERROR_IF_NO_TRANSFER_TO("unhex");

	uintmax_t number;

	if (str_to_uintmax_hex(str_c(state->transfer), &number) < 0) {
		*error_r = "Input is not a hex number";
		return -1;
	}

	var_expand_state_set_transfer(state, dec2str(number));

	return 0;
}


static int fn_hexlify(const struct var_expand_statement *stmt,
		      struct var_expand_state *state, const char **error_r)
{
	intmax_t width = 0;

	if (stmt->params != NULL) {
		const char *key = var_expand_parameter_key(stmt->params);
		if (key != NULL)
			ERROR_UNSUPPORTED_KEY(key);
		if (var_expand_parameter_number_or_var(state, stmt->params,
						       &width, error_r) < 0)
			return -1;
		if (width < 0) {
			*error_r = "Width must be positive";
			return -1;
		}
	}

	ERROR_IF_NO_TRANSFER_TO("hexlify");

	const char *result =
		binary_to_hex(state->transfer->data, state->transfer->used);
	size_t rlen = strlen(result);
	if (width == 0) {
		/* pass */
	} else if (rlen < (uintmax_t)width) {
		string_t *tmp = t_str_new(width);
		width -= strlen(result);
		for (; width > 0; width--)
			str_append_c(tmp, '0');
		str_append(tmp, result);
		result = str_c(tmp);
	} else if (rlen > (uintmax_t)width)
		result = t_strndup(result, width);
	var_expand_state_set_transfer(state, result);

	return 0;
}

static int fn_unhexlify(const struct var_expand_statement *stmt,
			struct var_expand_state *state, const char **error_r)
{
	ERROR_IF_ANY_PARAMETERS;
	ERROR_IF_NO_TRANSFER_TO("unhexlify");

	if (state->transfer->used % 2 != 0) {
		*error_r = "Not a hex value";
		return -1;
	}

	buffer_t *dest = t_buffer_create(state->transfer->used / 2);
	if (hex_to_binary(str_c(state->transfer), dest) == 0)
		var_expand_state_set_transfer_binary(state, dest->data, dest->used);
	else {
		*error_r = "Not a hex value";
		return -1;
	}
	return 0;
}

static int fn_reverse(const struct var_expand_statement *stmt,
		      struct var_expand_state *state, const char **error_r)
{
	ERROR_IF_ANY_PARAMETERS;
	ERROR_IF_NO_TRANSFER_TO("reverse");

	buffer_t *new_value = t_buffer_create(state->transfer->used);
	const unsigned char *tmp = state->transfer->data;
	for (size_t i = 1; i <= state->transfer->used; i++)
		buffer_append_c(new_value, tmp[state->transfer->used - i]);
	var_expand_state_set_transfer_data(state, new_value->data, new_value->used);

	return 0;
}

static int fn_truncate(const struct var_expand_statement *stmt,
		       struct var_expand_state *state, const char **error_r)
{
	ERROR_IF_NO_PARAMETERS;

	size_t len = SIZE_MAX;
	bool bits = FALSE;

	struct var_expand_parameter_iter_context *ctx =
		var_expand_parameter_iter_init(stmt);
	while (var_expand_parameter_iter_more(ctx)) {
		const struct var_expand_parameter *par =
			var_expand_parameter_iter_next(ctx);
		const char *key = var_expand_parameter_key(par);
		if (null_strcmp(key, "bits") == 0) {
			intmax_t value;
			if (var_expand_parameter_number_or_var(state, par,
							       &value, error_r) < 0)
				return -1;
			if (value < 0 || value > SSIZE_MAX) {
				*error_r = "Value of out of bounds";
				return -1;
			}
			len = (size_t)value;
			bits = TRUE;
		} else if (var_expand_parameter_idx(par) == 0) {
			intmax_t value;
			if (var_expand_parameter_number_or_var(state, par,
							       &value, error_r) < 0)
				return -1;
			if (value < 0 || value > SSIZE_MAX) {
				*error_r = "Value of out of bounds";
				return -1;
			}
			len = (size_t)value;
		} else if (key != NULL)
			ERROR_UNSUPPORTED_KEY(key);
		else
			ERROR_TOO_MANY_UNNAMED_PARAMETERS;
	}

	if (len == SIZE_MAX) {
		*error_r = "Missing truncation length";
		return -1;
	}

	ERROR_IF_NO_TRANSFER_TO("truncate");

	buffer_t *new_value = t_buffer_create(state->transfer->used);
	buffer_append_buf(new_value, state->transfer, 0, state->transfer->used);

	if (bits)
		buffer_truncate_rshift_bits(new_value, len);
	else
		buffer_set_used_size(new_value, len);

	var_expand_state_set_transfer_data(state, new_value->data, new_value->used);

	return 0;
}

static int fn_substr(const struct var_expand_statement *stmt,
		     struct var_expand_state *state, const char **error_r)
{
	intmax_t off = -INT_MAX, len = state->transfer->used;
	bool got_off = FALSE, got_len = FALSE;

	ERROR_IF_NO_PARAMETERS;

	struct var_expand_parameter_iter_context *ctx =
		var_expand_parameter_iter_init(stmt);
	while (var_expand_parameter_iter_more(ctx)) {
		intmax_t value;
		const struct var_expand_parameter *par =
			var_expand_parameter_iter_next(ctx);
		const char *key = var_expand_parameter_key(par);
		if (key != NULL)
			ERROR_UNSUPPORTED_KEY(key);
		if (var_expand_parameter_number_or_var(state, par, &value,
						       error_r) < 0)
			return -1;
		if (var_expand_parameter_idx(par) == 0) {
			off = value;
			got_off = TRUE;
		} else if (var_expand_parameter_idx(par) == 1) {
			len = value;
			got_len = TRUE;
		} else
			ERROR_TOO_MANY_UNNAMED_PARAMETERS;
	}

	if (!got_off) {
		*error_r = "Missing offset parameter";
		return -1;
	}

	ERROR_IF_NO_TRANSFER_TO("substring");

	if (off < -(intmax_t)state->transfer->used || off > (intmax_t)state->transfer->used) {
		*error_r = "Offset out of bounds";
		return -1;
	}

	if (len < -(intmax_t)state->transfer->used || len > (intmax_t)state->transfer->used) {
		*error_r = "Length out of bounds";
		return -1;
	}

	if (len == 0) {
		var_expand_state_set_transfer_data(state, "", 0);
		return 0;
	}

	if (off < 0)
		off = (intmax_t)state->transfer->used + off;

	/* from offset to end */
	if (!got_len)
		len = (intmax_t)state->transfer->used - off;
	else if (len < 0) {
		/* negative offset leaves that many characters from end */
		len = (intmax_t)state->transfer->used + len;
		if (len < off) {
			*error_r = "Length out of bounds";
			return -1;
		}
		len -= off;
	}

	if (off < 0 || off > (intmax_t)state->transfer->used) {
		*error_r = "Offset out of bounds";
		return -1;
	}

	if (len < 0 || len + off > (intmax_t)state->transfer->used) {
		*error_r = "Length out of bounds";
		return -1;
	} else if (len == 0) {
		var_expand_state_set_transfer_data(state, "", 0);
	} else {
		const unsigned char *data =
			p_memdup(pool_datastack_create(),
				 CONST_PTR_OFFSET(state->transfer->data, off), len);
		var_expand_state_set_transfer_data(state, data, len);
	}
	return 0;
}

static int fn_ldap_dn(const struct var_expand_statement *stmt,
		      struct var_expand_state *state, const char **error_r)
{
	ERROR_IF_ANY_PARAMETERS;
	ERROR_IF_NO_TRANSFER_TO("convert to ldap_dn");

	string_t *ret = t_str_new(256);
	const char *str = str_c(state->transfer);

	while (*str != '\0') {
		if (*str == '.')
			str_append(ret, ",dc=");
		else
			str_append_c(ret, *str);
		str++;
	}

	var_expand_state_set_transfer_data(state, ret->data, ret->used);
	return 0;
}

static int fn_regexp(const struct var_expand_statement *stmt,
		     struct var_expand_state *state, const char **error_r)
{
	ERROR_IF_NO_PARAMETERS;

	/* pattern and replacement */
	const char *pat = NULL;
	const char *rep = NULL;
	const char *error;
	struct var_expand_parameter_iter_context *ctx =
		var_expand_parameter_iter_init(stmt);
	while (var_expand_parameter_iter_more(ctx)) {
		const struct var_expand_parameter *par =
			var_expand_parameter_iter_next(ctx);
		const char *key = var_expand_parameter_key(par);
		if (key != NULL)
			ERROR_UNSUPPORTED_KEY(key);
		const char *value;
		if (var_expand_parameter_string_or_var(state, par, &value,
						       &error) < 0)
			return -1;
		switch (var_expand_parameter_idx(par)) {
		case 0:
			pat = value;
			break;
		case 1:
			rep = value;
			break;
		default:
			ERROR_TOO_MANY_UNNAMED_PARAMETERS;
		}
	}

	if (pat == NULL) {
		*error_r = "Missing pattern and replacement parameters";
		return -1;
	}

	if (rep == NULL) {
		*error_r = "Missing replacement parameter";
		return -1;
	}

	ERROR_IF_NO_TRANSFER_TO("regexp");

	int ret;
	regex_t reg;
	regmatch_t matches[10];
	const char *input = str_c(state->transfer);
	i_zero(&reg);
	i_zero(&matches);
	if ((ret = regcomp(&reg, pat, REG_EXTENDED)) != 0) {
		char errbuf[1024] = {0};
		(void)regerror(ret, &reg, errbuf, sizeof(errbuf));
		regfree(&reg);
		*error_r = t_strdup(errbuf);
		return -1;
	}

	ret = regexec(&reg, input, N_ELEMENTS(matches), matches, 0);
	if (ret == REG_NOMATCH) {
		/* no match, do not modify */
		regfree(&reg);
		return 0;
	}

	/* perform replacement */
	string_t *dest = t_str_new(strlen(rep));
	const char *p0 = rep;
	const char *p1;
	ret = 0;

	/* Supports up to 9 capture groups,
	 * if we need more, then this code should
	 * be refactored to see how many we really need
	 * and create a proper template from this. */
	while ((p1 = strchr(p0, '\\')) != NULL) {
		if (i_isdigit(p1[1])) {
			/* looks like a placeholder */
			str_append_data(dest, p0, p1 - p0);
			unsigned int g = p1[1] - '0';
			if (g >= N_ELEMENTS(matches) ||
			    matches[g].rm_so == -1) {
				*error_r = "Invalid capture group";
				ret = -1;
				break;
			}
			i_assert(matches[g].rm_eo >= matches[g].rm_so);
			str_append_data(dest, input + matches[g].rm_so,
				        matches[g].rm_eo - matches[g].rm_so);
			p0 = p1 + 2;
		} else {
			str_append_c(dest, *p1);
			p1++;
		}
	}

	regfree(&reg);

	if (ret == 0) {
		str_append(dest, p0);
		var_expand_state_set_transfer_data(state, dest->data, dest->used);
	}

	return ret == 0 ? 0 : -1;
}

static int fn_number(const struct var_expand_statement *stmt, bool be,
		     struct var_expand_state *state, const char **error_r)
{
	ERROR_IF_ANY_PARAMETERS;
	ERROR_IF_NO_TRANSFER_TO("convert to number");
	const unsigned char *data = state->transfer->data;
	size_t len = state->transfer->used;
	uintmax_t result;

	/* see if we can convert input bytes to a number */
	if (len == sizeof(uint8_t)) {
		if (be)
			result = be8_to_cpu_unaligned(data);
		else
			result = le8_to_cpu_unaligned(data);
	} else if (len == sizeof(uint16_t)) {
		if (be)
			result = be16_to_cpu_unaligned(data);
		else
			result = le16_to_cpu_unaligned(data);
	} else if (len == sizeof(uint32_t)) {
		if (be)
			result = be32_to_cpu_unaligned(data);
		else
			result = le32_to_cpu_unaligned(data);
	} else if (len == sizeof(uint64_t)) {
		if (be)
			result = be64_to_cpu_unaligned(data);
		else
			result = le64_to_cpu_unaligned(data);
	} else {
		*error_r = t_strdup_printf("Cannot convert '%zu' bytes to number",
					   len);
		return -1;
	}

	var_expand_state_set_transfer(state, dec2str(result));
	return 0;
}

static int fn_be_number(const struct var_expand_statement *stmt,
			struct var_expand_state *state, const char **error_r)
{
	return fn_number(stmt, TRUE, state ,error_r);
}

static int fn_le_number(const struct var_expand_statement *stmt,
			struct var_expand_state *state, const char **error_r)
{
	return fn_number(stmt, FALSE, state, error_r);
}

static int fn_index_common(struct var_expand_state *state, int index,
			   const char *separator, const char **error_r)
{
	const char *p;
	const char *token;
	const char *input = str_c(state->transfer);
	const char *end = CONST_PTR_OFFSET(input, str_len(state->transfer));
	ARRAY_TYPE(const_string) tokens;
	t_array_init(&tokens, 2);

	while ((p = strstr(input, separator)) != NULL) {
		token = t_strdup_until(input, p);
		array_push_back(&tokens, &token);
		input = p + strlen(separator);
		i_assert(input <= end);
	}
	token = t_strdup(input);
	array_push_back(&tokens, &token);

	if (index < 0)
		index = (int)array_count(&tokens) + index;

	if (index < 0 || (unsigned int)index >= array_count(&tokens)) {
		*error_r = "Position out of bounds";
		return -1;
	}

	token = array_idx_elem(&tokens, index);

	var_expand_state_set_transfer(state, token);
	return 0;
}

static int fn_index(const struct var_expand_statement *stmt,
		    struct var_expand_state *state, const char **error_r)
{
	ERROR_IF_NO_PARAMETERS;

	const char *separator = NULL;
	int idx = 0;
	bool got_idx = FALSE;

	struct var_expand_parameter_iter_context *ctx =
		var_expand_parameter_iter_init(stmt);
	while (var_expand_parameter_iter_more(ctx)) {
		const struct var_expand_parameter *par =
			var_expand_parameter_iter_next(ctx);
		const char *key = var_expand_parameter_key(par);
		intmax_t value;
		if (key != NULL)
			ERROR_UNSUPPORTED_KEY(key);
		switch (var_expand_parameter_idx(par)) {
		case 0:
			if (var_expand_parameter_string_or_var(state, par,
							       &separator, error_r) < 0)
				return -1;
			break;
		case 1:
			if (var_expand_parameter_number_or_var(state, par,
							       &value, error_r) < 0)
				return -1;
			else if (value < INT_MIN || value > INT_MAX) {
				*error_r = "Position out of bounds";
				return -1;
			}
			idx = (int)value;
			got_idx = TRUE;
			break;
		default:
			ERROR_TOO_MANY_UNNAMED_PARAMETERS;
		}
	}

	if (separator == NULL) {
		*error_r = "Missing separator and index parameters";
		return -1;
	}

	if (!got_idx) {
		*error_r = "Missing index parameter";
		return -1;
	}

	ERROR_IF_NO_TRANSFER_TO("index");

	return fn_index_common(state, idx, separator, error_r);
}

static int fn_username(const struct var_expand_statement *stmt,
		       struct var_expand_state *state, const char **error_r)
{
	ERROR_IF_ANY_PARAMETERS;
	ERROR_IF_NO_TRANSFER_TO("get username from");

	return fn_index_common(state, 0, "@", error_r);
}

static int fn_domain(const struct var_expand_statement *stmt,
		     struct var_expand_state *state, const char **error_r)
{
	ERROR_IF_ANY_PARAMETERS;
	ERROR_IF_NO_TRANSFER_TO("get domain from");

	/* This function needs to return the whole string after @ character
	   even if it contains @ characters. */
	const char *input = str_c(state->transfer);
	var_expand_state_set_transfer(state, t_strdup(i_strchr_to_next(input, '@')));
	return 0;
}

static int fn_list(const struct var_expand_statement *stmt,
		   struct var_expand_state *state, const char **error_r)
{
	/* allow optionally specifying separator */
	const char *sep = ",";
	struct var_expand_parameter_iter_context *iter =
		var_expand_parameter_iter_init(stmt);
	while (var_expand_parameter_iter_more(iter)) {
		const struct var_expand_parameter *par =
			var_expand_parameter_iter_next(iter);
		const char *key = var_expand_parameter_key(par);
		if (key != NULL)
			ERROR_UNSUPPORTED_KEY(key);
		if (var_expand_parameter_idx(par) > 0)
			ERROR_TOO_MANY_UNNAMED_PARAMETERS;
		if (var_expand_parameter_string_or_var(state, stmt->params, &sep,
						       error_r) < 0)
			return -1;
	}

	ERROR_IF_NO_TRANSFER_TO("generate list from");

	/* split tabescaped */
	const char *const *values = t_strsplit_tabescaped(str_c(state->transfer));
	/* join values */
	var_expand_state_set_transfer(state, t_strarray_join(values, sep));

	return 0;
}

static int fn_fill(const struct var_expand_statement *stmt, bool left,
		   struct var_expand_state *state, const char **error_r)
{
	size_t amount = 0;
	const char *filler = "0";

	ERROR_IF_NO_PARAMETERS;

	struct var_expand_parameter_iter_context *ctx =
		var_expand_parameter_iter_init(stmt);
	while (var_expand_parameter_iter_more(ctx)) {
		const struct var_expand_parameter *par =
			var_expand_parameter_iter_next(ctx);
		const char *key = var_expand_parameter_key(par);
		intmax_t value;

		if (key != NULL)
			ERROR_UNSUPPORTED_KEY(key);

		switch (var_expand_parameter_idx(par)) {
		case 0:
			if (var_expand_parameter_number_or_var(state, par,
							       &value, error_r) < 0)
				return -1;
			else if (value < 1 || value > INT_MAX) {
				*error_r = "Fill length out of bounds";
				return -1;
			}
			amount = (size_t)value;
			break;
		case 1:
			if (var_expand_parameter_string_or_var(state, par,
							       &filler, error_r) < 0)
				return -1;
			break;
		default:
			ERROR_TOO_MANY_UNNAMED_PARAMETERS;
		}
	}

	if (amount < 1) {
		*error_r = "Missing amount";
		return -1;
	}

	ERROR_IF_NO_TRANSFER_TO("fill");

	/* do nothing if it's already long enough */
	while (str_len(state->transfer) < (size_t)amount) {
		if (left)
			str_insert(state->transfer, 0, filler);
		else
			str_append(state->transfer, filler);
	}

	return 0;
}

static int fn_rfill(const struct var_expand_statement *stmt,
		    struct var_expand_state *state, const char **error_r)
{
	return fn_fill(stmt, FALSE, state, error_r);
}

static int fn_lfill(const struct var_expand_statement *stmt,
		    struct var_expand_state *state, const char **error_r)
{
	return fn_fill(stmt, TRUE, state, error_r);
}

static int fn_text(const struct var_expand_statement *stmt,
		   struct var_expand_state *state, const char **error_r)
{
	ERROR_IF_ANY_PARAMETERS;
	ERROR_IF_NO_TRANSFER_TO("text");
	string_t *result = t_str_new(state->transfer->used);
	str_sanitize_append_utf8(result, str_c(state->transfer), SIZE_MAX);
	var_expand_state_set_transfer(state, str_c(result));
	return 0;
}

static const struct var_expand_filter var_expand_builtin_filters[] = {
	{ .name = "lookup", .filter = fn_lookup },
	{ .name = "literal", .filter = fn_literal },
	{ .name = "calculate", .filter = fn_calculate },
	{ .name = "concat", .filter = fn_concat },
	{ .name = "upper", .filter = fn_upper },
	{ .name = "lower", .filter = fn_lower },
	{ .name = "hash", .filter = fn_hash },
	{ .name = "md5", .filter = fn_md5 },
	{ .name = "sha1", .filter = fn_sha1 },
	{ .name = "sha256", .filter = fn_sha256 },
	{ .name = "sha384", .filter = fn_sha384 },
	{ .name = "sha512", .filter = fn_sha512 },
	{ .name = "base64", .filter = fn_base64 } ,
	{ .name = "unbase64", .filter = fn_unbase64 },
	{ .name = "hex", .filter = fn_hex },
	{ .name = "unhex", .filter = fn_unhex },
	{ .name = "hexlify", .filter = fn_hexlify },
	{ .name = "unhexlify", .filter = fn_unhexlify },
	{ .name = "default", .filter = fn_default },
	{ .name = "reverse", .filter = fn_reverse },
	{ .name = "truncate", .filter = fn_truncate },
	{ .name = "substr", .filter = fn_substr },
	{ .name = "ldap_dn", .filter = fn_ldap_dn },
	{ .name = "if", .filter = expansion_filter_if },
	{ .name = "regexp", .filter = fn_regexp },
	{ .name = "lenumber", .filter = fn_le_number },
	{ .name = "benumber", .filter = fn_be_number },
	{ .name = "index", .filter = fn_index },
	{ .name = "username", .filter = fn_username },
	{ .name = "domain", .filter = fn_domain },
	{ .name = "list", .filter = fn_list },
	{ .name = "lfill", .filter = fn_lfill },
	{ .name = "rfill", .filter = fn_rfill },
	{ .name = "text", .filter = fn_text },
	{ .name = "encrypt", .filter = expansion_filter_encrypt },
	{ .name = "decrypt", .filter = expansion_filter_decrypt },
	{ .name = NULL }
};

static void var_expand_free_filters(void)
{
	array_free(&dyn_filters);
}

void var_expand_register_filter(const char *name, var_expand_filter_func_t *const filter)
{
	if (!array_is_created(&dyn_filters)) {
		i_array_init(&dyn_filters, 8);
		lib_atexit(var_expand_free_filters);
	}
	bool is_filter = var_expand_is_filter(name);
	i_assert(!is_filter);

	struct var_expand_filter f = {
		.name = name,
		.filter = filter,
	};
	array_push_back(&dyn_filters, &f);
}

bool var_expand_is_filter(const char *name)
{
	var_expand_filter_func_t *fn ATTR_UNUSED;
	return var_expand_find_filter(name, &fn) == 0;
}

void var_expand_unregister_filter(const char *name)
{
	i_assert(array_is_created(&dyn_filters));

	const struct var_expand_filter *filter;
	array_foreach(&dyn_filters, filter) {
		unsigned int i = array_foreach_idx(&dyn_filters, filter);
		if (strcmp(filter->name, name) == 0) {
			array_delete(&dyn_filters, i, 1);
			return;
		}
	}
	i_unreached();
}

int var_expand_find_filter(const char *name, var_expand_filter_func_t **fn_r)
{
	for (size_t i = 0; var_expand_builtin_filters[i].name != NULL; i++) {
		if (strcmp(var_expand_builtin_filters[i].name, name) == 0) {
			*fn_r = var_expand_builtin_filters[i].filter;
			return 0;
		}
	}

	if (array_is_created(&dyn_filters)) {
		const struct var_expand_filter *filter;
		/* see if we can find from dyn_filters */
		array_foreach(&dyn_filters, filter) {
			if (strcmp(filter->name, name) == 0) {
				*fn_r = filter->filter;
				return 0;
			}
		}
	}

	return -1;
}
