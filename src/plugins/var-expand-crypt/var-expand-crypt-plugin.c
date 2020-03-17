/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hex-binary.h"
#include "base64.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "var-expand-private.h"
#include "dcrypt.h"

#define VAR_EXPAND_CRYPT_DEFAULT_ALGO "AES-256-CBC"

struct module;

enum crypt_field_format {
	FORMAT_HEX,
	FORMAT_BASE64
};

struct var_expand_crypt_context {
	struct var_expand_context *ctx;
	const char *algo;
	string_t *iv;
	string_t *enckey;
	enum crypt_field_format format;
	bool enc_result_only:1;
};

static bool var_expand_crypt_initialize(const char **error_r);

void var_expand_crypt_init(struct module *module);
void var_expand_crypt_deinit(void);
void auth_var_expand_crypt_init(struct module *module);
void auth_var_expand_crypt_deinit(void);

static bool has_been_init;

static int
var_expand_crypt_settings(struct var_expand_crypt_context *ctx,
			  const char *const *args, const char **error_r)
{
	while(args != NULL && *args != NULL) {
		const char *k = t_strcut(*args, '=');
		const char *value = strchr(*args, '=');
		if (value == NULL) {
			args++;
			continue;
		} else {
			value++;
		}

		if (strcmp(k, "iv") == 0) {
			str_truncate(ctx->iv, 0);
			if (var_expand_with_funcs(ctx->iv, value, ctx->ctx->table,
						  ctx->ctx->func_table,
						  ctx->ctx->context, error_r) < 0) {
				return -1;
			}
			const char *hexiv = t_strdup(str_c(ctx->iv));
			/* try to decode IV */
			str_truncate(ctx->iv, 0);
			hex_to_binary(hexiv, ctx->iv);
		} if (strcmp(k, "noiv") == 0) {
			ctx->enc_result_only = strcasecmp(value, "yes")==0;
		} if (strcmp(k, "algo") == 0) {
			ctx->algo = value;
		} else if (strcmp(k, "key") == 0) {
			str_truncate(ctx->enckey, 0);
			if (var_expand_with_funcs(ctx->enckey, value,
						  ctx->ctx->table,
						  ctx->ctx->func_table,
						  ctx->ctx->context,
						  error_r) < 0) {
				return -1;
			}
			const char *hexkey = t_strdup(str_c(ctx->enckey));
			str_truncate(ctx->enckey, 0);
			hex_to_binary(hexkey, ctx->enckey);
		} else if (strcmp(k, "format") == 0) {
			if (strcmp(value, "hex") == 0) {
				ctx->format = FORMAT_HEX;
			} else if (strcmp(value, "base64") == 0) {
				ctx->format = FORMAT_BASE64;
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

	if (ctx->algo == NULL) {
		ctx->algo = "AES-256-CBC";
	}

	return 0;
}

static int
var_expand_crypt(struct dcrypt_context_symmetric *dctx, buffer_t *key, buffer_t *iv,
		 const buffer_t *input, buffer_t *output, const char **error_r)
{
	/* make sure IV is correct */
	if (iv->used == 0) {
		dcrypt_ctx_sym_set_key_iv_random(dctx);
		/* acquire IV */
		dcrypt_ctx_sym_get_iv(dctx, iv);
	} else if (dcrypt_ctx_sym_get_iv_length(dctx) != iv->used) {
		*error_r = t_strdup_printf("crypt: IV length invalid (%zu != %u)",
					   iv->used,
					   dcrypt_ctx_sym_get_iv_length(dctx));
		return -1;
	} else {
		dcrypt_ctx_sym_set_iv(dctx, iv->data, iv->used);
	}

	if (dcrypt_ctx_sym_get_key_length(dctx) != key->used) {
		*error_r = t_strdup_printf("crypt: Key length invalid (%zu != %u)",
					   key->used,
					   dcrypt_ctx_sym_get_key_length(dctx));
		return -1;
	} else {
		dcrypt_ctx_sym_set_key(dctx, key->data, key->used);
	}

	if (!dcrypt_ctx_sym_init(dctx, error_r) ||
	    !dcrypt_ctx_sym_update(dctx, input->data,
				   input->used, output, error_r) ||
	    !dcrypt_ctx_sym_final(dctx, output, error_r))
		return -1;
	return 0;
}

static int
var_expand_encrypt(struct var_expand_context *_ctx,
		   const char *key, const char *field,
		   const char **result_r, const char **error_r)
{
	if (!has_been_init && !var_expand_crypt_initialize(error_r))
		return -1;

	const char *p = strchr(key, ';');
	const char *const *args = NULL;
	const char *value;
	struct var_expand_crypt_context ctx;
	string_t *dest;
	int ret = 0;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ctx = _ctx;
	ctx.format = FORMAT_HEX;

	if (p != NULL) {
		args = t_strsplit(p+1, ",");
	}

	string_t *field_value = t_str_new(64);
	ctx.iv = t_str_new(64);
	ctx.enckey = t_str_new(64);
	string_t *tmp = t_str_new(128);

	if ((ret = var_expand_long(_ctx, field, strlen(field),
				   &value, error_r)) < 1) {
		return ret;
	}

	if (*value == '\0') {
		*result_r = value;
		return ret;
	}

	if (var_expand_crypt_settings(&ctx, args, error_r) < 0)
		return -1;

	str_append(field_value, value);

	struct dcrypt_context_symmetric *dctx;
	if (!dcrypt_ctx_sym_create(ctx.algo, DCRYPT_MODE_ENCRYPT, &dctx, error_r))
		return -1;

	ret = var_expand_crypt(dctx, ctx.enckey, ctx.iv, field_value, tmp, error_r);
	dcrypt_ctx_sym_destroy(&dctx);

	if (ret == 0) {
		/* makes compiler happy */
		const char *enciv = "";
		const char *res = "";

		switch(ctx.format) {
		case FORMAT_HEX:
			enciv = binary_to_hex(ctx.iv->data, ctx.iv->used);
			res = binary_to_hex(tmp->data, tmp->used);
			break;
		case FORMAT_BASE64:
			dest = t_str_new(32);
			base64_encode(ctx.iv->data, ctx.iv->used, dest);
			enciv = str_c(dest);
			dest = t_str_new(32);
			base64_encode(tmp->data, tmp->used, dest);
			res = str_c(dest);
			break;
		default:
			i_unreached();
		}
		if (ctx.enc_result_only)
			*result_r = t_strdup(res);
		else
			*result_r = t_strdup_printf("%s$%s$", enciv, res);
		ret = 1;
	}

	return ret;
}

static int
var_expand_decrypt(struct var_expand_context *_ctx,
		   const char *key, const char *field,
		   const char **result_r, const char **error_r)
{
	if (!has_been_init && !var_expand_crypt_initialize(error_r))
		return -1;

	const char *p = strchr(key, ';');
	const char *const *args = NULL;
	const char *value;
	struct var_expand_crypt_context ctx;
	int ret = 0;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ctx = _ctx;
	ctx.format = FORMAT_HEX;

	if (p != NULL) {
		args = t_strsplit(p+1, ",");
	}

	string_t *field_value = t_str_new(64);
	ctx.iv = t_str_new(64);
	ctx.enckey = t_str_new(64);
	string_t *tmp = t_str_new(128);

	if ((ret = var_expand_long(_ctx, field, strlen(field),
				   &value, error_r)) < 1) {
		return ret;
	}

	if (*value == '\0') {
		*result_r = value;
		return ret;
	}

	if (var_expand_crypt_settings(&ctx, args, error_r) < 0)
		return -1;

	const char *encdata = value;
	const char *enciv = "";

	/* make sure IV is correct */
	if (ctx.iv->used == 0 && (p = strchr(encdata, '$')) != NULL) {
		/* see if IV can be taken from data */
		enciv = t_strcut(encdata, '$');
		encdata = t_strcut(p+1,'$');
	}

	str_truncate(field_value, 0);

	/* try to decode iv and encdata */
	switch(ctx.format) {
	case FORMAT_HEX:
		if (ctx.iv->used == 0)
			hex_to_binary(enciv, ctx.iv);
		hex_to_binary(encdata, field_value);
		break;
	case FORMAT_BASE64:
		if (ctx.iv->used == 0)
			str_append_str(ctx.iv, t_base64_decode_str(enciv));
		str_append_str(field_value, t_base64_decode_str(encdata));
		break;
	}

	if (ctx.iv->used == 0) {
		*error_r = t_strdup_printf("decrypt: IV missing");
		return -1;
	}

	struct dcrypt_context_symmetric *dctx;
	if (!dcrypt_ctx_sym_create(ctx.algo, DCRYPT_MODE_DECRYPT, &dctx, error_r))
		return -1;
	ret = var_expand_crypt(dctx, ctx.enckey, ctx.iv, field_value, tmp, error_r);
	dcrypt_ctx_sym_destroy(&dctx);

	if (ret == 0) {
		*result_r = str_c(tmp);
		ret = 1;
	}

	return ret;
}

static const struct var_expand_extension_func_table funcs[] = {
	{ "encrypt", var_expand_encrypt },
	{ "decrypt", var_expand_decrypt },
	{ NULL, NULL, }
};

static bool var_expand_crypt_initialize(const char **error_r)
{
	return dcrypt_initialize(NULL, NULL, error_r);
}

void var_expand_crypt_init(struct module *module ATTR_UNUSED)
{
	var_expand_register_func_array(funcs);
	/* do not initialize dcrypt here - saves alot of memory
	   to not load openssl every time. Only load it if
	   needed */
}

void var_expand_crypt_deinit(void)
{
	var_expand_unregister_func_array(funcs);
	if (has_been_init)
		dcrypt_deinitialize();
}

void auth_var_expand_crypt_init(struct module *module)
{
	var_expand_crypt_init(module);
}

void auth_var_expand_crypt_deinit(void)
{
	var_expand_crypt_deinit();
}
