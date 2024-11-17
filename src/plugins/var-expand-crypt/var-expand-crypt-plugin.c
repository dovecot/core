/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hex-binary.h"
#include "str.h"
#include "var-expand-private.h"
#include "dcrypt.h"

#define VAR_EXPAND_CRYPT_DEFAULT_ALGO "AES-256-CBC"

struct module;

struct var_expand_crypt_context {
	const char *algo;
	string_t *iv;
	string_t *enckey;
	buffer_t *input;
	bool raw;
};

static bool var_expand_crypt_initialize(const char **error_r);

void var_expand_crypt_init(struct module *module);
void var_expand_crypt_deinit(void);
void auth_var_expand_crypt_init(struct module *module);
void auth_var_expand_crypt_deinit(void);

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
		*error_r = t_strdup_printf("IV length invalid (%zu != %u)",
					   iv->used,
					   dcrypt_ctx_sym_get_iv_length(dctx));
		return -1;
	} else {
		dcrypt_ctx_sym_set_iv(dctx, iv->data, iv->used);
	}

	if (dcrypt_ctx_sym_get_key_length(dctx) != key->used) {
		*error_r = t_strdup_printf("Key length invalid (%zu != %u)",
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

static int var_expand_crypt_settings(struct var_expand_state *state,
				     const struct var_expand_statement *stmt,
				     struct var_expand_crypt_context *ctx,
				     const char **error_r)
{
	const char *iv;
	const char *enckey = NULL;

	ctx->algo = VAR_EXPAND_CRYPT_DEFAULT_ALGO;

	struct var_expand_parameter_iter_context *iter =
		var_expand_parameter_iter_init(stmt);
	while (var_expand_parameter_iter_more(iter)) {
		const struct var_expand_parameter *par =
			var_expand_parameter_iter_next(iter);

		const char *key = var_expand_parameter_key(par);
		if (key == NULL)
			ERROR_TOO_MANY_UNNAMED_PARAMETERS;
		else if (strcmp(key, "algorithm") == 0) {
			if (var_expand_parameter_string_or_var(state, par,
							       &ctx->algo, error_r) < 0)
				return -1;
		} else if (strcmp(key, "iv") == 0) {
			if (var_expand_parameter_string_or_var(state, par, &iv,
							       error_r) < 0) {
				return -1;
			}
			ctx->iv = t_buffer_create(strlen(iv) / 2);
			hex_to_binary(iv, ctx->iv);
		} else if (strcmp(key, "key") == 0) {
			if (var_expand_parameter_string_or_var(state, par, &enckey,
							       error_r) < 0) {
				return -1;
			}
			if (enckey == NULL || *enckey == '\0') {
				*error_r = "Empty encryption key";
				return -1;
			}
		} else if (strcmp(key, "raw") == 0) {
			if (var_expand_parameter_bool_or_var(state, par, &ctx->raw,
							     error_r) < 0)
				return -1;
		} else
			ERROR_UNSUPPORTED_KEY(key);
	}

	if (enckey == NULL) {
		*error_r = "Encryption key missing";
		return -1;
	}

	ctx->enckey = t_buffer_create(strlen(enckey) / 2);
	hex_to_binary(enckey, ctx->enckey);

	ERROR_IF_NO_TRANSFER_TO(stmt->function);

	ctx->input = state->transfer;
	if (ctx->raw || strcmp(stmt->function, "encrypt") == 0)
		return 0;

	/* handle $ separated input, only support hex */
	const char *const *parts = t_strsplit(str_c(state->transfer), "$");
	if (str_array_length(parts) == 3 && *parts[2] == '\0') {
		if (ctx->iv->used > 0) {
			*error_r = "Cannot have iv in parameter and input";
			return -1;
		}
		hex_to_binary(parts[0], ctx->iv);
		ctx->input = t_buffer_create(strlen(parts[1]) / 2);
		hex_to_binary(parts[1], ctx->input);
	} else {
		*error_r = "Invalid input format";
		return -1;
	}

	return 0;

}

static int
var_expand_encrypt(const struct var_expand_statement *stmt,
		   struct var_expand_state *state, const char **error_r)
{
	if (!var_expand_crypt_initialize(error_r))
		return -1;

	struct var_expand_crypt_context ctx;
	i_zero(&ctx);
	if (var_expand_crypt_settings(state, stmt, &ctx, error_r) < 0)
		return -1;

	struct dcrypt_context_symmetric *dctx;
	if (!dcrypt_ctx_sym_create(ctx.algo, DCRYPT_MODE_ENCRYPT, &dctx, error_r))
		return -1;
	buffer_t *dest = t_buffer_create(state->transfer->used*2);

	int ret = var_expand_crypt(dctx, ctx.enckey, ctx.iv, ctx.input,
				   dest, error_r);
	dcrypt_ctx_sym_destroy(&dctx);

	if (ret == 0) {
		if (ctx.raw)
			var_expand_state_set_transfer_binary(state, dest->data, dest->used);
		else {
			state->transfer_set = TRUE;
			str_truncate(state->transfer, 0);
			binary_to_hex_append(state->transfer, ctx.iv->data, ctx.iv->used);
			str_append_c(state->transfer, '$');
			binary_to_hex_append(state->transfer, dest->data, dest->used);
			str_append_c(state->transfer, '$');
		}
	}

	return ret;
}

static int
var_expand_decrypt(const struct var_expand_statement *stmt,
		   struct var_expand_state *state, const char **error_r)

{
	if (!var_expand_crypt_initialize(error_r))
		return -1;

	struct var_expand_crypt_context ctx;
	i_zero(&ctx);
	if (var_expand_crypt_settings(state, stmt, &ctx, error_r) < 0)
		return -1;

	struct dcrypt_context_symmetric *dctx;
	if (!dcrypt_ctx_sym_create(ctx.algo, DCRYPT_MODE_DECRYPT, &dctx, error_r))
		return -1;
	string_t *dest = t_buffer_create(state->transfer->used / 2);
	int ret = var_expand_crypt(dctx, ctx.enckey, ctx.iv, ctx.input,
				   dest, error_r);
	dcrypt_ctx_sym_destroy(&dctx);

	if (ret == 0) {
		if (memchr(dest->data, '\0', dest->used) != NULL)
			var_expand_state_set_transfer_binary(state, dest->data, dest->used);
		else
			var_expand_state_set_transfer(state, str_c(dest));
	}
	return ret;
}

static bool var_expand_crypt_initialize(const char **error_r)
{
	return dcrypt_initialize(NULL, NULL, error_r);
}

void var_expand_crypt_init(struct module *module ATTR_UNUSED)
{
	/* do not initialize dcrypt here - saves alot of memory
	   to not load openssl every time. Only load it if
	   needed */
	var_expand_register_filter("encrypt", var_expand_encrypt);
	var_expand_register_filter("decrypt", var_expand_decrypt);
}

void var_expand_crypt_deinit(void)
{
	var_expand_unregister_filter("encrypt");
	var_expand_unregister_filter("decrypt");
}

void auth_var_expand_crypt_init(struct module *module)
{
	var_expand_crypt_init(module);
}

void auth_var_expand_crypt_deinit(void)
{
	var_expand_crypt_deinit();
}
