/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hex-binary.h"
#include "str.h"
#include "var-expand-private.h"
#include "expansion.h"
#include "dcrypt.h"

#define VAR_EXPAND_CRYPT_DEFAULT_ALGO "AES-256-CBC"
#define VAR_EXPAND_CRYPT_DEFAULT_ROUNDS 10000
#define VAR_EXPAND_CRYPT_DEFAULT_HASH "sha256"
#define VAR_EXPAND_CRYPT_DEFAULT_SALT_LEN 8

struct module;

struct var_expand_crypt_context {
	const char *algo;
	string_t *iv;
	string_t *enckey;
	intmax_t rounds;
	const char *salt;
	buffer_t *input;
	bool raw;
};

static bool var_expand_crypt_initialize(const char **error_r);

extern void var_expand_crypt_init(struct module *module);
extern void var_expand_crypt_deinit(void);

static int parse_parameters(struct var_expand_crypt_context *ctx,
			    const char *const *parts, const char **error_r)
{
	if (ctx->iv != NULL) {
		*error_r = "Cannot have iv in parameter and input";
		return -1;
	} else if (*parts[0] == 's' || *parts[0] == 'r') {
		const char *const *params =
			t_strsplit(parts[0], ",");
		for (; *params != NULL; params++) {
			const char *value;
			if (str_begins(*params, "s=", &ctx->salt)) {
				/* got salt */
			} else if (str_begins(*params, "r=", &value)) {
				if (str_to_intmax(value, &ctx->rounds) < 0 ||
				    ctx->rounds < 1) {
					*error_r = "Invalid input";
					return -1;
				}
			} else {
				*error_r = "Invalid input";
				return -1;
			}
		}
	} else {
		ctx->iv = t_buffer_create(32);
		hex_to_binary(parts[0], ctx->iv);
	}
	ctx->input = t_buffer_create(strlen(parts[1]) / 2);
	hex_to_binary(parts[1], ctx->input);
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

static const char salt_chars[] =
	"#&()*+-./0123456789:;<>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"[]^_`abcdefghijklmnopqrstuvwxyz{|}";

static const char *make_salt(size_t len)
{
	string_t *tmp = t_str_new(len);
	for (size_t i = 0; i < len; i++)
		str_append_c(tmp, salt_chars[i_rand_limit(sizeof(salt_chars)-1)]);
	return str_c(tmp);
}

static int var_expand_crypt_settings(struct var_expand_state *state,
				     const struct var_expand_statement *stmt,
				     struct var_expand_crypt_context *ctx,
				     const char **error_r)
{
	const char *iv;
	const char *enckey = NULL;
	const char *hash = VAR_EXPAND_CRYPT_DEFAULT_HASH;
	ctx->rounds = VAR_EXPAND_CRYPT_DEFAULT_ROUNDS;

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
			if (ctx->salt != NULL) {
				*error_r = "Cannot use both salt and iv";
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
		} else if (strcmp(key, "salt") == 0) {
			if (var_expand_parameter_string_or_var(state, par, &ctx->salt,
							       error_r) < 0) {
				return -1;
			}
			if (ctx->iv != NULL) {
				*error_r = "Cannot use both salt and iv";
				return -1;
			}
		} else if (strcmp(key, "hash") == 0) {
			if (var_expand_parameter_string_or_var(state, par, &hash,
							     error_r) < 0)
				return -1;
		} else if (strcmp(key, "rounds") == 0) {
			if (var_expand_parameter_number_or_var(state, par,
							       &ctx->rounds,
							       error_r) < 0)
				return -1;
			if (ctx->rounds < 1) {
				*error_r = "rounds must be positive integer";
				return -1;
			}
		} else
			ERROR_UNSUPPORTED_KEY(key);
	}

	if (enckey == NULL) {
		*error_r = "Encryption key missing";
		return -1;
	}

	ERROR_IF_NO_TRANSFER_TO(stmt->function);

	ctx->input = state->transfer;
	if (!ctx->raw && strcmp(stmt->function, "decrypt") == 0) {
		/* handle $ separated input, only support hex */
		const char *const *parts = t_strsplit(str_c(state->transfer), "$");
		if (str_array_length(parts) != 3 || *parts[2] != '\0') {
			*error_r = "Invalid input format";
			return -1;
		} else if (parse_parameters(ctx, parts, error_r) < 0)
			return -1;
	} else if (ctx->raw && ctx->iv == NULL && ctx->salt == NULL) {
		*error_r = "In raw format, salt or IV must be given";
		return -1;
	}

	if (ctx->iv == NULL) {
		if (ctx->salt == NULL)
			ctx->salt = make_salt(VAR_EXPAND_CRYPT_DEFAULT_SALT_LEN);
		buffer_t *keymaterial = t_buffer_create(48);
		/* figure out how much material we need */
		struct dcrypt_context_symmetric *sym_ctx;
		if (!dcrypt_ctx_sym_create(ctx->algo, DCRYPT_MODE_ENCRYPT,
					   &sym_ctx, error_r))
			return -1;
		size_t enckey_len = dcrypt_ctx_sym_get_key_length(sym_ctx);
		size_t iv_len = dcrypt_ctx_sym_get_iv_length(sym_ctx);
		dcrypt_ctx_sym_destroy(&sym_ctx);
		if (!dcrypt_pbkdf2((unsigned char*)enckey, strlen(enckey),
				   (unsigned char*)ctx->salt, strlen(ctx->salt),
				   hash, ctx->rounds, keymaterial,
				   enckey_len + iv_len, error_r))
			return -1;
		const unsigned char *data = keymaterial->data;
		ctx->enckey = t_buffer_create(enckey_len);
		ctx->iv = t_buffer_create(iv_len);
		buffer_append(ctx->enckey, data, enckey_len);
		buffer_append(ctx->iv, data + enckey_len, iv_len);
	} else {
		ctx->enckey = t_buffer_create(strlen(enckey) / 2);
		hex_to_binary(enckey, ctx->enckey);
	}

	/* IV can be optional in some algorithms */
	i_assert(ctx->enckey->used > 0);

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
			if (ctx.salt != NULL) {
				str_printfa(state->transfer, "s=%s,r=%jd",
					    ctx.salt, ctx.rounds);
			} else
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
	/* do not initialize dcrypt here - saves a lot of memory
	   to not load openssl every time. Only load it if
	   needed */

	expansion_filter_crypt_set_functions(var_expand_encrypt,
					     var_expand_decrypt);
}

void var_expand_crypt_deinit(void)
{
}
