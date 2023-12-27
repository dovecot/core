/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dcrypt.h"
#include "dcrypt-iostream.h"
#include "ostream-encrypt.h"
#include "istream-private.h"
#include "istream-decrypt.h"
#include "doveadm-dump.h"
#include "hex-binary.h"
#include "str.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

struct dcrypt_dump_context {
	const char *key;
	struct dcrypt_private_key *dec_key;
	const char *password;
	enum dcrypt_key_format dump_format;
	bool dump_key;
};

static int load_key_from_file(const char *file, const char **data_r,
			      const char **error_r)
{
	const char *error;
	string_t *keybuf = t_buffer_create(256);
	if (buffer_append_full_file(keybuf, file, SIZE_MAX, &error) !=
	    BUFFER_APPEND_OK) {
		*error_r = t_strdup_printf("read(%s) failed: %s", file, error);
		return -1;
	}
	*data_r = t_str_rtrim(str_c(keybuf), "\r\n\t ");
	return 0;
}

static void
dcrypt_dump_public_key_metadata(struct doveadm_cmd_context *cctx,
				const char *buf,
				const struct dcrypt_dump_context *ctx)
{
	const char *error = NULL;
	struct dcrypt_public_key *pub_key;

	bool ret = dcrypt_key_load_public(&pub_key, buf, &error);
	if (ret == FALSE) {
		e_error(cctx->event, "dcrypt_key_load_public failed: %s", error);
		return;
	}
	enum dcrypt_key_type key_type = dcrypt_key_type_public(pub_key);
	if (key_type == DCRYPT_KEY_RSA)
		printf("key type: DCRYPT_KEY_RSA\n");
	else if (key_type == DCRYPT_KEY_EC)
		printf("key type: DCRYPT_KEY_EC\n");

	string_t *hash = t_str_new(128);
	if (!dcrypt_key_id_public(pub_key, "sha256", hash, &error)) {
		e_error(cctx->event, "dcrypt_key_id_public failed: %s", error);
	} else {
		const char *v2_hash = binary_to_hex(hash->data, hash->used);
		printf("v2 hash: %s\n", v2_hash);

		if (key_type == DCRYPT_KEY_EC) {
			buffer_set_used_size(hash, 0);
			if (!dcrypt_key_id_public_old(pub_key, hash, &error)) {
				e_error(cctx->event,
					"dcrypt_key_id_public_old failed: %s",
					error);
			} else {
				const char *v1_hash = binary_to_hex(hash->data,
								    hash->used);
				printf("v1 hash: %s\n", v1_hash);
			}
		}
	}

	if (ctx->dump_key) {
		string_t *keybuf = t_str_new(512);
		if (!dcrypt_key_store_public(pub_key, ctx->dump_format, keybuf,
					     &error))
			i_fatal("%s", error);
		printf("Key:\n\n%s\n", str_c(keybuf));
	}

	dcrypt_key_unref_public(&pub_key);
}

static void
dcrypt_dump_private_key_metadata(struct doveadm_cmd_context *cctx,
				 const char *buf,
				 const struct dcrypt_dump_context *ctx)
{
	const char *error = NULL;
	struct dcrypt_private_key *priv_key, *dec_priv_key = NULL;

	if (ctx->key != NULL) {
		enum dcrypt_key_kind kind;
		enum dcrypt_key_encryption_type encryption_type;
		const char *dec_priv_key_data;

		if (load_key_from_file(ctx->key, &dec_priv_key_data, &error) <
		    0) {
			e_error(cctx->event, "%s", error);
			return;
		}

		if (!dcrypt_key_string_get_info(dec_priv_key_data, NULL, NULL,
						&kind, &encryption_type, NULL,
						NULL, &error)) {
			e_error(cctx->event, "%s: %s", ctx->key, error);
			return;
		}
		if (kind != DCRYPT_KEY_KIND_PRIVATE) {
			e_error(cctx->event,
				"Decryption key %s is not private key",
				ctx->key);
			return;
		}

		const char *dec_key_pw =
			encryption_type == DCRYPT_KEY_ENCRYPTION_TYPE_NONE ?
				      NULL :
				      ctx->password;
		/* load key */
		if (!dcrypt_key_load_private(&dec_priv_key, dec_priv_key_data,
					     dec_key_pw, NULL, &error)) {
			e_error(cctx->event,
				"crypt_key_load_private failed for %s: %s",
				ctx->key, error);
			return;
		}
	}

	const char *dec_pw = dec_priv_key == NULL ? ctx->password : NULL;

	bool ret = dcrypt_key_load_private(&priv_key, buf, dec_pw, dec_priv_key,
					   &error);
	dcrypt_key_unref_private(&dec_priv_key);
	if (ret == FALSE) {
		e_error(cctx->event, "dcrypt_key_load_private failed: %s", error);
		return;
	}
	enum dcrypt_key_type key_type = dcrypt_key_type_private(priv_key);
	if (key_type == DCRYPT_KEY_RSA)
		printf("key type: DCRYPT_KEY_RSA\n");
	else if (key_type == DCRYPT_KEY_EC)
		printf("key type: DCRYPT_KEY_EC\n");

	string_t *hash = t_str_new(128);
	if (!dcrypt_key_id_private(priv_key, "sha256", hash, &error)) {
		e_error(cctx->event, "dcrypt_key_id_private failed: %s", error);
	} else {
		const char *v2_hash = binary_to_hex(hash->data, hash->used);
		printf("v2 hash: %s\n", v2_hash);

		if (key_type == DCRYPT_KEY_EC) {
			buffer_set_used_size(hash, 0);
			if (!dcrypt_key_id_private_old(priv_key, hash, &error)) {
				e_error(cctx->event,
					"dcrypt_key_id_private_old failed: %s", error);
			} else {
				const char *v1_hash = binary_to_hex(hash->data,
								    hash->used);
				printf("v1 hash: %s\n", v1_hash);
			}
		}
	}

	if (ctx->dump_key) {
		string_t *keybuf = t_str_new(512);
		if (!dcrypt_key_store_private(priv_key, ctx->dump_format, NULL,
					      keybuf, NULL, NULL, &error))
			i_fatal("%s", error);
		printf("Key:\n\n%s\n", str_c(keybuf));
	}

	dcrypt_key_unref_private(&priv_key);
}

static bool dcrypt_key_dump_metadata(struct doveadm_cmd_context *cctx,
				     const char *filename, bool print,
				     const struct dcrypt_dump_context *ctx)
{
	bool ret = TRUE;
	enum dcrypt_key_format format;
	enum dcrypt_key_version version;
	enum dcrypt_key_kind kind;
	enum dcrypt_key_encryption_type encryption_type;
	const char *encryption_key_hash;
	const char *key_hash;
	const char *error;
	const char *data;

	if (load_key_from_file(filename, &data, &error) < 0) {
		if (print)
			e_error(cctx->event, "%s", error);
		return FALSE;
	}

	ret = dcrypt_key_string_get_info(data, &format, &version, &kind,
					 &encryption_type, &encryption_key_hash,
					 &key_hash, &error);
	if (ret == FALSE) {
		if (print) e_error(cctx->event,
			   "dcrypt_key_string_get_info failed: %s", error);
		return FALSE;
	}
	if (!print) return TRUE;

	switch (format) {
	case DCRYPT_FORMAT_PEM:
		printf("format: DCRYPT_FORMAT_PEM\n");
		break;
	case DCRYPT_FORMAT_DOVECOT:
		printf("format: DCRYPT_FORMAT_DOVECOT\n");
		break;
	case DCRYPT_FORMAT_JWK:
		printf("format: DCRYPT_FORMAT_JWK\n");
	}

	switch (version) {
	case DCRYPT_KEY_VERSION_1:
		printf("version: DCRYPT_KEY_VERSION_1\n");
		break;
	case DCRYPT_KEY_VERSION_2:
		printf("version: DCRYPT_KEY_VERSION_2\n");
		break;
	case DCRYPT_KEY_VERSION_NA:
		printf("version: DCRYPT_KEY_VERSION_NA\n");
		break;
	}

	switch (kind) {
	case DCRYPT_KEY_KIND_PUBLIC:
		printf("kind: DCRYPT_KEY_KIND_PUBLIC\n");
		break;
	case DCRYPT_KEY_KIND_PRIVATE:
		printf("kind: DCRYPT_KEY_KIND_PRIVATE\n");
		break;
	}

	switch (encryption_type) {
	case DCRYPT_KEY_ENCRYPTION_TYPE_NONE:
		printf("encryption_type: DCRYPT_KEY_ENCRYPTION_TYPE_NONE\n");
		break;
	case DCRYPT_KEY_ENCRYPTION_TYPE_KEY:
		printf("encryption_type: DCRYPT_KEY_ENCRYPTION_TYPE_KEY\n");
		break;
	case DCRYPT_KEY_ENCRYPTION_TYPE_PASSWORD:
		printf("encryption_type: DCRYPT_KEY_ENCRYPTION_TYPE_PASSWORD\n");
		break;
	}

	if (encryption_key_hash != NULL)
		printf("encryption_key_hash: %s\n", encryption_key_hash);
	if (key_hash != NULL)
		printf("key_hash: %s\n", key_hash);

	switch (kind) {
	case DCRYPT_KEY_KIND_PUBLIC:
		dcrypt_dump_public_key_metadata(cctx, data, ctx);
		break;
	case DCRYPT_KEY_KIND_PRIVATE:
		if (encryption_type == DCRYPT_KEY_ENCRYPTION_TYPE_NONE ||
		    (ctx->key != NULL || ctx->password != NULL))
			dcrypt_dump_private_key_metadata(cctx, data, ctx);
		break;
	}
	return TRUE;
}

static bool test_dump_dcrypt_key(struct doveadm_cmd_context *cctx,
				 const char *path)
{
	const char *error;
	struct dcrypt_dump_context ctx;
	i_zero(&ctx);

	if (!dcrypt_initialize("openssl", NULL, &error)) {
		e_error(cctx->event, "%s", error);
		return FALSE;
	}
	bool ret = dcrypt_key_dump_metadata(cctx, path, FALSE, &ctx);
	return ret;
}

static void cmd_dump_dcrypt_key(struct doveadm_cmd_context *cctx,
				const char *path, const char *const *args)
{
	const char *error = NULL;
	struct dcrypt_dump_context ctx;
	i_zero(&ctx);

	if (!dcrypt_initialize("openssl", NULL, &error))
		i_fatal("dcrypt_initialize: %s", error);
	for (; *args != NULL; args++) {
		const char *key, *value;
		if (!t_split_key_value_eq(*args, &key, &value))
			i_fatal("Invalid argument '%s': Missing '='", *args);
		if (strcmp(key, "private_key") == 0)
			ctx.key = value;
		else if (strcmp(key, "password") == 0)
			ctx.password = value;
		else if (strcmp(key, "dump") == 0) {
			ctx.dump_key = TRUE;
			if (strcasecmp(value, "pem") == 0)
				ctx.dump_format = DCRYPT_FORMAT_PEM;
			else if (strcasecmp(value, "dovecot") == 0)
				ctx.dump_format = DCRYPT_FORMAT_DOVECOT;
			else if (strcasecmp(value, "jwk") == 0)
				ctx.dump_format = DCRYPT_FORMAT_JWK;
			else
				i_fatal("Unsupported dump format '%s'", value);
		} else
			i_fatal("Unsupported argument '%s'", key);
	}

	(void)dcrypt_key_dump_metadata(cctx, path, TRUE, &ctx);
}

struct doveadm_cmd_dump doveadm_cmd_dump_dcrypt_key = {
	"dcrypt-key",
	test_dump_dcrypt_key,
	cmd_dump_dcrypt_key
};
