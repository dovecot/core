/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "hex-binary.h"
#include "str.h"
#include "dcrypt.h"
#include "write-full.h"
#include "istream.h"
#include "istream-decrypt.h"
#include "dcrypt-iostream.h"
#include "doveadm-dump.h"
#include <stdio.h>
#include <unistd.h>

struct dcrypt_dump_context {
	const char *key;
	struct dcrypt_private_key *dec_key;
	const char *password;
	char *digest;
};

static int get_digest(const char *digest,
		      struct dcrypt_private_key **priv_key_r,
		      const char **error_r, void *context)
{
	struct dcrypt_dump_context *ctx = context;
	ctx->digest = i_strdup(digest);
	string_t *keydata = t_str_new(4096);
	struct dcrypt_private_key *priv;
	if (buffer_append_full_file(keydata, ctx->key, SIZE_MAX, error_r) !=
	    BUFFER_APPEND_OK)
		return -1;
	if (!dcrypt_key_load_private(&priv, str_c(keydata), ctx->password,
				     ctx->dec_key, error_r))
		return -1;
	/* check digest */
	buffer_t *id = t_buffer_create(32);
	if (!dcrypt_key_id_private(priv, "sha256", id, error_r))
		return -1;
	if (strcmp(binary_to_hex(id->data, id->used), digest) != 0) {
		dcrypt_key_unref_private(&priv);
		return 0;
	}
	*priv_key_r = priv;
	return 1;
}

static void dcrypt_istream_dump_metadata(const struct istream *stream)
{
	enum io_stream_encrypt_flags flags = i_stream_encrypt_get_flags(stream);
	if ((flags & IO_STREAM_ENC_INTEGRITY_HMAC) != 0)
		printf("flags: IO_STREAM_ENC_INTEGRITY_HMAC\n");
	if ((flags & IO_STREAM_ENC_INTEGRITY_AEAD) != 0)
		printf("flags: IO_STREAM_ENC_INTEGRITY_AEAD\n");
	if ((flags & IO_STREAM_ENC_INTEGRITY_NONE) != 0)
		printf("flags: IO_STREAM_ENC_INTEGRITY_NONE\n");
	if ((flags & IO_STREAM_ENC_VERSION_1) != 0)
		printf("flags: IO_STREAM_ENC_VERSION_1\n");

	enum decrypt_istream_format format = i_stream_encrypt_get_format(stream);
	switch (format) {
	case DECRYPT_FORMAT_V1:
		printf("format: DECRYPT_FORMAT_V1\n");
		break;
	case DECRYPT_FORMAT_V2:
		printf("format: DECRYPT_FORMAT_V2\n");
		break;
	}
}

static bool dcrypt_file_dump_metadata(struct doveadm_cmd_context *cctx,
				      const char *filename, bool print,
				      struct dcrypt_dump_context *ctx)
{
	bool ret = FALSE;
	struct istream *is = i_stream_create_file(filename, IO_BLOCK_SIZE);
	struct istream *ds =
		i_stream_create_decrypt_callback(is, get_digest, ctx);

	size_t size;
	const unsigned char *data;
	ssize_t ret2 = i_stream_read(ds);

	i_assert(ctx->key != NULL || ret2 < 2);

	if (ctx->digest != NULL) {
		ret = TRUE;
		if (print) {
			dcrypt_istream_dump_metadata(ds);
			printf("decrypt key digest: %s\n", ctx->digest);
		}
	} else if (print && ds->stream_errno != 0) {
		e_error(cctx->event, "read(%s) failed: %s",
			i_stream_get_name(ds), i_stream_get_error(ds));
	}

	if (print && ctx->key != NULL) {
		while (i_stream_read_more(ds, &data, &size) > 0) {
			if (write_full(STDOUT_FILENO, data, size) < 0)
				i_fatal("write(STDOUT) failed: %m");
			i_stream_skip(ds, size);
		}
		if (ds->stream_errno != 0) {
			i_error("read(%s) failed: %s", i_stream_get_name(ds),
				i_stream_get_error(ds));
		}
	}

	i_stream_unref(&ds);
	i_stream_unref(&is);
	i_free(ctx->digest);
	return ret;
}

static bool test_dump_dcrypt_file(struct doveadm_cmd_context *cctx,
				  const char *path)
{
	const char *error;
	struct dcrypt_dump_context ctx;
	i_zero(&ctx);
	if (!dcrypt_initialize("openssl", NULL, &error)) {
		e_error(cctx->event, "%s", error);
		return FALSE;
	}
	bool ret = dcrypt_file_dump_metadata(cctx, path, FALSE, &ctx);
	return ret;
}

static void cmd_dump_dcrypt_file(struct doveadm_cmd_context *cctx,
				 const char *path, const char *const *args)
{
	const char *error = NULL;
	struct dcrypt_dump_context ctx;
	i_zero(&ctx);
	if (!dcrypt_initialize("openssl", NULL, &error))
		i_fatal("dcrypt_initialize failed: %s", error);
	for (; *args != NULL; args++) {
		const char *key, *value;
		if (!t_split_key_value_eq(*args, &key, &value))
			i_fatal("Invalid argument '%s': Missing '='", *args);
		if (strcmp(key, "private_key") == 0)
			ctx.key = value;
		else if (strcmp(key, "password") == 0)
			ctx.password = value;
		else
			i_fatal("Unsupported argument '%s'", key);
	}
	(void)dcrypt_file_dump_metadata(cctx, path, TRUE, &ctx);
}

struct doveadm_cmd_dump doveadm_cmd_dump_dcrypt_file = {
	"dcrypt-file",
	test_dump_dcrypt_file,
	cmd_dump_dcrypt_file
};
