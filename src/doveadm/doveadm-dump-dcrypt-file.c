/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dcrypt.h"
#include "istream.h"
#include "istream-decrypt.h"
#include "dcrypt-iostream.h"
#include "doveadm-dump.h"
#include <stdio.h>

static int get_digest(const char *digest,
		struct dcrypt_private_key **priv_key_r ATTR_UNUSED,
		const char **error_r ATTR_UNUSED,
		void *context)
{
	const char **digest_r = (const char**)context;
	*digest_r = t_strdup(digest);
	return 0;
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

static bool dcrypt_file_dump_metadata(const char *filename, bool print)
{
	bool ret = FALSE;
	struct istream *is = i_stream_create_file(filename, IO_BLOCK_SIZE);
	const char *key_digest = NULL;
	struct istream *ds = i_stream_create_decrypt_callback(is,
			get_digest, &key_digest);

	ssize_t size = i_stream_read(ds);
	i_assert(size < 0);

	if (key_digest != NULL) {
		ret = TRUE;
		if (print) {
			dcrypt_istream_dump_metadata(ds);
			printf("decrypt key digest: %s\n", key_digest);
		}
	} else if (print && ds->stream_errno != 0) {
		i_error("read(%s) failed: %s",
			i_stream_get_name(ds),
			i_stream_get_error(ds));
	}

	i_stream_unref(&ds);
	i_stream_unref(&is);
	return ret;
}

static bool test_dump_dcrypt_file(const char *path)
{
	if (!dcrypt_initialize("openssl", NULL, NULL))
		return FALSE;
	bool ret = dcrypt_file_dump_metadata(path, FALSE);
	return ret;
}

static void cmd_dump_dcrypt_file(int argc ATTR_UNUSED, char *argv[])
{
	const char *error = NULL;
	if (!dcrypt_initialize("openssl", NULL, &error))
		i_fatal("dcrypt_initialize failed: %s", error);
	(void)dcrypt_file_dump_metadata(argv[1], TRUE);
}

struct doveadm_cmd_dump doveadm_cmd_dump_dcrypt_file = {
	"dcrypt-file",
	test_dump_dcrypt_file,
	cmd_dump_dcrypt_file
};
