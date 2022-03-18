/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "ostream.h"
#include "path-util.h"
#include "randgen.h"
#include "test-common.h"
#include "hex-binary.h"
#include "fs-api.h"
#include "fs-api-private.h"
#include "dcrypt.h"

#include <unistd.h>

const char *private_key_pem = "-----BEGIN PRIVATE KEY-----\n"
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYIufJZZe2Y6iFz5x\n"
"koIoysb3dZLZWsyekjOc/GjsLd2hRANCAASnIWgQuhE8jqALcmfiunRyEk7vkq/y\n"
"a9vYK50b3cFhCsLU4tfVTLkB1Y/6VlZj63QKMzXNvk5G5OD1ofElcpyj\n"
"-----END PRIVATE KEY-----";
const char *public_key_pem = "-----BEGIN PUBLIC KEY-----\n"
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpyFoELoRPI6gC3Jn4rp0chJO75Kv\n"
"8mvb2CudG93BYQrC1OLX1Uy5AdWP+lZWY+t0CjM1zb5ORuTg9aHxJXKcow==\n"
"-----END PUBLIC KEY-----";

extern const struct fs fs_class_crypt;

static struct fs_settings test_fs_set;

static void test_setup(void)
{
	struct fs *fs;
	struct fs_file *file;
	const char *error;

	test_fs_set.base_dir = ".";
	test_fs_set.temp_dir = ".";

	i_unlink_if_exists("test_public_key.pem");
	i_unlink_if_exists("test_private_key.pem");

	fs_class_register(&fs_class_posix);
	fs_class_register(&fs_class_crypt);

	if (fs_init_from_string("posix", &test_fs_set, &fs, &error) < 0)
		 i_fatal("fs_init(posix) failed: %s", error);
	/* write keys to disk */
	file = fs_file_init(fs, "test_public_key.pem", FS_OPEN_MODE_CREATE);
	if (fs_write(file, public_key_pem, strlen(public_key_pem)) < 0) {
		i_fatal("fs_write(test_public_key.pem) failed: %s",
			fs_file_last_error(file));
	}
	fs_file_deinit(&file);
	file = fs_file_init(fs, "test_private_key.pem", FS_OPEN_MODE_CREATE);
	if (fs_write(file, private_key_pem, strlen(private_key_pem)) < 0) {
		i_fatal("fs_write(test_private_key.pem) failed: %s",
			fs_file_last_error(file));
	}
	fs_file_deinit(&file);
	fs_deinit(&fs);
}

static void test_fs_crypt_read_write(void)
{
	test_begin("fs-crypt: read write");
	const char *error;
	struct fs *fs;

	if (fs_init_from_string("crypt:public_key_path=test_public_key.pem:"
				"private_key_path=test_private_key.pem:posix",
				&test_fs_set, &fs, &error) < 0)
		i_fatal("fs_init(crypt:posix) failed: %s", error);

	i_unlink_if_exists("test_file");
	/* write some data to disk */
	unsigned char databuf[128];
	random_fill(databuf, sizeof(databuf));

	struct fs_file *file = fs_file_init(fs, "test_file", FS_OPEN_MODE_CREATE);
	struct ostream *os = fs_write_stream(file);
	test_assert(o_stream_send(os, databuf, sizeof(databuf)) == sizeof(databuf));
	test_assert(o_stream_finish(os) == 1);
	fs_write_stream_finish(file, &os);
	fs_file_deinit(&file);

	file = fs_file_init(fs, "test_file", FS_OPEN_MODE_READONLY);

	struct istream *is = fs_read_stream(file, 8192);
	buffer_t *readbuf = t_buffer_create(sizeof(databuf));
	int ret;

	while ((ret = i_stream_read(is)) > 0) {
		size_t size;
		const unsigned char *data = i_stream_get_data(is, &size);
		buffer_append(readbuf, data, size);
		i_stream_skip(is, size);
	}

	test_assert(ret == -1);
	test_assert(is->stream_errno == 0);
	test_assert(is->eof);
	test_assert(readbuf->used == sizeof(databuf) &&
		    memcmp(readbuf->data, databuf, sizeof(databuf)) == 0);
	i_stream_unref(&is);

	fs_file_deinit(&file);
	fs_deinit(&fs);

	test_end();
}

static void test_fs_crypt_read_write_0(void)
{
	test_begin("fs-crypt: read write (size=0)");
	const char *error;
	struct fs *fs;

	if (fs_init_from_string("crypt:public_key_path=test_public_key.pem:"
				"private_key_path=test_private_key.pem:posix",
				&test_fs_set, &fs, &error) < 0)
		i_fatal("fs_init(crypt:posix) failed: %s", error);

	i_unlink_if_exists("test_file");
	/* write nothing to disk */

	struct fs_file *file = fs_file_init(fs, "test_file", FS_OPEN_MODE_CREATE);
	struct ostream *os = fs_write_stream(file);
	test_assert(o_stream_finish(os) == 1);
	fs_write_stream_finish(file, &os);
	fs_file_deinit(&file);

	/* check that the result file is empty */
	struct stat st;
	if (stat("test_file", &st) < 0)
		i_fatal("stat(test_file) failed: %m");
	test_assert_ucmp(st.st_size, ==, 0);

	file = fs_file_init(fs, "test_file", FS_OPEN_MODE_READONLY);

	struct istream *is = fs_read_stream(file, 8192);
	test_assert(i_stream_read(is) == -1);
	test_assert(is->v_offset == 0);
	test_assert(is->stream_errno == 0);
	test_assert(is->eof);
	i_stream_unref(&is);

	fs_file_deinit(&file);
	fs_deinit(&fs);

	test_end();
}

static void test_fs_crypt_read_write_unencrypted(void)
{
	test_begin("fs-crypt: read write (maybe encrypted)");
	const char *error;
	struct fs *fs;

	if (fs_init_from_string("crypt:public_key_path=:"
				"private_key_path=test_private_key.pem:"
				"maybe:posix",
				&test_fs_set, &fs, &error) < 0)
		i_fatal("fs_init(crypt:posix) failed: %s", error);

	i_unlink_if_exists("test_file");
	/* write some data to disk */
	unsigned char databuf[128];
	/* avoid being detected as crypted */
	memset(databuf, '\1', 8);
	random_fill(databuf+8, sizeof(databuf)-8);

	struct fs_file *file = fs_file_init(fs, "test_file", FS_OPEN_MODE_CREATE);
	struct ostream *os = fs_write_stream(file);
	test_assert(o_stream_send(os, databuf, sizeof(databuf)) == sizeof(databuf));
	test_assert(o_stream_finish(os) == 1);
	fs_write_stream_finish(file, &os);
	fs_file_deinit(&file);

	file = fs_file_init(fs, "test_file", FS_OPEN_MODE_READONLY);

	struct istream *is = fs_read_stream(file, 8192);
	buffer_t *readbuf = t_buffer_create(sizeof(databuf));
	int ret;

	while ((ret = i_stream_read(is)) > 0) {
		size_t size;
		const unsigned char *data = i_stream_get_data(is, &size);
		buffer_append(readbuf, data, size);
		i_stream_skip(is, size);
	}

	test_assert(ret == -1);
	test_assert(is->eof);
	test_assert(readbuf->used == sizeof(databuf) &&
		    memcmp(readbuf->data, databuf, sizeof(databuf)) == 0);
	i_stream_unref(&is);

	fs_file_deinit(&file);
	fs_deinit(&fs);

	if (fs_init_from_string("crypt:public_key_path=test_public_key.pem:"
				"private_key_path=test_private_key.pem:"
				"maybe:posix",
				&test_fs_set, &fs, &error) < 0)
		i_fatal("fs_init(crypt:posix) failed: %s", error);

	i_unlink_if_exists("test_file");
	/* write some data to disk */
	random_fill(databuf, sizeof(databuf));

	file = fs_file_init(fs, "test_file", FS_OPEN_MODE_CREATE);
	os = fs_write_stream(file);
	test_assert(o_stream_send(os, databuf, sizeof(databuf)) == sizeof(databuf));
	test_assert(o_stream_finish(os) == 1);
	fs_write_stream_finish(file, &os);
	fs_file_deinit(&file);

	file = fs_file_init(fs, "test_file", FS_OPEN_MODE_READONLY);

	is = fs_read_stream(file, 8192);
	readbuf = t_buffer_create(sizeof(databuf));

	while ((ret = i_stream_read(is)) > 0) {
		size_t size;
		const unsigned char *data = i_stream_get_data(is, &size);
		buffer_append(readbuf, data, size);
		i_stream_skip(is, size);
	}

	test_assert(ret == -1);
	test_assert(is->eof);
	test_assert(readbuf->used == sizeof(databuf) &&
		    memcmp(readbuf->data, databuf, sizeof(databuf)) == 0);
	i_stream_unref(&is);

	fs_file_deinit(&file);
	fs_deinit(&fs);

	test_end();
}

static void test_teardown(void)
{
	i_unlink_if_exists("test_public_key.pem");
	i_unlink_if_exists("test_private_key.pem");
	i_unlink_if_exists("test_file");
}

static bool test_init_dcrypt(void)
{
	const char *error;
	struct dcrypt_settings set = {
		.module_dir = top_builddir"/src/lib-dcrypt/.libs"
	};
	if (!dcrypt_initialize(NULL, &set, &error)) {
		i_error("No functional dcrypt backend found - "
			"skipping tests: %s", error);
		return FALSE;
	}
	return TRUE;
}

int main(void)
{
	if (!test_init_dcrypt())
		return 0;
	void (*const tests[])(void)  = {
		test_setup,
		test_fs_crypt_read_write,
		test_fs_crypt_read_write_0,
		test_fs_crypt_read_write_unencrypted,
		test_teardown,
		NULL
	};
	int ret = test_run(tests);
	dcrypt_deinitialize();
	return ret;
}
