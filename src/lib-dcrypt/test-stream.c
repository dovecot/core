/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "dcrypt.h"
#include "dcrypt-iostream.h"
#include "ostream.h"
#include "ostream-encrypt.h"
#include "istream.h"
#include "istream-decrypt.h"
#include "istream-hash.h"
#include "istream-base64.h"
#include "randgen.h"
#include "hash-method.h"
#include "test-common.h"
#include "hex-binary.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>

static const char key_v1_priv[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIGpAgEAMBAGByqGSM49AgEGBSuBBAAjBIGRMIGOAgEBBEGz2V2VMi/5s+Z+GJh7\n"
	"4WfqZjZUpqqm+NJWojm6BbrZMY+9ZComlTGVcUZ007acFxV93oMmrfmtRUb5ynrb\n"
	"MRFskKFGA0QAAwHrAJc8TvyPzspOoz6UH1C1YRmaUVm8tsLu2d0dYtZeOKJUl52J\n"
	"4o8MKIg+ce4q0mTNFrhj+glKj29ppWti6JGAQA==\n"
	"-----END PRIVATE KEY-----";

static const char key_v1_pub[] =
	"-----BEGIN PUBLIC KEY-----\n"
	"MFgwEAYHKoZIzj0CAQYFK4EEACMDRAADAesAlzxO/I/Oyk6jPpQfULVhGZpRWby2\n"
	"wu7Z3R1i1l44olSXnYnijwwoiD5x7irSZM0WuGP6CUqPb2mla2LokYBA\n"
	"-----END PUBLIC KEY-----";

static const char key_v2_priv[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgtuQJA+uboZWVwgHc\n"
	"DciyVdrovAPwlMqshDK3s78IDDuhRANCAAQm0VEdzLB9PtD0HA8JK1zifWnj8M00\n"
	"FQzedfp9SQsWyA8dzs5/NFR5MTe6Xbh/ndKEs1zZH3vZ4FlNrilZc0st\n"
	"-----END PRIVATE KEY-----";

static const char key_v2_pub[] =
	"-----BEGIN PUBLIC KEY-----\n"
	"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJtFRHcywfT7Q9BwPCStc4n1p4/DN\n"
	"NBUM3nX6fUkLFsgPHc7OfzRUeTE3ul24f53ShLNc2R972eBZTa4pWXNLLQ==\n"
	"-----END PUBLIC KEY-----";

static const char test_sample_v1_hash[] =
	"1d7cc2cc1f1983f76241cc42389911e88590ad58cf9d54cafeb5b198d3723dd1";
static const char test_sample_v1_short_hash[] =
	"b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c";
static const char test_sample_v2_hash[] =
	"2e31218656dd34db65b321688bf418dee4ee785e99eb9c21e0d29b4af27a863e";

static struct dcrypt_keypair test_v1_kp;
static struct dcrypt_keypair test_v2_kp;

static void test_static_v1_input(void)
{
	ssize_t siz;
	const struct hash_method *hash = hash_method_lookup("sha256");
	unsigned char hash_ctx[hash->context_size];
	unsigned char hash_dgst[hash->digest_size];
	hash->init(hash_ctx);

	test_begin("test_static_v1_input");

	struct istream *is_1 =
		i_stream_create_file(DCRYPT_SRC_DIR"/sample-v1.asc",
				     IO_BLOCK_SIZE);
	struct istream *is_2 = i_stream_create_base64_decoder(is_1);
	i_stream_unref(&is_1);
	struct istream *is_3 = i_stream_create_decrypt(is_2, test_v1_kp.priv);
	i_stream_unref(&is_2);
	struct istream *is_4 = i_stream_create_hash(is_3, hash, hash_ctx);
	i_stream_unref(&is_3);

	while((siz = i_stream_read(is_4))>0) { i_stream_skip(is_4, siz); }

	if (is_4->stream_errno != 0)
		i_debug("error: %s", i_stream_get_error(is_4));

	test_assert(is_4->stream_errno == 0);

	i_stream_unref(&is_4);

	hash->result(hash_ctx, hash_dgst);

	test_assert(strcmp(test_sample_v1_hash,
			   binary_to_hex(hash_dgst, sizeof(hash_dgst))) == 0);

	test_end();
}

static void test_static_v1_input_short(void)
{
	ssize_t siz;
	const struct hash_method *hash = hash_method_lookup("sha256");
	unsigned char hash_ctx[hash->context_size];
	unsigned char hash_dgst[hash->digest_size];
	hash->init(hash_ctx);

	test_begin("test_static_v1_input_short");

	struct istream *is_1 =
		i_stream_create_file(DCRYPT_SRC_DIR"/sample-v1_short.asc",
				     IO_BLOCK_SIZE);
	struct istream *is_2 = i_stream_create_base64_decoder(is_1);
	i_stream_unref(&is_1);
	struct istream *is_3 = i_stream_create_decrypt(is_2, test_v1_kp.priv);
	i_stream_unref(&is_2);
	struct istream *is_4 = i_stream_create_hash(is_3, hash, hash_ctx);
	i_stream_unref(&is_3);

	while((siz = i_stream_read(is_4))>0) { i_stream_skip(is_4, siz); }

	if (is_4->stream_errno != 0)
		i_debug("error: %s", i_stream_get_error(is_4));

	test_assert(is_4->stream_errno == 0);

	i_stream_unref(&is_4);

	hash->result(hash_ctx, hash_dgst);

	test_assert(strcmp(test_sample_v1_short_hash,
			   binary_to_hex(hash_dgst, sizeof(hash_dgst))) == 0);

	test_end();
}

static void test_static_v2_input(void)
{
	test_begin("test_static_v2_input");

	ssize_t amt;
	const struct hash_method *hash = hash_method_lookup("sha256");
	unsigned char hash_ctx[hash->context_size];
	unsigned char hash_dgst[hash->digest_size];
	hash->init(hash_ctx);

	struct istream *is_1 =
		i_stream_create_file(DCRYPT_SRC_DIR"/sample-v2.asc",
				     IO_BLOCK_SIZE);
	struct istream *is_2 = i_stream_create_base64_decoder(is_1);
	i_stream_unref(&is_1);
	struct istream *is_3 = i_stream_create_decrypt(is_2, test_v2_kp.priv);
	i_stream_unref(&is_2);
	struct istream *is_4 = i_stream_create_hash(is_3, hash, hash_ctx);
	i_stream_unref(&is_3);

	while((amt = i_stream_read(is_4))>0) { i_stream_skip(is_4, amt); }

	if (is_4->stream_errno != 0)
		i_debug("error: %s", i_stream_get_error(is_4));

	test_assert(is_4->stream_errno == 0);

	i_stream_unref(&is_4);

	hash->result(hash_ctx, hash_dgst);

	test_assert(strcmp(test_sample_v2_hash,
		    binary_to_hex(hash_dgst, sizeof(hash_dgst))) == 0);

	test_end();

/** this code is left here to show how the sample file is created
	struct istream *is =
		i_stream_create_file("../lib-fts/udhr_fra.txt", 8192);
	struct istream *is_2 = i_stream_create_hash(is, hash, hash_ctx);
	int fd = open("sample-v2.bin", O_CREAT|O_TRUNC|O_WRONLY, S_IRWXU);
	struct ostream *os = o_stream_create_fd_file(fd, 0, TRUE);
	struct ostream *os_2 = o_stream_create_encrypt(os,
		"aes-256-gcm-sha256", test_v2_kp.pub,
		IO_STREAM_ENC_INTEGRITY_AEAD);
	const unsigned char *ptr;
	size_t siz;

	while(i_stream_read_data(is_2, &ptr, &siz, 0)>0) {
		o_stream_nsend(os_2, ptr, siz);
		i_stream_skip(is_2, siz);
	}

	i_assert(o_stream_finish(os_2) > 0);

	o_stream_close(os_2);
	i_stream_close(is_2);

	hash->result(hash_ctx, hash_dgst);
	printf("%s\n", binary_to_hex(hash_dgst, sizeof(hash_dgst)));
*/
}

static void test_write_read_v1(void)
{
	test_begin("test_write_read_v1");
	unsigned char payload[IO_BLOCK_SIZE];
	const unsigned char *ptr;
	size_t pos = 0, siz;
	random_fill(payload, IO_BLOCK_SIZE);

	buffer_t *buf = buffer_create_dynamic(default_pool, sizeof(payload));
	struct ostream *os = o_stream_create_buffer(buf);
	struct ostream *os_2 = o_stream_create_encrypt(os,
		"<unused>", test_v2_kp.pub, IO_STREAM_ENC_VERSION_1);
	o_stream_nsend(os_2, payload, sizeof(payload));

	if (os_2->stream_errno != 0)
		i_debug("error: %s", o_stream_get_error(os_2));

	test_assert(os_2->stream_errno == 0);
	test_assert(o_stream_finish(os_2) > 0);
	test_assert(os_2->stream_errno == 0);

	o_stream_unref(&os);
	o_stream_unref(&os_2);

	struct istream *is = test_istream_create_data(buf->data, buf->used);
	struct istream *is_2 = i_stream_create_decrypt(is, test_v2_kp.priv);

	size_t offset = 0;
	test_istream_set_allow_eof(is, FALSE);
	test_istream_set_size(is, 0);
	while(i_stream_read_data(is_2, &ptr, &siz, 0)>=0) {
		if (offset == buf->used)
			test_istream_set_allow_eof(is, TRUE);
		else
			test_istream_set_size(is, ++offset);

		test_assert_idx(pos + siz <= sizeof(payload), pos);
		if (pos + siz > sizeof(payload))
			break;
		test_assert_idx(siz == 0 ||
				memcmp(ptr, payload + pos, siz) == 0, pos);
		i_stream_skip(is_2, siz); pos += siz;
	}

	test_assert(is_2->stream_errno == 0);

	i_stream_unref(&is);
	i_stream_unref(&is_2);
	buffer_free(&buf);

	test_end();
}

static void test_write_read_v1_short(void)
{
	test_begin("test_write_read_v1_short");
	unsigned char payload[1];
	const unsigned char *ptr;
	size_t pos = 0, siz;
	random_fill(payload, 1);

	buffer_t *buf = buffer_create_dynamic(default_pool, 64);
	struct ostream *os = o_stream_create_buffer(buf);
	struct ostream *os_2 = o_stream_create_encrypt(os,
		"<unused>", test_v2_kp.pub, IO_STREAM_ENC_VERSION_1);
	o_stream_nsend(os_2, payload, sizeof(payload));

	if (os_2->stream_errno != 0)
		i_debug("error: %s", o_stream_get_error(os_2));

	test_assert(os_2->stream_errno == 0);
	test_assert(o_stream_finish(os_2) > 0);
	test_assert(os_2->stream_errno == 0);

	o_stream_unref(&os);
	o_stream_unref(&os_2);

	struct istream *is = test_istream_create_data(buf->data, buf->used);
	struct istream *is_2 = i_stream_create_decrypt(is, test_v2_kp.priv);

	size_t offset = 0;
	test_istream_set_allow_eof(is, FALSE);
	test_istream_set_size(is, 0);
	while(i_stream_read_data(is_2, &ptr, &siz, 0)>=0) {
		if (offset == buf->used)
			test_istream_set_allow_eof(is, TRUE);
		else
			test_istream_set_size(is, ++offset);

		test_assert_idx(pos + siz <= sizeof(payload), pos);
		if (siz > sizeof(payload) || pos + siz > sizeof(payload))
			break;
		test_assert_idx(siz == 0 ||
				memcmp(ptr, payload + pos, siz) == 0, pos);
		i_stream_skip(is_2, siz); pos += siz;
	}

	test_assert(is_2->stream_errno == 0);

	i_stream_unref(&is);
	i_stream_unref(&is_2);
	buffer_free(&buf);

	test_end();
}

static void test_write_read_v1_empty(void)
{
	const unsigned char *ptr;
	size_t siz;
	test_begin("test_write_read_v1_empty");
	buffer_t *buf = buffer_create_dynamic(default_pool, 64);
	struct ostream *os = o_stream_create_buffer(buf);
	struct ostream *os_2 = o_stream_create_encrypt(os,
		"<unused>", test_v1_kp.pub, IO_STREAM_ENC_VERSION_1);
	test_assert(o_stream_finish(os_2) > 0);
	if (os_2->stream_errno != 0)
		i_debug("error: %s", o_stream_get_error(os_2));

	o_stream_unref(&os);
	o_stream_unref(&os_2);
	/* this should've been enough */

	struct istream *is = test_istream_create_data(buf->data, buf->used);
	struct istream *is_2 = i_stream_create_decrypt(is, test_v1_kp.priv);

	/* read should not fail */
	test_istream_set_allow_eof(is, FALSE);
	test_istream_set_size(is, 0);
	size_t offset = 0;
	ssize_t ret;
	while ((ret = i_stream_read_data(is_2, &ptr, &siz, 0)) >= 0) {
		test_assert(ret == 0);
		if (offset == buf->used)
			test_istream_set_allow_eof(is, TRUE);
		else
			test_istream_set_size(is, ++offset);
	};

	test_assert(is_2->stream_errno == 0);
	if (is_2->stream_errno != 0)
		i_debug("error: %s", i_stream_get_error(is_2));
	i_stream_unref(&is);
	i_stream_unref(&is_2);
	buffer_free(&buf);
	test_end();
}

static void test_write_read_v2(void)
{
	test_begin("test_write_read_v2");
	unsigned char payload[IO_BLOCK_SIZE*10];
	const unsigned char *ptr;
	size_t pos = 0, siz;
	random_fill(payload, IO_BLOCK_SIZE*10);

	buffer_t *buf = buffer_create_dynamic(default_pool, sizeof(payload));
	struct ostream *os = o_stream_create_buffer(buf);
	struct ostream *os_2 = o_stream_create_encrypt(os,
		"aes-256-gcm-sha256", test_v1_kp.pub,
		IO_STREAM_ENC_INTEGRITY_AEAD);
	o_stream_nsend(os_2, payload, sizeof(payload));
	test_assert(o_stream_finish(os_2) > 0);
	if (os_2->stream_errno != 0)
		i_debug("error: %s", o_stream_get_error(os_2));

	o_stream_unref(&os);
	o_stream_unref(&os_2);

	struct istream *is = test_istream_create_data(buf->data, buf->used);
	/* test regression where read fails due to incorrect behaviour
	   when buffer is full before going to decrypt code */
	i_stream_set_max_buffer_size(is, 8192);
	i_stream_read(is);
	struct istream *is_2 = i_stream_create_decrypt(is, test_v1_kp.priv);

	size_t offset = 0;
	test_istream_set_size(is, 0);
	test_istream_set_allow_eof(is, FALSE);
	while(i_stream_read_data(is_2, &ptr, &siz, 0)>=0) {
		if (offset == buf->used)
			test_istream_set_allow_eof(is, TRUE);
		else
			test_istream_set_size(is, ++offset);

		test_assert_idx(pos + siz <= sizeof(payload), pos);
		if (pos + siz > sizeof(payload)) break;
		test_assert_idx(siz == 0 ||
				memcmp(ptr, payload + pos, siz) == 0, pos);
		i_stream_skip(is_2, siz); pos += siz;
	}

	test_assert(is_2->stream_errno == 0);
	if (is_2->stream_errno != 0)
		i_debug("error: %s", i_stream_get_error(is_2));

	/* test seeking */
	for (size_t i = sizeof(payload)-100; i > 100; i -= 100) {
		i_stream_seek(is_2, i);
		test_assert_idx(i_stream_read_data(is_2, &ptr, &siz, 0) == 1, i);
		test_assert_idx(memcmp(ptr, payload + i, siz) == 0, i);
	}
	i_stream_seek(is_2, 0);
	test_assert(i_stream_read_data(is_2, &ptr, &siz, 0) == 1);
	test_assert(memcmp(ptr, payload, siz) == 0);

	i_stream_unref(&is);
	i_stream_unref(&is_2);
	buffer_free(&buf);

	test_end();
}

static void test_write_read_v2_short(void)
{
	test_begin("test_write_read_v2_short");
	unsigned char payload[1];
	const unsigned char *ptr;
	size_t pos = 0, siz;
	random_fill(payload, 1);

	buffer_t *buf = buffer_create_dynamic(default_pool, 64);
	struct ostream *os = o_stream_create_buffer(buf);
	struct ostream *os_2 = o_stream_create_encrypt(os,
		"aes-256-gcm-sha256", test_v1_kp.pub,
		IO_STREAM_ENC_INTEGRITY_AEAD);
	o_stream_nsend(os_2, payload, sizeof(payload));
	test_assert(o_stream_finish(os_2) > 0);
	if (os_2->stream_errno != 0)
		i_debug("error: %s", o_stream_get_error(os_2));

	o_stream_unref(&os);
	o_stream_unref(&os_2);

	struct istream *is = test_istream_create_data(buf->data, buf->used);
	struct istream *is_2 = i_stream_create_decrypt(is, test_v1_kp.priv);

	size_t offset = 0;
	test_istream_set_allow_eof(is, FALSE);
	test_istream_set_size(is, 0);
	while(i_stream_read_data(is_2, &ptr, &siz, 0)>=0) {
		if (offset == buf->used)
			test_istream_set_allow_eof(is, TRUE);
		test_istream_set_size(is, ++offset);

		test_assert_idx(pos + siz <= sizeof(payload), pos);
		if (siz > sizeof(payload) || pos + siz > sizeof(payload))
			break;
		test_assert_idx(siz == 0 ||
				memcmp(ptr, payload + pos, siz) == 0, pos);
		i_stream_skip(is_2, siz); pos += siz;
	}

	test_assert(is_2->stream_errno == 0);
	if (is_2->stream_errno != 0)
		i_debug("error: %s", i_stream_get_error(is_2));

	i_stream_unref(&is);
	i_stream_unref(&is_2);
	buffer_free(&buf);

	test_end();
}

static void test_write_read_v2_empty(void)
{
	const unsigned char *ptr;
	size_t siz;
	test_begin("test_write_read_v2_empty");
	buffer_t *buf = buffer_create_dynamic(default_pool, 64);
	struct ostream *os = o_stream_create_buffer(buf);
	struct ostream *os_2 = o_stream_create_encrypt(os,
		"aes-256-gcm-sha256", test_v1_kp.pub,
		IO_STREAM_ENC_INTEGRITY_AEAD);
	test_assert(o_stream_finish(os_2) > 0);
	if (os_2->stream_errno != 0)
		i_debug("error: %s", o_stream_get_error(os_2));

	o_stream_unref(&os);
	o_stream_unref(&os_2);
	/* this should've been enough */

	struct istream *is = test_istream_create_data(buf->data, buf->used);
	struct istream *is_2 = i_stream_create_decrypt(is, test_v1_kp.priv);

	/* read should not fail */
	size_t offset = 0;
	test_istream_set_allow_eof(is, FALSE);
	test_istream_set_size(is, 0);
	ssize_t ret;
	while ((ret = i_stream_read_data(is_2, &ptr, &siz, 0)) >= 0) {
		test_assert(ret == 0);
		if (offset == buf->used)
			test_istream_set_allow_eof(is, TRUE);
		test_istream_set_size(is, ++offset);
	};

	test_assert(is_2->stream_errno == 0);
	if (is_2->stream_errno != 0)
		i_debug("error: %s", i_stream_get_error(is_2));
	i_stream_unref(&is);
	i_stream_unref(&is_2);
	buffer_free(&buf);
	test_end();
}

static int
no_op_cb(const char *digest ATTR_UNUSED,
	 struct dcrypt_private_key **priv_key_r ATTR_UNUSED,
	 const char **error_r ATTR_UNUSED,
	 void *context ATTR_UNUSED)
{
	return 0;
}

static void test_read_0_to_400_byte_garbage(void)
{
	test_begin("test_read_0_to_100_byte_garbage");

	char data[512];
	memset(data, 0, sizeof(data));

	for (size_t s = 0; s <= 400; ++s) {
		struct istream *is = test_istream_create_data(data, s);
		struct istream *ds = i_stream_create_decrypt_callback(is,
				no_op_cb, NULL);
		test_istream_set_size(is, 0);
		test_istream_set_allow_eof(is, FALSE);
		ssize_t siz = 0;
		for (size_t offset = 0; offset <= s && siz == 0; offset++) {
			if (offset == s)
				test_istream_set_allow_eof(is, TRUE);
			test_istream_set_size(is, offset);
			siz = i_stream_read(ds);
		}
		test_assert_idx(siz < 0, s);
		i_stream_unref(&ds);
		i_stream_unref(&is);
	}

	test_end();
}

static void test_read_large_header(void)
{
	test_begin("test_read_large_header");

	struct istream *is =
		test_istream_create_data(IOSTREAM_CRYPT_MAGIC,
					 sizeof(IOSTREAM_CRYPT_MAGIC));
	struct istream *ds =
		i_stream_create_decrypt_callback(is, no_op_cb, NULL);
	test_istream_set_allow_eof(is, FALSE);
	test_istream_set_max_buffer_size(is, sizeof(IOSTREAM_CRYPT_MAGIC));

	test_assert(i_stream_read(ds) == -1);
	i_stream_unref(&ds);
	i_stream_unref(&is);

	test_end();
}

static void test_read_increment(void)
{
	test_begin("test_read_increment");

	ssize_t amt, total, i;

	struct istream *is_1 = i_stream_create_file(
		DCRYPT_SRC_DIR"/sample-v2.asc", IO_BLOCK_SIZE);
	struct istream *is_2 = i_stream_create_base64_decoder(is_1);
	i_stream_unref(&is_1);
	struct istream *is_3 = i_stream_create_decrypt(is_2, test_v2_kp.priv);
	i_stream_unref(&is_2);
	total = 0;
	i = 500;

	i_stream_set_max_buffer_size(is_3, i);
	while((amt = i_stream_read(is_3)) > 0) {
		total += amt;
		i_stream_set_max_buffer_size(is_3, ++i);
	}

	test_assert(total == 13534);
	test_assert(is_3->stream_errno == 0);
	test_assert(is_3->eof);

	i_stream_unref(&is_3);

        test_end();
}

static void test_free_keys()
{
	dcrypt_key_unref_private(&test_v1_kp.priv);
	dcrypt_key_unref_public(&test_v1_kp.pub);
	dcrypt_key_unref_private(&test_v2_kp.priv);
	dcrypt_key_unref_public(&test_v2_kp.pub);
}

int main(void)
{
	struct dcrypt_settings set = {
		.module_dir = ".libs"
	};
	const char *error;

	if (!dcrypt_initialize(NULL, &set, &error)) {
		i_error("No functional dcrypt backend found - "
			"skipping tests: %s", error);
		return 0;
	}

	test_assert(dcrypt_key_load_private(&test_v1_kp.priv, key_v1_priv,
					    NULL, NULL, NULL));
	test_assert(dcrypt_key_load_public(&test_v1_kp.pub, key_v1_pub, NULL));
	test_assert(dcrypt_key_load_private(&test_v2_kp.priv, key_v2_priv,
					    NULL, NULL, NULL));
	test_assert(dcrypt_key_load_public(&test_v2_kp.pub, key_v2_pub, NULL));

	static void (*const test_functions[])(void) = {
		test_static_v1_input,
		test_static_v1_input_short,
		test_static_v2_input,
		test_read_increment,
		test_write_read_v1,
		test_write_read_v1_short,
		test_write_read_v1_empty,
		test_write_read_v2,
		test_write_read_v2_short,
		test_write_read_v2_empty,
		test_free_keys,
		test_read_0_to_400_byte_garbage,
		test_read_large_header,
		NULL
	};

	return test_run(test_functions);
}
