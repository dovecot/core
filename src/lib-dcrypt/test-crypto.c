/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "str.h"
#include "dcrypt.h"
#include "dcrypt-iostream.h"
#include "ostream.h"
#include "ostream-encrypt.h"
#include "istream.h"
#include "iostream-temp.h"
#include "randgen.h"
#include "test-common.h"
#include "hex-binary.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <openssl/evp.h>

#if defined(NID_X25519)
# define HAVE_X25519
#endif

static void test_cipher_test_vectors(void)
{
	const char *error ATTR_UNUSED;

	static const struct {
		const char *key;
		const char *iv;
		const char *pt;
		const char *ct;
	} vectors[] = {
		{
			"2b7e151628aed2a6abf7158809cf4f3c",
			"000102030405060708090a0b0c0d0e0f",
			"6bc1bee22e409f96e93d7e117393172a",
			"7649abac8119b246cee98e9b12e9197d"
		}, {
			"2b7e151628aed2a6abf7158809cf4f3c",
			"7649ABAC8119B246CEE98E9B12E9197D",
			"ae2d8a571e03ac9c9eb76fac45af8e51",
			"5086cb9b507219ee95db113a917678b2"
		}
	};


	test_begin("test_cipher_test_vectors");

	buffer_t *key,*iv,*pt,*ct,*res_enc,*res_dec;

	key = t_buffer_create(16);
	iv = t_buffer_create(16);
	pt = t_buffer_create(16);
	ct = t_buffer_create(16);

	res_enc = t_buffer_create(32);
	res_dec = t_buffer_create(32);

	for(size_t i = 0; i < N_ELEMENTS(vectors); i++) {
		struct dcrypt_context_symmetric *ctx;

		buffer_set_used_size(key, 0);
		buffer_set_used_size(iv, 0);
		buffer_set_used_size(pt, 0);
		buffer_set_used_size(ct, 0);
		buffer_set_used_size(res_enc, 0);
		buffer_set_used_size(res_dec, 0);

		hex_to_binary(vectors[i].key, key);
		hex_to_binary(vectors[i].iv, iv);
		hex_to_binary(vectors[i].pt, pt);
		hex_to_binary(vectors[i].ct, ct);

		if (!dcrypt_ctx_sym_create("AES-128-CBC", DCRYPT_MODE_ENCRYPT,
					   &ctx, &error)) {
			test_assert_failed("dcrypt_ctx_sym_create",
					   __FILE__, __LINE__-1);
			continue;
		}

		dcrypt_ctx_sym_set_padding(ctx, FALSE);

		dcrypt_ctx_sym_set_key(ctx, key->data, key->used);
		dcrypt_ctx_sym_set_iv(ctx, iv->data, iv->used);

		test_assert_idx(dcrypt_ctx_sym_init(ctx, &error), i);

		test_assert_idx(dcrypt_ctx_sym_update(ctx,
			pt->data, pt->used, res_enc, &error), i);
		test_assert_idx(dcrypt_ctx_sym_final(ctx, res_enc, &error), i);

		test_assert_idx(buffer_cmp(ct, res_enc), i);

		dcrypt_ctx_sym_destroy(&ctx);

		if (!dcrypt_ctx_sym_create("AES-128-CBC", DCRYPT_MODE_DECRYPT,
					   &ctx, NULL)) {
			test_assert_failed("dcrypt_ctx_sym_create",
					   __FILE__, __LINE__-1);
			continue;
		}

		dcrypt_ctx_sym_set_padding(ctx, FALSE);

		dcrypt_ctx_sym_set_key(ctx, key->data, key->used);
		dcrypt_ctx_sym_set_iv(ctx, iv->data, iv->used);

		test_assert_idx(dcrypt_ctx_sym_init(ctx, &error), i);
		test_assert_idx(dcrypt_ctx_sym_update(ctx,
			res_enc->data, res_enc->used, res_dec, &error), i);
		test_assert_idx(dcrypt_ctx_sym_final(ctx, res_dec, &error), i);

		test_assert_idx(buffer_cmp(pt, res_dec), i);

		dcrypt_ctx_sym_destroy(&ctx);
	}

	test_end();
}

static void test_cipher_aead_test_vectors(void)
{
	struct dcrypt_context_symmetric *ctx;
	const char *error = NULL;

	test_begin("test_cipher_aead_test_vectors");

	if (!dcrypt_ctx_sym_create("aes-128-gcm", DCRYPT_MODE_ENCRYPT,
				   &ctx, &error)) {
		test_assert_failed("dcrypt_ctx_sym_create",
				   __FILE__, __LINE__-1);
		test_end();
		return;
	}

	buffer_t *key, *iv, *aad, *pt, *ct, *tag, *tag_res, *res;

	key = t_buffer_create(16);
	iv = t_buffer_create(16);
	aad = t_buffer_create(16);
	pt = t_buffer_create(16);
	ct = t_buffer_create(16);
	tag = t_buffer_create(16);
	res = t_buffer_create(16);
	tag_res = t_buffer_create(16);

	hex_to_binary("feffe9928665731c6d6a8f9467308308", key);
	hex_to_binary("cafebabefacedbaddecaf888", iv);
	hex_to_binary("d9313225f88406e5a55909c5aff5269a"
		      "86a7a9531534f7da2e4c303d8a318a72"
		      "1c3c0c95956809532fcf0e2449a6b525"
		      "b16aedf5aa0de657ba637b391aafd255", pt);
	hex_to_binary("42831ec2217774244b7221b784d0d49c"
		      "e3aa212f2c02a4e035c17e2329aca12e"
		      "21d514b25466931c7d8f6a5aac84aa05"
		      "1ba30b396a0aac973d58e091473f5985", ct);
	hex_to_binary("4d5c2af327cd64a62cf35abd2ba6fab4", tag);

	dcrypt_ctx_sym_set_key(ctx, key->data, key->used);
	dcrypt_ctx_sym_set_iv(ctx, iv->data, iv->used);
	dcrypt_ctx_sym_set_aad(ctx, aad->data, aad->used);
	test_assert(dcrypt_ctx_sym_init(ctx, &error));
	test_assert(dcrypt_ctx_sym_update(ctx, pt->data, pt->used, res, &error));
	test_assert(dcrypt_ctx_sym_final(ctx, res, &error));
	test_assert(dcrypt_ctx_sym_get_tag(ctx, tag_res));

	test_assert(buffer_cmp(ct, res) == TRUE);
	test_assert(buffer_cmp(tag, tag_res) == TRUE);

	dcrypt_ctx_sym_destroy(&ctx);

	if (!dcrypt_ctx_sym_create("aes-128-gcm", DCRYPT_MODE_DECRYPT,
				   &ctx, &error)) {
		test_assert_failed("dcrypt_ctx_sym_create",
				   __FILE__, __LINE__-1);
	} else {

		buffer_set_used_size(res, 0);

		dcrypt_ctx_sym_set_key(ctx, key->data, key->used);
		dcrypt_ctx_sym_set_iv(ctx, iv->data, iv->used);
		dcrypt_ctx_sym_set_aad(ctx, aad->data, aad->used);
		dcrypt_ctx_sym_set_tag(ctx, tag->data, tag->used);
		test_assert(dcrypt_ctx_sym_init(ctx, &error));
		test_assert(dcrypt_ctx_sym_update(ctx,
			ct->data, ct->used, res, &error));
		test_assert(dcrypt_ctx_sym_final(ctx, res, &error));

		test_assert(buffer_cmp(pt, res) == TRUE);

		dcrypt_ctx_sym_destroy(&ctx);
	}

	test_end();
}

static void test_hmac_test_vectors(void)
{
	test_begin("test_hmac_test_vectors");

	const char *error ATTR_UNUSED;
	buffer_t *pt, *ct, *key, *res;
	pt = t_buffer_create(50);
	key = t_buffer_create(20);
	ct = t_buffer_create(32);
	res = t_buffer_create(32);

	hex_to_binary("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", key);
	hex_to_binary("dddddddddddddddddddddddddddddddddddddddddddddddddd"
		      "dddddddddddddddddddddddddddddddddddddddddddddddddd", pt);
	hex_to_binary("773ea91e36800e46854db8ebd09181a7"
		      "2959098b3ef8c122d9635514ced565fe", res);

	struct dcrypt_context_hmac *hctx;
	if (!dcrypt_ctx_hmac_create("sha256", &hctx, &error)) {
		test_assert_failed("dcrypt_ctx_hmac_create",
				   __FILE__, __LINE__-1);
	} else {
		dcrypt_ctx_hmac_set_key(hctx, key->data, key->used);
		test_assert(dcrypt_ctx_hmac_init(hctx, &error));
		test_assert(dcrypt_ctx_hmac_update(hctx,
			pt->data, pt->used, NULL));
		test_assert(dcrypt_ctx_hmac_final(hctx, ct, &error));
		test_assert(buffer_cmp(ct, res));
		dcrypt_ctx_hmac_destroy(&hctx);
	}

	test_end();
}

static void test_load_v1_keys(void)
{
	test_begin("test_load_v1_keys");

	const char *error = NULL;
	const char *data1 =
		"1\t716\t1\t0567e6bf9579813ae967314423b0fceb14bda24"
		"749303923de9a9bb9370e0026f995901a57e63113eeb2baf0c"
		"940e978d00686cbb52bd5014bc318563375876255\t0300E46"
		"DA2125427BE968EB3B649910CDC4C405E5FFDE18D433A97CAB"
		"FEE28CEEFAE9EE356C792004FFB80981D67E741B8CC036A342"
		"35A8D2E1F98D1658CFC963D07EB\td0cfaca5d335f9edc41c8"
		"4bb47465184cb0e2ec3931bebfcea4dd433615e77a0\t7c9a1"
		"039ea2e4fed73e81dd3ffc3fa22ea4a28352939adde7bf8ea8"
		"58b00fa4f";

	enum dcrypt_key_format format;
	enum dcrypt_key_version version;
	enum dcrypt_key_kind kind;
	enum dcrypt_key_encryption_type encryption_type;
	const char *encryption_key_hash = NULL;
	const char *key_hash = NULL;

	bool ret = dcrypt_key_string_get_info(data1, &format, &version,
			&kind, &encryption_type, &encryption_key_hash,
			&key_hash, &error);

	test_assert(ret == TRUE);
	test_assert(error == NULL);
	test_assert(format == DCRYPT_FORMAT_DOVECOT);
	test_assert(version == DCRYPT_KEY_VERSION_1);
	test_assert(kind == DCRYPT_KEY_KIND_PRIVATE);
	test_assert(encryption_type == DCRYPT_KEY_ENCRYPTION_TYPE_KEY);
	test_assert(strcmp(encryption_key_hash,
		"d0cfaca5d335f9edc41c84bb47465184"
		"cb0e2ec3931bebfcea4dd433615e77a0") == 0);
	test_assert(strcmp(key_hash,
		"7c9a1039ea2e4fed73e81dd3ffc3fa22"
		"ea4a28352939adde7bf8ea858b00fa4f") == 0);

	const char* data2 =
		"1\t716\t0301EB00973C4EFC8FCECA4EA33E941F50B561199A"
		"5159BCB6C2EED9DD1D62D65E38A254979D89E28F0C28883E71"
		"EE2AD264CD16B863FA094A8F6F69A56B62E8918040\t7c9a10"
		"39ea2e4fed73e81dd3ffc3fa22ea4a28352939adde7bf8ea85"
		"8b00fa4f";

	error = NULL;
	encryption_key_hash = NULL;
	key_hash = NULL;

	ret = dcrypt_key_string_get_info(data2, &format, &version,
			&kind, &encryption_type, &encryption_key_hash,
			&key_hash, &error);

	test_assert(ret == TRUE);
	test_assert(error == NULL);
	test_assert(format == DCRYPT_FORMAT_DOVECOT);
	test_assert(version == DCRYPT_KEY_VERSION_1);
	test_assert(kind == DCRYPT_KEY_KIND_PUBLIC);
	test_assert(encryption_type == DCRYPT_KEY_ENCRYPTION_TYPE_NONE);
	test_assert(encryption_key_hash == NULL);
	test_assert(strcmp(key_hash,
		"7c9a1039ea2e4fed73e81dd3ffc3fa22"
		"ea4a28352939adde7bf8ea858b00fa4f") == 0);

	/* This is the key that should be able to decrypt key1 */
	const char *data3 =
		"1\t716\t0\t048FD04FD3612B22D32790C592CF21CEF417EFD"
		"2EA34AE5F688FA5B51BED29E05A308B68DA78E16E90B47A11E"
		"133BD9A208A2894FD01B0BEE865CE339EA3FB17AC\td0cfaca"
		"5d335f9edc41c84bb47465184cb0e2ec3931bebfcea4dd4336"
		"15e77a0";

	error = NULL;
	encryption_key_hash = NULL;
	key_hash = NULL;

	ret = dcrypt_key_string_get_info(data3, &format, &version,
			&kind, &encryption_type, &encryption_key_hash,
			&key_hash, &error);
	test_assert(ret == TRUE);
	test_assert(error == NULL);
	test_assert(format == DCRYPT_FORMAT_DOVECOT);
	test_assert(version == DCRYPT_KEY_VERSION_1);
	test_assert(kind == DCRYPT_KEY_KIND_PRIVATE);
	test_assert(encryption_type == DCRYPT_KEY_ENCRYPTION_TYPE_NONE);
	test_assert(encryption_key_hash == NULL);
	test_assert(strcmp(key_hash,
		"d0cfaca5d335f9edc41c84bb47465184"
		"cb0e2ec3931bebfcea4dd433615e77a0") == 0);

	/* key3's key_hash should and does match key1's encryption_key_hash */
	struct dcrypt_private_key *pkey = NULL;
	struct dcrypt_private_key *pkey2 = NULL;
	pkey = NULL;
	error = NULL;

	ret = dcrypt_key_load_private(&pkey2, data3, NULL, NULL, &error);
	test_assert(ret == TRUE);
	test_assert(error == NULL);

	ret = dcrypt_key_load_private(&pkey, data1, NULL, pkey2, &error);
	test_assert(ret == TRUE);
	test_assert(error == NULL);

	dcrypt_key_unref_private(&pkey2);
	dcrypt_key_unref_private(&pkey);

	test_end();
}

static void test_load_v1_key(void)
{
	test_begin("test_load_v1_key");

	buffer_t *key_1 = t_buffer_create(128);

	struct dcrypt_private_key *pkey = NULL, *pkey2 = NULL;
	const char *error = NULL;

	test_assert(dcrypt_key_load_private(&pkey,
		"1\t716\t0\t048FD04FD3612B22D32790C592CF21CEF417EFD"
		"2EA34AE5F688FA5B51BED29E05A308B68DA78E16E90B47A11E"
		"133BD9A208A2894FD01B0BEE865CE339EA3FB17AC\td0cfaca"
		"5d335f9edc41c84bb47465184cb0e2ec3931bebfcea4dd4336"
		"15e77a0", NULL, NULL, &error));
	if (pkey != NULL) {
		buffer_set_used_size(key_1, 0);
		/* check that key_id matches */
		struct dcrypt_public_key *pubkey = NULL;
		dcrypt_key_convert_private_to_public(pkey, &pubkey);
		test_assert(dcrypt_key_store_public(pubkey,
			    DCRYPT_FORMAT_DOVECOT, key_1, NULL));
		buffer_set_used_size(key_1, 0);
		dcrypt_key_id_public(pubkey, "sha256", key_1, &error);
		test_assert(strcmp("792caad4d38c9eb2134a0cbc844eae38"
				   "6116de096a0ccafc98479825fc99b6a1",
				   binary_to_hex(key_1->data, key_1->used))
				== 0);

		dcrypt_key_unref_public(&pubkey);
		pkey2 = NULL;

		test_assert(dcrypt_key_load_private(&pkey2,
			"1\t716\t1\t0567e6bf9579813ae967314423b0fceb14"
			"bda24749303923de9a9bb9370e0026f995901a57e6311"
			"3eeb2baf0c940e978d00686cbb52bd5014bc318563375"
			"876255\t0300E46DA2125427BE968EB3B649910CDC4C4"
			"05E5FFDE18D433A97CABFEE28CEEFAE9EE356C792004F"
			"FB80981D67E741B8CC036A34235A8D2E1F98D1658CFC9"
			"63D07EB\td0cfaca5d335f9edc41c84bb47465184cb0e"
			"2ec3931bebfcea4dd433615e77a0\t7c9a1039ea2e4fe"
			"d73e81dd3ffc3fa22ea4a28352939adde7bf8ea858b00"
			"fa4f", NULL, pkey, &error));
		if (pkey2 != NULL) {
			buffer_set_used_size(key_1, 0);
			/* check that key_id matches */
			struct dcrypt_public_key *pubkey = NULL;
			dcrypt_key_convert_private_to_public(pkey2, &pubkey);
			test_assert(dcrypt_key_store_public(pubkey,
				DCRYPT_FORMAT_DOVECOT, key_1, NULL));
			buffer_set_used_size(key_1, 0);
			test_assert(dcrypt_key_id_public_old(pubkey,
				key_1, &error));
			test_assert(strcmp(
				"7c9a1039ea2e4fed73e81dd3ffc3fa22"
				"ea4a28352939adde7bf8ea858b00fa4f",
				binary_to_hex(key_1->data, key_1->used)) == 0);

			dcrypt_key_unref_public(&pubkey);
			dcrypt_key_unref_private(&pkey2);
		}
		dcrypt_key_unref_private(&pkey);
	}

	test_end();
}

static void test_load_v1_public_key(void)
{
	test_begin("test_load_v1_public_key");

	const char* data1 =
		"1\t716\t030131D8A5FD5167947A0AE9CB112ADED652665463"
		"5AA5887051EE2364414B60FF32EBA8FA0BBE9485DBDE8794BB"
		"BCB44BBFC0D662A4287A848BA570D4E5E45A11FE0F\td0cfac"
		"a5d335f9edc41c84bb47465184cb0e2ec3931bebfcea4dd433"
		"615e77a0";

	const char* error = NULL;
	const char* key_hash = NULL;
	const char* encryption_key_hash = NULL;

	enum dcrypt_key_format format;
	enum dcrypt_key_version version;
	enum dcrypt_key_kind kind;
	enum dcrypt_key_encryption_type encryption_type;

	bool ret = dcrypt_key_string_get_info(data1, &format, &version,
			&kind, &encryption_type, &encryption_key_hash,
			&key_hash, &error);

	test_assert(ret == TRUE);
	test_assert(error == NULL);
	test_assert(format == DCRYPT_FORMAT_DOVECOT);
	test_assert(version == DCRYPT_KEY_VERSION_1);
	test_assert(kind == DCRYPT_KEY_KIND_PUBLIC);
	test_assert(encryption_type == DCRYPT_KEY_ENCRYPTION_TYPE_NONE);
	test_assert(key_hash != NULL &&
		strcmp(key_hash, "d0cfaca5d335f9edc41c84bb47465184"
				 "cb0e2ec3931bebfcea4dd433615e77a0") == 0);
	test_assert(encryption_key_hash == NULL);

	struct dcrypt_public_key *pub_key = NULL;
	ret = dcrypt_key_load_public(&pub_key, data1, &error);
	test_assert(ret == TRUE);
	test_assert(error == NULL);

	test_assert(dcrypt_key_type_public(pub_key) == DCRYPT_KEY_EC);

	dcrypt_key_unref_public(&pub_key);
	test_assert(pub_key == NULL);

	test_end();
}

static void test_load_v2_key(void)
{
	const char *keys[] = {
		"-----BEGIN PRIVATE KEY-----\n"
		"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgtu"
		"QJA+uboZWVwgHc\n"
		"DciyVdrovAPwlMqshDK3s78IDDuhRANCAAQm0VEdzLB9PtD0HA"
		"8JK1zifWnj8M00\n"
		"FQzedfp9SQsWyA8dzs5/NFR5MTe6Xbh/ndKEs1zZH3vZ4FlNri"
		"lZc0st\n"
		"-----END PRIVATE KEY-----\n",
		"2:1.2.840.10045.3.1.7:0:0000002100b6e40903eb9ba195"
		"95c201dc0dc8b255dae8bc03f094caac8432b7b3bf080c3b:a"
		"b13d251976dedab546b67354e7678821740dd534b749c2857f"
		"66bf62bbaddfd",
		"2:1.2.840.10045.3.1.7:2:aes-256-ctr:483bd74fd3d917"
		"63:sha256:2048:d44ae35d3af7a2febcb15cde0c3693e7ed9"
		"8595665ed655a97fa918d346d5c661a6e2339f4:ab13d25197"
		"6dedab546b67354e7678821740dd534b749c2857f66bf62bba"
		"ddfd",
		"2:1.2.840.10045.3.1.7:1:aes-256-ctr:2574c10be28a4c"
		"09:sha256:2048:a750ec9dea91999f108f943485a20f273f4"
		"0f75c37fc9bcccdedda514c8243e550d69ce1bd:02237a199d"
		"7d945aa6492275a02881071eceec5749caf2485da8c64fb601"
		"229098:ab13d251976dedab546b67354e7678821740dd534b7"
		"49c2857f66bf62bbaddfd:ab13d251976dedab546b67354e76"
		"78821740dd534b749c2857f66bf62bbaddfd"
	};

	test_begin("test_load_v2_key");
	const char *error = NULL;
	buffer_t *tmp = buffer_create_dynamic(default_pool, 256);

	struct dcrypt_private_key *priv,*priv2;

	test_assert_idx(dcrypt_key_load_private(&priv2,
		keys[0], NULL, NULL, &error), 0);
	test_assert_idx(dcrypt_key_store_private(priv2,
		DCRYPT_FORMAT_PEM, NULL, tmp, NULL, NULL, &error), 0);
	test_assert_idx(strcmp(str_c(tmp), keys[0])==0, 0);
	buffer_set_used_size(tmp, 0);

	test_assert_idx(dcrypt_key_load_private(&priv,
		keys[1], NULL, NULL, &error), 1);
	test_assert_idx(dcrypt_key_store_private(priv,
		DCRYPT_FORMAT_DOVECOT, NULL, tmp, NULL, NULL, &error), 1);
	test_assert_idx(strcmp(str_c(tmp), keys[1])==0, 1);
	buffer_set_used_size(tmp, 0);
	dcrypt_key_unref_private(&priv);

	test_assert_idx(dcrypt_key_load_private(&priv,
		keys[2], "This Is Sparta", NULL, &error), 2);
	test_assert_idx(dcrypt_key_store_private(priv,
		DCRYPT_FORMAT_DOVECOT, "aes-256-ctr", tmp,
		"This Is Sparta", NULL, &error), 2);
	buffer_set_used_size(tmp, 0);
	dcrypt_key_unref_private(&priv);

	struct dcrypt_public_key *pub = NULL;
	dcrypt_key_convert_private_to_public(priv2, &pub);
	test_assert_idx(dcrypt_key_load_private(&priv,
		keys[3], NULL, priv2, &error), 3);
	test_assert_idx(dcrypt_key_store_private(priv,
		DCRYPT_FORMAT_DOVECOT, "ecdh-aes-256-ctr", tmp,
		NULL, pub, &error), 3);
	buffer_set_used_size(tmp, 0);
	dcrypt_key_unref_private(&priv2);
	dcrypt_key_unref_private(&priv);
	dcrypt_key_unref_public(&pub);

	buffer_free(&tmp);

	if (error != NULL) error = NULL;

	test_end();
}

static void test_load_v2_public_key(void)
{
	struct dcrypt_public_key *pub = NULL;
	const char *error;

	test_begin("test_load_v2_public_key");
	const char *key =
		"2:3058301006072a8648ce3d020106052b810400230344000"
		"301c50954e734dd8b410a607764a7057065a45510da52f2c6"
		"e28e0cb353b9c389fa8cb786943ae991fce9befed78fb162f"
		"bbc615415f06af06c8cc80c37f4e94ff6c7:185a721254278"
		"2e239111f9c19d126ad55b18ddaf4883d66afe8d9627c3607"
		"d8";

	test_assert(dcrypt_key_load_public(&pub, key, &error));

	buffer_t *tmp = buffer_create_dynamic(default_pool, 256);

	if (pub != NULL) {
		test_assert(dcrypt_key_store_public(pub,
			DCRYPT_FORMAT_DOVECOT, tmp, &error));
		test_assert(strcmp(key, str_c(tmp))==0);
		buffer_free(&tmp);
		dcrypt_key_unref_public(&pub);
	}

	test_end();
}

static void test_get_info_v2_key(void)
{
	test_begin("test_get_info_v2_key");

	const char *key =
		"2:305e301006072a8648ce3d020106052b81040026034a0002"
		"03fcc90034fa03d6fb79a0fc8b3b43c3398f68e76029307360"
		"cdcb9e27bb7e84b3c19dfb7244763bc4d442d216f09b7b7945"
		"ed9d182f3156550e9ee30b237a0217dbf79d28975f31:86706"
		"b69d1f640011a65d26a42f2ba20a619173644e1cc7475eb1d9"
		"0966e84dc";
	enum dcrypt_key_format format;
	enum dcrypt_key_version version = DCRYPT_KEY_VERSION_NA;
	enum dcrypt_key_kind kind;
	enum dcrypt_key_encryption_type encryption_type;
	const char *encryption_key_hash = NULL;
	const char *key_hash = NULL;
	const char *error = NULL;

	test_assert(dcrypt_key_string_get_info(key, &format, &version,
			&kind, &encryption_type, &encryption_key_hash,
			&key_hash, &error));
	test_assert(error == NULL);
	test_assert(format == DCRYPT_FORMAT_DOVECOT);
	test_assert(version == DCRYPT_KEY_VERSION_2);

	test_assert(kind == DCRYPT_KEY_KIND_PUBLIC);
	test_assert(encryption_type == DCRYPT_KEY_ENCRYPTION_TYPE_NONE);
	test_assert(encryption_key_hash == NULL);
	test_assert(key_hash != NULL && strcmp(key_hash,
		"86706b69d1f640011a65d26a42f2ba20"
		"a619173644e1cc7475eb1d90966e84dc") == 0);

	test_end();
}

static void test_gen_and_get_info_rsa_pem(void)
{
	test_begin("test_gen_and_get_info_rsa_pem");

	const char *error = NULL;
	bool ret = FALSE;
	struct dcrypt_keypair pair;
	string_t* buf = str_new(default_pool, 4096);

	ret = dcrypt_keypair_generate(&pair, DCRYPT_KEY_RSA, 1024, NULL, &error);
	test_assert(ret == TRUE);

	/* test public key */
	enum dcrypt_key_format format;
	enum dcrypt_key_version version;
	enum dcrypt_key_kind kind;
	enum dcrypt_key_encryption_type encryption_type;
	const char *encryption_key_hash;
	const char *key_hash;

	ret = dcrypt_key_store_public(pair.pub, DCRYPT_FORMAT_PEM, buf,
			&error);
	test_assert(ret == TRUE);

	ret = dcrypt_key_string_get_info(str_c(buf), &format, &version,
			&kind, &encryption_type, &encryption_key_hash,
			&key_hash, &error);
	test_assert(ret == TRUE);
	test_assert(format == DCRYPT_FORMAT_PEM);
	test_assert(version == DCRYPT_KEY_VERSION_NA);

	test_assert(kind == DCRYPT_KEY_KIND_PUBLIC);
	test_assert(encryption_type == DCRYPT_KEY_ENCRYPTION_TYPE_NONE);
	test_assert(encryption_key_hash == NULL);
	test_assert(key_hash == NULL);

	/* test private key */
	buffer_set_used_size(buf, 0);
	ret = dcrypt_key_store_private(pair.priv, DCRYPT_FORMAT_PEM, NULL,
			buf, NULL, NULL, &error);

	test_assert(ret == TRUE);

	ret = dcrypt_key_string_get_info(str_c(buf), &format, &version,
			&kind, &encryption_type, &encryption_key_hash,
			&key_hash, &error);

	test_assert(ret == TRUE);
	test_assert(format == DCRYPT_FORMAT_PEM);
	test_assert(version == DCRYPT_KEY_VERSION_NA);

	test_assert(kind == DCRYPT_KEY_KIND_PRIVATE);

	test_assert(encryption_type == DCRYPT_KEY_ENCRYPTION_TYPE_NONE);
	test_assert(encryption_key_hash == NULL);
	test_assert(key_hash == NULL);

	dcrypt_keypair_unref(&pair);
	buffer_free(&buf);

	test_end();
}

static void test_get_info_rsa_private_key(void)
{
	test_begin("test_get_info_rsa_private_key");

	const char *key =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIICXQIBAAKBgQC89q02I9NezBLQ+otn5XLYE7S+GsKUz59ogr45DA/6MI9jey0W\n"
"56SeWQ1FJD1vDhAx/TRBMfOmhcIPsBjc5sakYOawPdoiqLjOIlO+iHwnbbmLuMsq\n"
"ue09vgvZsKjuTr2F5DOFQY43Bq/Nd+4bjHJItdOM58+xwA2I/8vDbtI8jwIDAQAB\n"
"AoGBAJCUrTMfdjqyKjN7f+6ewKBTc5eBIiB6O53ba3B6qj7jqNKVDIrZ8jq2KFEe\n"
"yWKPgBS/h5vafHKNJU6bjmp2qMUJPB7PTA876eDo0cq9PplUqihiTlXJFwNQYtF+\n"
"o27To5t25+5qdSAj657+lQfFT9Xn9fzYHDmotURxH10FgFkBAkEA+7Ny6lBTeb3W\n"
"LnP0UPfPzQLilEr8u81PLWe69RGtsEaMQHGpHOl4e+bvvVYbG1cgxwxI1m01uR9r\n"
"qpD3qLUdrQJBAMAw6UvN8R+opYTZzwqK7Nliil2QZMPmXM04SV1iFq26NM60w2Fm\n"
"HqOOh0EbpSWsFtIgxJFWoZOtrguxqCJuUqsCQF3EoXf3StHczhDqM8eCOpD2lTCH\n"
"qxXPy8JvlW+9EUbNUWykq0rRE4idJQ0VKe4KjHR6+Buh/dSkhvi5Hvpj1tUCQHRv\n"
"LWeXZLVhXqWVrzEb6VHpuRnmGKX2MdLCfu/sNQEbBlMUgCnJzFYaSybOsMaZ81lq\n"
"MKw8Z7coSYEcKFhzrfECQQD7l+4Bhy8Zuz6VoGGIZwIhxkJrImBFmaUwx8N6jg20\n"
"sgDRYwCoGkGd7B8uIHZLJoWzSSutHiu5i5PYUy5VT1yT\n"
"-----END RSA PRIVATE KEY-----\n";

	const char *error = NULL;

	test_assert(!dcrypt_key_string_get_info(key, NULL, NULL,
			NULL, NULL, NULL, NULL, &error));
	test_assert(error != NULL && strstr(error, "pkey") != NULL);

	test_end();
}

static void test_get_info_invalid_keys(void)
{
	test_begin("test_get_info_invalid_keys");

	static const struct {
		const char *key;
		const char *error;
	} invalid_keys[] = {
		{
			.key = "1:716:030131D8A5FD5167947A0AE9CB112ADED6526654635A"
			       "A5887051EE2364414B60FF32EBA8FA0BBE9485DBDE8794BBBC"
			       "B44BBFC0D662A4287A848BA570D4E5E45A11FE0F:d0cfaca5d"
			       "335f9edc41c84bb47465184cb0e2ec3931bebfcea4dd433615"
			       "e77a0",
			.error = "tab",
		},
		{
			.key = "2\t305e301006072a8648ce3d020106052b81040026034a000"
			       "203fcc90034fa03d6fb79a0fc8b3b43c3398f68e7602930736"
			       "0cdcb9e27bb7e84b3c19dfb7244763bc4d442d216f09b7b794"
			       "5ed9d182f3156550e9ee30b237a0217dbf79d28975f31\t867"
			       "06b69d1f640011a65d26a42f2ba20a619173644e1cc7475eb1"
			       "d90966e84dc",
			.error = "colon",
		},
		{
			.key = "2",
			.error = "Unknown",
		},
		{
			.key = "{"
			       "\"kty\":\"invalid\""
			       "}",
			.error = "Unsupported JWK key type",
		},
		{
			.key = "{"
			       "}",
			.error = "Missing kty parameter",
		},
	};

	for (size_t i = 0; i < N_ELEMENTS(invalid_keys); i++) {
		const char *error = NULL;
		test_assert(dcrypt_key_string_get_info(
				    invalid_keys[i].key, NULL, NULL, NULL, NULL,
				    NULL, NULL, &error) == FALSE);
		test_assert(error != NULL &&
			    strstr(error, invalid_keys[i].error) != NULL);
	}

	test_end();
}

static void test_get_info_key_encrypted(void)
{
	test_begin("test_get_info_key_encrypted");

	struct dcrypt_keypair p1, p2;
	const char *error = NULL;
	bool ret = dcrypt_keypair_generate(&p1,
		DCRYPT_KEY_EC, 0, "secp521r1", &error);
	test_assert(ret == TRUE);
	ret = dcrypt_keypair_generate(&p2,
		DCRYPT_KEY_EC, 0, "secp521r1", &error);
	test_assert(ret == TRUE);

	string_t* buf = t_str_new(4096);

	buffer_set_used_size(buf, 0);
	ret = dcrypt_key_store_private(p1.priv,
		DCRYPT_FORMAT_DOVECOT, "ecdh-aes-256-ctr", buf,
		NULL, p2.pub, &error);
	test_assert(ret == TRUE);

	enum dcrypt_key_format format;
	enum dcrypt_key_version version;
	enum dcrypt_key_kind kind;
	enum dcrypt_key_encryption_type enc_type;
	const char *enc_hash;
	const char *key_hash;

	ret = dcrypt_key_string_get_info(str_c(buf), &format, &version,
			&kind, &enc_type, &enc_hash, &key_hash, &error);
	test_assert(ret == TRUE);
	test_assert(format == DCRYPT_FORMAT_DOVECOT);
	test_assert(version == DCRYPT_KEY_VERSION_2);
	test_assert(kind == DCRYPT_KEY_KIND_PRIVATE);
	test_assert(enc_type == DCRYPT_KEY_ENCRYPTION_TYPE_KEY);
	test_assert(enc_hash != NULL);
	test_assert(key_hash != NULL);

	dcrypt_keypair_unref(&p1);
	dcrypt_keypair_unref(&p2);

	test_end();
}

static void test_get_info_pw_encrypted(void)
{
	test_begin("test_get_info_pw_encrypted");

	struct dcrypt_keypair p1;
	i_zero(&p1);
	const char *error;
	bool ret = dcrypt_keypair_generate(&p1,
		DCRYPT_KEY_EC, 0, "secp521r1", &error);
	test_assert(ret == TRUE);

	string_t* buf = t_str_new(4096);
	ret = dcrypt_key_store_private(p1.priv,
		DCRYPT_FORMAT_DOVECOT, "aes-256-ctr", buf, "pw", NULL, &error);
	test_assert(ret == TRUE);

	enum dcrypt_key_format format;
	enum dcrypt_key_version version;
	enum dcrypt_key_kind kind;
	enum dcrypt_key_encryption_type enc_type;
	const char *enc_hash;
	const char *key_hash;

	ret = dcrypt_key_string_get_info(str_c(buf), &format, &version,
			&kind, &enc_type, &enc_hash, &key_hash, &error);
	test_assert(ret == TRUE);
	test_assert(format == DCRYPT_FORMAT_DOVECOT);
	test_assert(version == DCRYPT_KEY_VERSION_2);
	test_assert(kind == DCRYPT_KEY_KIND_PRIVATE);
	test_assert(enc_type == DCRYPT_KEY_ENCRYPTION_TYPE_PASSWORD);
	test_assert(enc_hash == NULL);
	test_assert(key_hash != NULL);

	dcrypt_keypair_unref(&p1);

	test_end();
}

static void test_password_change(void)
{
	test_begin("test_password_change");

	const char *pw1 = "first password";
	struct dcrypt_keypair orig;
	const char *error = NULL;

	bool ret = dcrypt_keypair_generate(&orig,
		DCRYPT_KEY_EC, 0, "secp521r1", &error);
	test_assert(ret == TRUE);

	string_t *buf = t_str_new(4096);
	ret = dcrypt_key_store_private(orig.priv,
		DCRYPT_FORMAT_DOVECOT, "aes-256-ctr", buf, pw1, NULL, &error);
	test_assert(ret == TRUE);

	/* load the pw-encrypted key */
	struct dcrypt_private_key *k1_priv = NULL;
	ret = dcrypt_key_load_private(&k1_priv, str_c(buf), pw1, NULL, &error);
	test_assert(ret == TRUE);

	/* encrypt a key with the pw-encrypted key k1 */
	struct dcrypt_keypair k2;
	ret = dcrypt_keypair_generate(&k2,
		DCRYPT_KEY_EC, 0, "secp521r1", &error);
	test_assert(ret == TRUE);

	string_t *buf2 = t_str_new(4096);
	struct dcrypt_public_key *k1_pub = NULL;
	dcrypt_key_convert_private_to_public(k1_priv, &k1_pub);
	ret = dcrypt_key_store_private(k2.priv,
		DCRYPT_FORMAT_DOVECOT, "ecdh-aes-256-ctr", buf2,
		NULL, k1_pub, &error);
	test_assert(ret == TRUE);

	/* change the password */
	const char *pw2 = "second password";
	string_t *buf3 = t_str_new(4096);

	/* encrypt k1 with pw2 */
	ret = dcrypt_key_store_private(k1_priv,
		DCRYPT_FORMAT_DOVECOT, "aes-256-ctr", buf3, pw2, NULL, &error);
	test_assert(ret == TRUE);

	/* load the pw2 encrypted key */
	struct dcrypt_private_key *k2_priv = NULL;
	ret = dcrypt_key_load_private(&k2_priv, str_c(buf3), pw2, NULL, &error);
	test_assert(ret == TRUE);

	/* load the key that was encrypted with pw1 using the pw2 encrypted key */
	struct dcrypt_private_key *k3_priv = NULL;
	ret = dcrypt_key_load_private(&k3_priv,
		str_c(buf2), NULL, k2_priv, &error);
	test_assert(ret == TRUE);

	dcrypt_key_unref_private(&k1_priv);
	dcrypt_key_unref_public(&k1_pub);
	dcrypt_key_unref_private(&k2_priv);
	dcrypt_key_unref_private(&k3_priv);
	dcrypt_keypair_unref(&orig);
	dcrypt_keypair_unref(&k2);

	test_end();
}

static void test_load_invalid_keys(void)
{
	test_begin("test_load_invalid_keys");

	static const struct {
		const char *key;
		const char *error;
		bool public;
	} invalid_keys[] = {
		{
			.key = "1:716:0301EB00973C4EFC8FCECA4EA33E941F50B561199A51"
			       "59BCB6C2EED9DD1D62D65E38A254979D89E28F0C28883E71EE"
			       "2AD264CD16B863FA094A8F6F69A56B62E8918040:7c9a1039e"
			       "a2e4fed73e81dd3ffc3fa22ea4a28352939adde7bf8ea858b0"
			       "0fa4f",
			.error =
				"Dovecot v1 key format uses tab to separate fields",
			.public = TRUE,
		},
		{
			.key = "2:305e301006072a8648ce3d020106052b81040026034a0002"
			       "03fcc90034fa03d6fb79a0fc8b3b43c3398f68e76029307360"
			       "cdcb9e27bb7e84b3c19dfb7244763bc4d442d216f09b7b7945"
			       "ed9d182f3156550e9ee30b237a0217dbf79d28975f31:86706"
			       "b69d1f640011a65d26a42f2ba20a619173644e1cc7475eb1d9"
			       "0966e84dc",
			.error = "key is not private",
			.public = FALSE,
		},
		/* JWT ECDSA: Missing kty */
		{
			.key = "{"
			       "\"d\":\"gSGuVf7wU1eT_QTyIuT57UgKm8gh5NYi6TaGTLOOZ28\","
			       "\"use\":\"sig\","
			       "\"crv\":\"P-256\","
			       "\"x\":\"-TjShNC76Uconyoo25WUmm9BuuDn5gmx2T14d6i5vgQ\","
			       "\"y\":\"V3zIBTnVTKY14HZP9a2lXgReyq6-EeOrCoZf76KUlEc\","
			       "\"alg\":\"ES256\""
			       "}",
			.error = "Missing kty parameter",
			.public = FALSE,
		},
		/* JWT ECDSA: Missing curve */
		{
			.key = "{"
			       "\"kty\":\"EC\","
			       "\"d\":\"gSGuVf7wU1eT_QTyIuT57UgKm8gh5NYi6TaGTLOOZ28\","
			       "\"use\":\"sig\","
			       "\"x\":\"-TjShNC76Uconyoo25WUmm9BuuDn5gmx2T14d6i5vgQ\","
			       "\"y\":\"V3zIBTnVTKY14HZP9a2lXgReyq6-EeOrCoZf76KUlEc\","
			       "\"alg\":\"ES256\""
			       "}",
			.error = "Missing crv parameter",
			.public = FALSE,
		},
		/* JWT ECDSA: Unsupported curve */
		{
			.key = "{"
			       "\"kty\":\"EC\","
			       "\"d\":\"gSGuVf7wU1eT_QTyIuT57UgKm8gh5NYi6TaGTLOOZ28\","
			       "\"use\":\"sig\","
			       "\"crv\":\"secp384k5\","
			       "\"x\":\"-TjShNC76Uconyoo25WUmm9BuuDn5gmx2T14d6i5vgQ\","
			       "\"y\":\"V3zIBTnVTKY14HZP9a2lXgReyq6-EeOrCoZf76KUlEc\","
			       "\"alg\":\"ES256\""
			       "}",
			.error = "Unsupported curve: secp384k5",
			.public = FALSE,
		},
		/* JWT ECDSA: Wrong curve for key */
		{
			.key = "{"
			       "\"kty\":\"EC\","
			       "\"d\":\"gSGuVf7wU1eT_QTyIuT57UgKm8gh5NYi6TaGTLOOZ28\","
			       "\"use\":\"sig\","
			       "\"crv\":\"P-384\","
			       "\"x\":\"-TjShNC76Uconyoo25WUmm9BuuDn5gmx2T14d6i5vgQ\","
			       "\"y\":\"V3zIBTnVTKY14HZP9a2lXgReyq6-EeOrCoZf76KUlEc\","
			       "\"alg\":\"ES256\""
			       "}",
			.error = "point is not on curve",
			.public = FALSE,
		},
		/* JWT ECDSA: Missing private key */
		{
			.key = "{"
			       "\"kty\":\"EC\","
			       "\"use\":\"sig\","
			       "\"crv\":\"P-256\","
			       "\"x\":\"-TjShNC76Uconyoo25WUmm9BuuDn5gmx2T14d6i5vgQ\","
			       "\"y\":\"V3zIBTnVTKY14HZP9a2lXgReyq6-EeOrCoZf76KUlEc\","
			       "\"alg\":\"ES256\""
			       "}",
			.error = "key is not private",
			.public = FALSE,
		},
		/* JWT ECDSA: Missing public key */
		{
			.key = "{"
			       "\"kty\":\"EC\","
			       "\"d\":\"gSGuVf7wU1eT_QTyIuT57UgKm8gh5NYi6TaGTLOOZ28\","
			       "\"use\":\"sig\","
			       "\"crv\":\"P-256\","
			       "\"alg\":\"ES256\""
			       "}",
			.error = "Missing x parameter",
			.public = FALSE,
		},
		/* JWT ECDSA: Missing x */
		{
			.key = "{"
			       "\"kty\":\"EC\","
			       "\"d\":\"gSGuVf7wU1eT_QTyIuT57UgKm8gh5NYi6TaGTLOOZ28\","
			       "\"use\":\"sig\","
			       "\"crv\":\"P-256\","
			       "\"y\":\"V3zIBTnVTKY14HZP9a2lXgReyq6-EeOrCoZf76KUlEc\","
			       "\"alg\":\"ES256\""
			       "}",
			.error = "Missing x parameter",
			.public = FALSE,
		},
		/* JWT ECDSA: Missing y */
		{
			.key = "{"
			       "\"kty\":\"EC\","
			       "\"d\":\"gSGuVf7wU1eT_QTyIuT57UgKm8gh5NYi6TaGTLOOZ28\","
			       "\"use\":\"sig\","
			       "\"crv\":\"P-256\","
			       "\"x\":\"-TjShNC76Uconyoo25WUmm9BuuDn5gmx2T14d6i5vgQ\","
			       "\"alg\":\"ES256\""
			       "}",
			.error = "Missing y parameter",
			.public = FALSE,
		},
		/* JWT ECDSA: d does not match x,y */
		{
			.key = "{"
			       "\"kty\":\"EC\","
			       "\"d\":\"I_HrrKbVygrMsHcF3jDmQzXorfnzWb9ZGgZshvjOo9k\","
			       "\"use\":\"sig\","
			       "\"crv\":\"P-256\","
			       "\"x\":\"-TjShNC76Uconyoo25WUmm9BuuDn5gmx2T14d6i5vgQ\","
			       "\"y\":\"V3zIBTnVTKY14HZP9a2lXgReyq6-EeOrCoZf76KUlEc\","
			       "\"alg\":\"ES256\""
			       "}",
#ifdef HAVE_OPENSSL3
			.error = "Private key did not match with public key",
#else
			.error = "invalid private key",
#endif
			.public = FALSE,
		},
		/* JWT ECDSA: x,y does not match d */
		{
			.key = "{"
			       "\"kty\":\"EC\","
			       "\"d\":\"gSGuVf7wU1eT_QTyIuT57UgKm8gh5NYi6TaGTLOOZ28\","
			       "\"use\":\"sig\","
			       "\"crv\":\"P-256\","
			       "\"x\":\"YlM4gDHMvdBUG7jD9rle5H2xQrYFdd2CeL_UnF9TyVQ\","
			       "\"y\":\"GNg7QEUgyjyE7DBc8ciuu9JAg9bJlaFvP2gLpexrjsw\","
			       "\"alg\":\"ES256\""
			       "}",
#ifdef HAVE_OPENSSL3
			.error = "Private key did not match with public key",
#else
			.error = "invalid private key",
#endif
			.public = FALSE,
		},
		/* JWT ECDSA: y does not match d, x */
		{
			.key = "{"
			       "\"kty\":\"EC\","
			       "\"d\":\"gSGuVf7wU1eT_QTyIuT57UgKm8gh5NYi6TaGTLOOZ28\","
			       "\"use\":\"sig\","
			       "\"crv\":\"P-256\","
			       "\"x\":\"-TjShNC76Uconyoo25WUmm9BuuDn5gmx2T14d6i5vgQ\","
			       "\"y\":\"GNg7QEUgyjyE7DBc8ciuu9JAg9bJlaFvP2gLpexrjsw\","
			       "\"alg\":\"ES256\""
			       "}",
			.error = "point is not on curve",
			.public = FALSE,
		},
		/* JWT RSA: Missing d */
		{
			.key = "{"
			       "\"p\": \"0Il4JCQvWtDxyVEHd18rqxhXzdzIaJ3Xq5311ppIXs-oNCe2G2eTAE-CRiePOE0aQ0rl0fjkEeL8kRZZa17npQ\","
			       "\"kty\": \"RSA\","
			       "\"q\": \"stp6wLoE3XI3oITZO73DkhpDpuNpZ4uMHCg8GCcj784xhLtlPF_hiPgNMgT7tS4JFHFwn7V5GEG3Rk8ThDVvPQ\","
			       "\"e\": \"AQAB\","
			       "\"use\": \"sig\","
			       "\"n\": \"kbGOl_HS6aYs8Ya2Y-OMlK8YcaGldcLanU6wF8nCI0WnedR_DnzZllDhWr7o8h0J5BKuL7Hop_8rn5zSEva213_Zpy3cE5DdrWtdpGyyz9cTceuhukvFSBfw_D4HOQdigRYwerl8Oq6kqCYDL5ui-TmYDLbL_oVdXshfMsU2vVE\""
			       "}",
			.error = "key is not private",
			.public = FALSE,
		},
		/* JWT RSA: Missing e */
		{
			.key = "{"
			       "\"p\": \"0Il4JCQvWtDxyVEHd18rqxhXzdzIaJ3Xq5311ppIXs-oNCe2G2eTAE-CRiePOE0aQ0rl0fjkEeL8kRZZa17npQ\","
			       "\"kty\": \"RSA\","
			       "\"q\": \"stp6wLoE3XI3oITZO73DkhpDpuNpZ4uMHCg8GCcj784xhLtlPF_hiPgNMgT7tS4JFHFwn7V5GEG3Rk8ThDVvPQ\","
			       "\"d\": \"CqxINudXPRiYWEU3HVAxHz9IeiKOXXcdzsJR8hwsparXnvwrJqOMyQ85ww0TQZFRBS09J29QDOaLipDRbuQ19q0c7k0ek_sIrrzx9iulSCPdrbhdw0LS48HfsJxoD5xFg8E5BtDAjnd0P3eUrtG3R1rZXpvnlMd6-kLW-WAyGnE\","
			       "\"use\": \"sig\","
			       "\"n\": \"kbGOl_HS6aYs8Ya2Y-OMlK8YcaGldcLanU6wF8nCI0WnedR_DnzZllDhWr7o8h0J5BKuL7Hop_8rn5zSEva213_Zpy3cE5DdrWtdpGyyz9cTceuhukvFSBfw_D4HOQdigRYwerl8Oq6kqCYDL5ui-TmYDLbL_oVdXshfMsU2vVE\""
			       "}",
			.error = "Missing e parameter",
			.public = FALSE,
		},
		/* JWT RSA: Missing n */
		{
			.key = "{"
			       "\"p\": \"0Il4JCQvWtDxyVEHd18rqxhXzdzIaJ3Xq5311ppIXs-oNCe2G2eTAE-CRiePOE0aQ0rl0fjkEeL8kRZZa17npQ\","
			       "\"kty\": \"RSA\","
			       "\"q\": \"stp6wLoE3XI3oITZO73DkhpDpuNpZ4uMHCg8GCcj784xhLtlPF_hiPgNMgT7tS4JFHFwn7V5GEG3Rk8ThDVvPQ\","
			       "\"d\": \"CqxINudXPRiYWEU3HVAxHz9IeiKOXXcdzsJR8hwsparXnvwrJqOMyQ85ww0TQZFRBS09J29QDOaLipDRbuQ19q0c7k0ek_sIrrzx9iulSCPdrbhdw0LS48HfsJxoD5xFg8E5BtDAjnd0P3eUrtG3R1rZXpvnlMd6-kLW-WAyGnE\","
			       "\"e\": \"AQAB\","
			       "\"use\": \"sig\""
			       "}",
			.error = "Missing n parameter",
			.public = FALSE,
		},
		/* JWT RSA: Mismatch p,q and d */
		{
			.key = "{"
			       "\"p\": \"7v5Z9uz-SES2yQ1lWTvYIqxW7B6avGJcI6W_t5c5JDzLxmT3OQ-kw9oJV7oYvFVagIVgmTgP1ymvbcfYzDSKKQ\","
			       "\"kty\": \"RSA\","
			       "\"q\": \"sdZWMrIiOa8XJFtRkHKZE5sp6PTvTH1H52Zcr7O14j39zMmR-i9GL1-uI_EQGBA0TK-zxnZ-incUm2cWirwVbw\","
			       "\"d\": \"CqxINudXPRiYWEU3HVAxHz9IeiKOXXcdzsJR8hwsparXnvwrJqOMyQ85ww0TQZFRBS09J29QDOaLipDRbuQ19q0c7k0ek_sIrrzx9iulSCPdrbhdw0LS48HfsJxoD5xFg8E5BtDAjnd0P3eUrtG3R1rZXpvnlMd6-kLW-WAyGnE\","
			       "\"e\": \"AQAB\","
			       "\"use\": \"sig\","
			       "\"n\": \"kbGOl_HS6aYs8Ya2Y-OMlK8YcaGldcLanU6wF8nCI0WnedR_DnzZllDhWr7o8h0J5BKuL7Hop_8rn5zSEva213_Zpy3cE5DdrWtdpGyyz9cTceuhukvFSBfw_D4HOQdigRYwerl8Oq6kqCYDL5ui-TmYDLbL_oVdXshfMsU2vVE\""
			       "}",
			.error = "Cannot derive rsa primes",
			.public = FALSE,
		},
		/* JWT RSA: Mismatch n and p,q,d */
		{
			.key = "{"
			       "\"p\": \"0Il4JCQvWtDxyVEHd18rqxhXzdzIaJ3Xq5311ppIXs-oNCe2G2eTAE-CRiePOE0aQ0rl0fjkEeL8kRZZa17npQ\","
			       "\"kty\": \"RSA\","
			       "\"q\": \"stp6wLoE3XI3oITZO73DkhpDpuNpZ4uMHCg8GCcj784xhLtlPF_hiPgNMgT7tS4JFHFwn7V5GEG3Rk8ThDVvPQ\","
			       "\"d\": \"CqxINudXPRiYWEU3HVAxHz9IeiKOXXcdzsJR8hwsparXnvwrJqOMyQ85ww0TQZFRBS09J29QDOaLipDRbuQ19q0c7k0ek_sIrrzx9iulSCPdrbhdw0LS48HfsJxoD5xFg8E5BtDAjnd0P3eUrtG3R1rZXpvnlMd6-kLW-WAyGnE\","
			       "\"e\": \"AQAB\","
			       "\"use\": \"sig\","
			       "\"n\": \"pgX1S7R5QI9c2Y7X6KXgUyJdOLJP3DZWBR-NR7w96rHOayKeAHKPiyg9vyGzV8rB_uePbmrnhBAZ42IDlXW_AieJGhPLYkH34d4FX8cC7mmWWXXjolajZWoW5pCg2Ilkk47R1osXGkS6Ta97ODtAvzw7PAJq1jFFPjYXVmo5RMc\""
			       "}",
			.error = "Cannot derive rsa primes",
			.public = FALSE,
		},
		/* JWT RSA: Mismatch e */
		{
			.key = "{" \
				"\"p\": \"0Il4JCQvWtDxyVEHd18rqxhXzdzIaJ3Xq5311ppIXs-oNCe2G2eTAE-CRiePOE0aQ0rl0fjkEeL8kRZZa17npQ\"," \
				"\"kty\": \"RSA\"," \
				"\"q\": \"stp6wLoE3XI3oITZO73DkhpDpuNpZ4uMHCg8GCcj784xhLtlPF_hiPgNMgT7tS4JFHFwn7V5GEG3Rk8ThDVvPQ\"," \
				"\"d\": \"CqxINudXPRiYWEU3HVAxHz9IeiKOXXcdzsJR8hwsparXnvwrJqOMyQ85ww0TQZFRBS09J29QDOaLipDRbuQ19q0c7k0ek_sIrrzx9iulSCPdrbhdw0LS48HfsJxoD5xFg8E5BtDAjnd0P3eUrtG3R1rZXpvnlMd6-kLW-WAyGnE\"," \
				"\"e\": \"AQAC\"," \
				"\"use\": \"sig\"," \
				"\"n\": \"kbGOl_HS6aYs8Ya2Y-OMlK8YcaGldcLanU6wF8nCI0WnedR_DnzZllDhWr7o8h0J5BKuL7Hop_8rn5zSEva213_Zpy3cE5DdrWtdpGyyz9cTceuhukvFSBfw_D4HOQdigRYwerl8Oq6kqCYDL5ui-TmYDLbL_oVdXshfMsU2vVE\"" \
			"}",
			.error = "Cannot derive rsa primes",
			.public = FALSE,
		},
#ifdef HAVE_X25519
		/* JWT EdDSA: Missing d */
		{
			.key = "{"
			       "\"kty\": \"OKP\","
			       "\"use\": \"sig\","
			       "\"crv\": \"X25519\","
			       "\"x\": \"JCyCLQ6SqDZbqfzu-HCmet3dQI-iGLChRcYEshx7vns\""
			       "}",
			.error = "key is not private",
			.public = FALSE,
		},
		/* JWT EdDSA: Missing x*/
		{
			.key = "{"
			       "\"kty\": \"OKP\","
			       "\"d\": \"LnPo87ilJKiaF1u6Q59QRUvxJlMs_CJshtLiB29hhlA\","
			       "\"use\": \"sig\","
			       "\"crv\": \"X25519\""
			       "}",
			.error = "Missing x parameter",
			.public = FALSE,
		},
		/* JWT EdDSA: Curve mismatch */
		{
			.key = "{"
			       "\"kty\": \"OKP\","
			       "\"d\": \"LnPo87ilJKiaF1u6Q59QRUvxJlMs_CJshtLiB29hhlA\","
			       "\"use\": \"sig\","
			       "\"crv\": \"X448\","
			       "\"x\": \"JCyCLQ6SqDZbqfzu-HCmet3dQI-iGLChRcYEshx7vns\""
			       "}",
#ifdef HAVE_OPENSSL3
			.error = "Unknown error",
#else
			.error = "key setup failed",
#endif
			.public = FALSE,
		},
#endif
	};

	for (size_t i = 0; i < N_ELEMENTS(invalid_keys); i++) {
		struct dcrypt_keypair pair;
		i_zero(&pair);
		bool ret;
		const char *error = NULL;
		if (invalid_keys[i].public) {
			ret = dcrypt_key_load_public(
				&pair.pub, invalid_keys[i].key, &error);
		} else {
			ret = dcrypt_key_load_private(&pair.priv,
						      invalid_keys[i].key, NULL,
						      NULL, &error);
		}
		test_assert_idx(ret == FALSE, i);
		test_assert_idx(error != NULL, i);
		test_assert_idx(error != NULL && strstr(error, invalid_keys[i].error) != NULL,
				i);
		if (ret)
			dcrypt_keypair_unref(&pair);
	}

	test_end();
}

static void test_raw_keys(void)
{

	test_begin("test_raw_keys");

	const char *error;
	ARRAY_TYPE(dcrypt_raw_key) priv_key;
	ARRAY_TYPE(dcrypt_raw_key) pub_key;
	pool_t pool = pool_datastack_create();

	enum dcrypt_key_type t;

	p_array_init(&priv_key, pool, 2);
	p_array_init(&pub_key, pool, 2);

	/* generate ECC key */
	struct dcrypt_keypair pair;
	i_assert(dcrypt_keypair_generate(&pair, DCRYPT_KEY_EC, 0, "prime256v1", &error));

	/* store it */
	test_assert(dcrypt_key_store_private_raw(pair.priv, pool, &t, &priv_key,
		    NULL));
	test_assert(dcrypt_key_store_public_raw(pair.pub, pool, &t, &pub_key,
		    NULL));
	dcrypt_keypair_unref(&pair);

	/* load it */
	test_assert(dcrypt_key_load_private_raw(&pair.priv, t, &priv_key,
		    NULL));
	test_assert(dcrypt_key_load_public_raw(&pair.pub, t, &pub_key,
		    NULL));

	dcrypt_keypair_unref(&pair);

	/* test load known raw private key */
	const char *curve = "prime256v1";
	const unsigned char priv_key_data[] = {
		0x16, 0x9e, 0x62, 0x36, 0xaf, 0x9c, 0xae, 0x0e, 0x71, 0xda,
		0xf2, 0x63, 0xe2, 0xe0, 0x5d, 0xf1, 0xd5, 0x35, 0x8c, 0x2b,
		0x68, 0xf0, 0x2a, 0x69, 0xc4, 0x5d, 0x3d, 0x1c, 0xde, 0xa1,
		0x9b, 0xd3
	};

	/* create buffers */
	struct dcrypt_raw_key *item;
	ARRAY_TYPE(dcrypt_raw_key) static_key;
	t_array_init(&static_key, 2);

	/* Add OID */
	buffer_t *buf = t_buffer_create(32);
	test_assert(dcrypt_name2oid(curve, buf, &error));
	item = array_append_space(&static_key);
	item->parameter = buf->data;
	item->len = buf->used;

	/* Add key data */
	item = array_append_space(&static_key);
	item->parameter = priv_key_data;
	item->len = sizeof(priv_key_data);

	/* Try load it */
	test_assert(dcrypt_key_load_private_raw(&pair.priv, t,
						&static_key, NULL));

	/* See what we got */
	buf = t_buffer_create(128);
	test_assert(dcrypt_key_store_private(pair.priv, DCRYPT_FORMAT_DOVECOT,
					     NULL, buf, NULL, NULL, NULL));
	test_assert_strcmp(str_c(buf),
			   "2:1.2.840.10045.3.1.7:0:00000020169e6236af9cae0e71d"
			   "af263e2e05df1d5358c2b68f02a69c45d3d1cdea19bd3:21d11"
			   "6b7b3e5c52e81f0437a10b0116cfafc467fb1b96e48926d0216"
			   "68fc1bea");

	/* try to load public key, too */
	const unsigned char pub_key_data[] = {
		0x04, 0xe8, 0x7c, 0x6d, 0xa0, 0x29, 0xfe, 0x5d, 0x16, 0x1a,
		0xd6, 0x6a, 0xc6, 0x1c, 0x78, 0x8a, 0x36, 0x0f, 0xfb, 0x64,
		0xe7, 0x7f, 0x58, 0x13, 0xb3, 0x80, 0x1f, 0x99, 0x45, 0xee,
		0xa9, 0x4a, 0xe2, 0xde, 0xf3, 0x88, 0xc6, 0x37, 0x72, 0x7f,
		0xbe, 0x97, 0x02, 0x94, 0xb2, 0x21, 0x60, 0xa4, 0x98, 0x4e,
		0xfb, 0x46, 0x19, 0x61, 0x4c, 0xc5, 0xe1, 0x9f, 0xe9, 0xb2,
		0xd2, 0x4d, 0xae, 0x83, 0x4b
	};

	array_clear(&static_key);

	/* Add OID */
	buf = t_buffer_create(32);
	test_assert(dcrypt_name2oid(curve, buf, &error));
	item = array_append_space(&static_key);
	item->parameter = buf->data;
	item->len = buf->used;

	/* Add key data */
	item = array_append_space(&static_key);
	item->parameter = pub_key_data;
	item->len = sizeof(pub_key_data);

	/* See what we got */
	test_assert(dcrypt_key_load_public_raw(&pair.pub, t,
					       &static_key, NULL));
	buf = t_buffer_create(128);
	test_assert(dcrypt_key_store_public(pair.pub, DCRYPT_FORMAT_DOVECOT,
					    buf, NULL));
	test_assert_strcmp(str_c(buf),
		"2:3039301306072a8648ce3d020106082a8648ce3d03010703220003e87c6d"
		"a029fe5d161ad66ac61c788a360ffb64e77f5813b3801f9945eea94ae2:21d"
		"116b7b3e5c52e81f0437a10b0116cfafc467fb1b96e48926d021668fc1bea");
	dcrypt_keypair_unref(&pair);

	test_end();
}

static void test_sign_verify_rsa(void)
{
	const char *error = NULL;
	bool valid;
	struct dcrypt_private_key *priv_key = NULL;
	struct dcrypt_public_key *pub_key = NULL;

	buffer_t *signature =
		buffer_create_dynamic(pool_datastack_create(), 128);
	const char *data = "signed data";

	test_begin("sign and verify (rsa)");
	const char *key =
"-----BEGIN PRIVATE KEY-----\n"
"MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALz2rTYj017MEtD6\n"
"i2flctgTtL4awpTPn2iCvjkMD/owj2N7LRbnpJ5ZDUUkPW8OEDH9NEEx86aFwg+w\n"
"GNzmxqRg5rA92iKouM4iU76IfCdtuYu4yyq57T2+C9mwqO5OvYXkM4VBjjcGr813\n"
"7huMcki104znz7HADYj/y8Nu0jyPAgMBAAECgYEAkJStMx92OrIqM3t/7p7AoFNz\n"
"l4EiIHo7ndtrcHqqPuOo0pUMitnyOrYoUR7JYo+AFL+Hm9p8co0lTpuOanaoxQk8\n"
"Hs9MDzvp4OjRyr0+mVSqKGJOVckXA1Bi0X6jbtOjm3bn7mp1ICPrnv6VB8VP1ef1\n"
"/NgcOai1RHEfXQWAWQECQQD7s3LqUFN5vdYuc/RQ98/NAuKUSvy7zU8tZ7r1Ea2w\n"
"RoxAcakc6Xh75u+9VhsbVyDHDEjWbTW5H2uqkPeotR2tAkEAwDDpS83xH6ilhNnP\n"
"Cors2WKKXZBkw+ZczThJXWIWrbo0zrTDYWYeo46HQRulJawW0iDEkVahk62uC7Go\n"
"Im5SqwJAXcShd/dK0dzOEOozx4I6kPaVMIerFc/Lwm+Vb70RRs1RbKSrStETiJ0l\n"
"DRUp7gqMdHr4G6H91KSG+Lke+mPW1QJAdG8tZ5dktWFepZWvMRvpUem5GeYYpfYx\n"
"0sJ+7+w1ARsGUxSAKcnMVhpLJs6wxpnzWWowrDxntyhJgRwoWHOt8QJBAPuX7gGH\n"
"Lxm7PpWgYYhnAiHGQmsiYEWZpTDHw3qODbSyANFjAKgaQZ3sHy4gdksmhbNJK60e\n"
"K7mLk9hTLlVPXJM=\n"
"-----END PRIVATE KEY-----";

	test_assert(dcrypt_key_load_private(&priv_key,
		key, NULL, NULL, &error));
	if (priv_key == NULL)
		i_fatal("%s", error);
	dcrypt_key_convert_private_to_public(priv_key, &pub_key);
	test_assert(dcrypt_sign(priv_key, "sha256", DCRYPT_SIGNATURE_FORMAT_DSS,
		 data, strlen(data), signature, 0, &error));
	/* verify signature */
	test_assert(dcrypt_verify(pub_key, "sha256", DCRYPT_SIGNATURE_FORMAT_DSS,
		 data, strlen(data),
		 signature->data, signature->used, &valid, 0, &error) && valid);

	dcrypt_key_unref_public(&pub_key);
	dcrypt_key_unref_private(&priv_key);

	test_end();
}

static void test_sign_verify_ecdsa(void)
{
	const char *error = NULL;
	bool valid;
	struct dcrypt_private_key *priv_key = NULL;
	struct dcrypt_public_key *pub_key = NULL;

	buffer_t *signature =
		buffer_create_dynamic(pool_datastack_create(), 128);
	const char *data = "signed data";

	test_begin("sign and verify (ecdsa)");
	const char *key =
"-----BEGIN PRIVATE KEY-----\n"
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZ4AMMyJ9XDl5lKM2\n"
"vusbT1OQ6VzBWBkB3/4syovaKtyhRANCAAQHTR+6L2qMh5fdcMZF+Y1rctBsq8Oy\n"
"7jZ4uV+MiuaoGNQ5sTxlcv6ETX/XrEDq4S/DUhFKzQ6u9VXYZImvRCT1\n"
"-----END PRIVATE KEY-----";

	test_assert(dcrypt_key_load_private(&priv_key,
		key, NULL, NULL, &error));
	if (priv_key == NULL)
		i_fatal("%s", error);
	dcrypt_key_convert_private_to_public(priv_key, &pub_key);
	test_assert(dcrypt_sign(priv_key, "sha256", DCRYPT_SIGNATURE_FORMAT_DSS,
		data, strlen(data), signature, 0, &error));
	/* verify signature */
	test_assert(dcrypt_verify(pub_key, "sha256", DCRYPT_SIGNATURE_FORMAT_DSS,
		data, strlen(data), signature->data,
		signature->used, &valid, 0, &error) && valid);

	dcrypt_key_unref_public(&pub_key);
	dcrypt_key_unref_private(&priv_key);

	test_end();
}

static void test_sign_verify_x962(void)
{
	const char *error = NULL;
	bool valid;
	struct dcrypt_private_key *priv_key = NULL;
	struct dcrypt_public_key *pub_key = NULL;

	buffer_t *signature =
		buffer_create_dynamic(pool_datastack_create(), 128);
	const char *data = "signed data";

	test_begin("sign and verify (x9.62)");
	const char *key =
"-----BEGIN PRIVATE KEY-----\n"
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZ4AMMyJ9XDl5lKM2\n"
"vusbT1OQ6VzBWBkB3/4syovaKtyhRANCAAQHTR+6L2qMh5fdcMZF+Y1rctBsq8Oy\n"
"7jZ4uV+MiuaoGNQ5sTxlcv6ETX/XrEDq4S/DUhFKzQ6u9VXYZImvRCT1\n"
"-----END PRIVATE KEY-----";

	test_assert(dcrypt_key_load_private(&priv_key,
		key, NULL, NULL, &error));
	if (priv_key == NULL)
		i_fatal("%s", error);
	dcrypt_key_convert_private_to_public(priv_key, &pub_key);
	test_assert(dcrypt_sign(priv_key, "sha256", DCRYPT_SIGNATURE_FORMAT_X962,
		data, strlen(data), signature, 0, &error));
	/* verify signature */
	test_assert(dcrypt_verify(pub_key, "sha256", DCRYPT_SIGNATURE_FORMAT_X962,
		data, strlen(data), signature->data,
		signature->used, &valid, 0, &error) && valid);

	dcrypt_key_unref_public(&pub_key);
	dcrypt_key_unref_private(&priv_key);

	test_end();
}

static void test_static_verify_ecdsa(void)
{
	test_begin("static verify (ecdsa)");
	const char *input = "hello, world";
	const char *priv_key_pem =
"-----BEGIN PRIVATE KEY-----\n"
"MGcCAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcETTBLAgEBBCC25AkD65uhlZXCAdwN\n"
"yLJV2ui8A/CUyqyEMrezvwgMO6EkAyIAAybRUR3MsH0+0PQcDwkrXOJ9aePwzTQV\n"
"DN51+n1JCxbI\n"
"-----END PRIVATE KEY-----";
	const char *pub_key_pem =
"-----BEGIN PUBLIC KEY-----\n"
"MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADJtFRHcywfT7Q9BwPCStc4n1p4/DN\n"
"NBUM3nX6fUkLFsg=\n"
"-----END PUBLIC KEY-----";

	const unsigned char sig[] = {
		0x30,0x45,0x02,0x20,0x2c,0x76,0x20,0x5e,0xfc,0xa6,0x9e,0x16,
		0x44,0xb3,0xbc,0xbf,0xcc,0x43,0xc1,0x08,0x76,0x4a,0xe8,0x60,
		0xc5,0x9b,0x99,0x20,0x5b,0x44,0x33,0x5c,0x38,0x84,0x63,0xcb,
		0x02,0x21,0x00,0xa3,0x67,0xed,0x57,0xbf,0x59,0x46,0xb7,0x0c,
		0x7b,0xec,0x4f,0x78,0x14,0xec,0xfa,0x8d,0xa2,0x85,0x48,0xea,
		0xe1,0xaf,0x9e,0xbf,0x04,0xac,0x0e,0x41,0xfe,0x84,0x0e
	};

	struct dcrypt_keypair pair;
	bool valid;
	const char *error;

	i_zero(&pair);
	/* static key test */
	test_assert(dcrypt_key_load_public(&pair.pub, pub_key_pem, &error));
	test_assert(dcrypt_key_load_private(&pair.priv, priv_key_pem, NULL, NULL, &error));
	/* validate signature */
	test_assert(dcrypt_verify(pair.pub, "sha256", DCRYPT_SIGNATURE_FORMAT_DSS,
				  input, strlen(input),
				  sig, sizeof(sig), &valid, 0, &error) &&
		    valid == TRUE);

	dcrypt_keypair_unref(&pair);

	test_end();
}

static void test_jwk_key(const char *jwk_key_json_in, const char *jwk_key_json_out,
			 const char *pem_key)
{
	const char *error ATTR_UNUSED;
	struct dcrypt_keypair pair;
	buffer_t *pem = t_buffer_create(256);
	i_zero(&pair);

	test_assert(dcrypt_key_load_public(&pair.pub, jwk_key_json_in, &error));
	test_assert(dcrypt_key_load_private(&pair.priv, jwk_key_json_in, NULL, NULL, &error));

	/* test accessors */
	test_assert_strcmp(dcrypt_key_get_id_public(pair.pub), "123");
	test_assert(dcrypt_key_get_usage_public(pair.pub) == DCRYPT_KEY_USAGE_SIGN);

	/* make sure we got the right key */
	test_assert(dcrypt_key_store_public(pair.pub, DCRYPT_FORMAT_PEM, pem, &error));
	const char *pem_result = str_c(pem);
	if (pem_result[strlen(pem_result)-1] != '\n')
		str_append_c(pem, '\n');
	test_assert_strcmp(str_c(pem), pem_key);

	i_assert(pair.priv != NULL);

	str_truncate(pem, 0);
	test_assert(dcrypt_key_store_private(pair.priv, DCRYPT_FORMAT_JWK, NULL, pem, NULL, NULL, &error));
	test_assert_strcmp(str_c(pem), jwk_key_json_out);

	dcrypt_keypair_unref(&pair);
}

static void test_jwk_keys(void)
{
	/* Make sure to get PEM output using something else */
	struct {
		const char *json_in;
		const char *json_out;
		const char *pem;
	} cases[] = {
		{
			.json_in = "{\"kty\":\"EC\","
				"\"crv\":\"P-256\","
				"\"x\":\"Kp0Y4-Wpt-D9t_2XenFIj0LmvaZByLG69yOisek4aMI\","
				"\"y\":\"wjEPB5BhH5SRPw1cCN5grWrLCphrW19fCFR8p7c9O5o\","
				"\"use\":\"sig\","
				"\"kid\":\"123\","
				"\"d\":\"Po2z9rs86J2Qb_xWprr4idsWNPlgKf3G8-mftnE2ync\"}",
			.json_out = "{\"kty\":\"EC\","
				"\"crv\":\"P-256\","
				"\"x\":\"Kp0Y4-Wpt-D9t_2XenFIj0LmvaZByLG69yOisek4aMI\","
				"\"y\":\"wjEPB5BhH5SRPw1cCN5grWrLCphrW19fCFR8p7c9O5o\","
				"\"use\":\"sig\","
				"\"kid\":\"123\","
				"\"d\":\"Po2z9rs86J2Qb_xWprr4idsWNPlgKf3G8-mftnE2ync\"}",
			.pem = "-----BEGIN PUBLIC KEY-----\n"
			       "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKp0Y4+Wpt+D9t/2XenFIj0LmvaZB\n"
			       "yLG69yOisek4aMLCMQ8HkGEflJE/DVwI3mCtassKmGtbX18IVHyntz07mg==\n"
			       "-----END PUBLIC KEY-----\n",
		},
		{ .json_in = "{\"kty\":\"RSA\","
			  "\"n\":\"vvznTCNpPXQW_HND7U3gGEzSiu_kgRrv2fUCD1HqycgLlz2bToo"
			  "OQjPLnx-2I1d6kw4PjSCGnLxVRMkFF7IK0SoJ1pN5vYbTX3R3Ns"
			  "D2WnQQubjLiQKlj7S18n-jyL7T4-hDGRG4tqEa_5LwAptooOD64"
			  "3JeJJYF8scVeKNYtR8\","
			  "\"e\":\"AQAB\","
			  "\"use\":\"sig\","
			  "\"kid\":\"123\","
			  "\"d\":\"igf0DpYFKHHvbvLLZAWFcWqMO_fW2Owj7w1hOLtGiiD3J45R4Xhr"
			  "h7MxdcaQd4hwwTlHSgL45uxCYB08ffyiTXq9RQyiA9bZC8Xz9gP"
			  "MzjzztG7uCY8us24wu_B0vdi-UPcV8Qe3P7zu2nlpvJFMmnW5C9"
			  "0sWZO--MwshVWtjlk\"}",
		  .json_out = "{\"kty\":\"RSA\","
			  "\"n\":\"vvznTCNpPXQW_HND7U3gGEzSiu_kgRrv2fUCD1HqycgLlz2bTooOQjPLnx"
			  "-2I1d6kw4PjSCGnLxVRMkFF7IK0SoJ1pN5vYbTX3R3NsD2WnQQubjLiQKlj7S18n-j"
			  "yL7T4-hDGRG4tqEa_5LwAptooOD643JeJJYF8scVeKNYtR8\","
			  "\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"123\","
			  "\"d\":\"igf0DpYFKHHvbvLLZAWFcWqMO_fW2Owj7w1hOLtGiiD3J45R4Xhrh7Mxdca"
			  "Qd4hwwTlHSgL45uxCYB08ffyiTXq9RQyiA9bZC8Xz9gPMzjzztG7uCY8us24wu_B0vd"
			  "i-UPcV8Qe3P7zu2nlpvJFMmnW5C90sWZO--MwshVWtjlk\",\"p\":\"7WD6fHlqSGf"
			  "ukEULSrEwD77Roxlhzmb-FuCq-wNUUvphOlxIzWzT3p0et1PkgSWhmax2QAzLRaS1ee"
			  "XhjJYWOw\",\"q\":\"zfhOeQ-TN1hrAsyxtWTrNe45HxThb_He8xJm5cOiGa85gEZF"
			  "6mmawWsZiXMmJ9UTMC0j8ZJ09Y3U8bUU2lnabQ\",\"dp\":\"mB2WRt_TYPThJqhoF"
			  "QQ4xU5FrtvcFlVfrC9qwhIfHlF-rtRmfuWnW7eZ8GcdPjlsNjsTR_Yq6MUk2imbAOlI"
			  "8w\",\"dq\":\"Xe9t0paA3I_tlgRG0-SnxRvVX1CFlClqNc9hsE4toqsgfVkPT95D3"
			  "wx6RA6JC0eJDcK4jtbtkoPR5z5fuUmbbQ\",\"qi\":\"YAowniOLomk52oiRbA3o0B"
			  "QwRKAPbXtRBYJbxsLL4XuISWcvQ6II54D6uziqyjKc4VifvngRC3mEmEyGaEudFA\"}",
		  .pem = "-----BEGIN PUBLIC KEY-----\n"
			 "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+/OdMI2k9dBb8c0PtTeAYTNKK\n"
			 "7+SBGu/Z9QIPUerJyAuXPZtOig5CM8ufH7YjV3qTDg+NIIacvFVEyQUXsgrRKgnW\n"
			 "k3m9htNfdHc2wPZadBC5uMuJAqWPtLXyf6PIvtPj6EMZEbi2oRr/kvACm2ig4Prj\n"
			 "cl4klgXyxxV4o1i1HwIDAQAB\n"
			 "-----END PUBLIC KEY-----\n" },
		{.json_in = "{" \
			"\"p\": \"3sx9h7zkPBGs0cnvEFLABeEZ8ew4Jdh1y2r-coJRmPy2rX"
			"0fh4kw2trqYZirGUqOj4Gz6yf6-_nB3W4QHZamLdl1zADHuV-OM6Tk2"
			"DTVctgbwasXnFjvIgOh6FZZyWXhgSnoLdwUTRjDyDzQqOZ0ttb8mnPD"
			"ZmXFyM2GnAu4CSk\","
			"\"kty\": \"RSA\","
			"\"q\": \"lMrUzcLmjz_yUbFx7c4rdO0KYQ6GU7hZ5K2LjEOM4l3OLw"
			"EBMxm_CeS5_qZhiOgbKklovlu6hGuxzn0asPax9EhpDt8W3PYZoQjYc"
			"2SwtOuB7wudtZMFHX_L19Tv6Q3EN8fkqQFGoiiRDrPi4MePy-MNBbBD"
			"3otbWIg65fmqbkk\","
			"\"d\": \"O5jrumGNlc3BOfyTUxYGlZPvgYA-qII64dsDwXtTwbqmwi"
			"63km_ij7yVZiMX8oSOkR5UVwK0VsdX4Zq6LPCjeg80Xjd-noYwQ9A5h"
			"AW1YNKDN5IMYqIPXSF0rPpbwaGzLUPToZORblqKkrOfCuvkUB9RY7A1"
			"fyYxad7b9I178R3RiT9pyfC_8axEBnkXjfo_HehBkGKK-8I9cetxzDA"
			"8xEJekja1V5nnzWq7_fO2VtEu5L_W-JxAtPWT-Hh484OzZrOmZo93HW"
			"vml5D7ezJMslTx90hHkxqf66c0x7gmmLsU8GmI5yBsZitz5lQrYR6jY"
			"nfsm3Ye87VcfwMMUa1qgQ\","
			"\"e\": \"AQAB\","
			"\"use\": \"sig\","
			"\"kid\": \"123\","
			"\"qi\": \"JWvEuWge1CB6lrFsBHtco3pfC-xUOBtQArH7H3bGH5I_b"
			"Ewxqvtnau3WH89DOXDoZsKBIuuoIl_rW9640pRpp9UOoLrE7jGqevDj"
			"mcq2ZwKMIGp9XeAs2zMm08-sQmFp6NAfhjFhBhvH2ITqrLs49cHNvtL"
			"g8WVpiDJRnHEgKSQ\","
			"\"dp\": \"ICgdmiDOREk8y068_XskEfUqXHt-ox-56LE5pmdexZj7-"
			"NBNY6-OaJgeKhXx5AWZy-aphDBSDlo---mt08dxlr6DPP2D1iKPkK6l"
			"BPujLx836lz6XGuNoDgr_y-vZ90Xjh_xTeUs3O_NGjKE30vb3qPq85P"
			"vyPC5ekEHw7ABUPk\","
			"\"alg\": \"RS256\","
			"\"dq\": \"RipUKefkA9967O1JtYPI2G3DvDs2OxqvQXhZWz6rnD_yM"
			"BZAM5HLleXHk_9v9TjHPqy5eTMWhMWoZqB2Ssc66eCPslSfmnlvYpIi"
			"SGBOODLq5ghLScnX2q5eORyQOg2k300jVlNktKl-pjlMHwXcmKAsjuc"
			"tSi_bVqd_Zt3Scgk\","
			"\"n\": \"gX6_IfGjjHZozSzXlGPTwoEE6v_zTyDGB_Xc1P6aAZUHFe"
			"1gV8pD_6c6-i6HeWR79zbtL6QGH6OCQdnn_pkVh7zmxS4yMfsz6NmqL"
			"S5NftG-Uw1tRhxMG-nypPRyPd6IO4ozeujAt25_htnfOdMlQp-uAJc5"
			"Lu7pM_8qr-g9O-Q1ih-FBhGp8xbyEvDw4VRtr1OyZsHDPV9f35QXyny"
			"PqO-oeCEqqDoWEnwSgbDRek93m3gnsYjvti_3VsaH1YtjfU6K-ZXhbC"
			"xNxhhOo8Zr-ZxEVIs_Ck6dXttuCPA5enf0fREsw4fP_gY2RR5b6Lv7E"
			"mdR2MjOB9Pg87RUYaQ6sQ\""
			"}",
		.json_out = "{\"kty\":\"RSA\",\"n\":\"gX6_IfGjjHZozSzXlGPTwoEE6v_zTyDGB_Xc1P6aA"
			"ZUHFe1gV8pD_6c6-i6HeWR79zbtL6QGH6OCQdnn_pkVh7zmxS4yMfsz6NmqLS5NftG-Uw1"
			"tRhxMG-nypPRyPd6IO4ozeujAt25_htnfOdMlQp-uAJc5Lu7pM_8qr-g9O-Q1ih-FBhGp8"
			"xbyEvDw4VRtr1OyZsHDPV9f35QXynyPqO-oeCEqqDoWEnwSgbDRek93m3gnsYjvti_3Vsa"
			"H1YtjfU6K-ZXhbCxNxhhOo8Zr-ZxEVIs_Ck6dXttuCPA5enf0fREsw4fP_gY2RR5b6Lv7E"
			"mdR2MjOB9Pg87RUYaQ6sQ\","
			"\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"123\","
			"\"d\":\"O5jrumGNlc3BOfyTUxYGlZPvgYA-qII64dsDwXtTwbqmwi63km_ij7yVZiMX8o"
			"SOkR5UVwK0VsdX4Zq6LPCjeg80Xjd-noYwQ9A5hAW1YNKDN5IMYqIPXSF0rPpbwaGzLUPT"
			"oZORblqKkrOfCuvkUB9RY7A1fyYxad7b9I178R3RiT9pyfC_8axEBnkXjfo_HehBkGKK-8"
			"I9cetxzDA8xEJekja1V5nnzWq7_fO2VtEu5L_W-JxAtPWT-Hh484OzZrOmZo93HWvml5D7"
			"ezJMslTx90hHkxqf66c0x7gmmLsU8GmI5yBsZitz5lQrYR6jYnfsm3Ye87VcfwMMUa1qgQ\","
			"\"p\":\"3sx9h7zkPBGs0cnvEFLABeEZ8ew4Jdh1y2r-coJRmPy2rX0fh4kw2trqYZirGU"
			"qOj4Gz6yf6-_nB3W4QHZamLdl1zADHuV-OM6Tk2DTVctgbwasXnFjvIgOh6FZZyWXhgSno"
			"LdwUTRjDyDzQqOZ0ttb8mnPDZmXFyM2GnAu4CSk\",\"q\":\"lMrUzcLmjz_yUbFx7c4r"
			"dO0KYQ6GU7hZ5K2LjEOM4l3OLwEBMxm_CeS5_qZhiOgbKklovlu6hGuxzn0asPax9EhpDt"
			"8W3PYZoQjYc2SwtOuB7wudtZMFHX_L19Tv6Q3EN8fkqQFGoiiRDrPi4MePy-MNBbBD3otb"
			"WIg65fmqbkk\",\"dp\":\"ICgdmiDOREk8y068_XskEfUqXHt-ox-56LE5pmdexZj7-NB"
			"NY6-OaJgeKhXx5AWZy-aphDBSDlo---mt08dxlr6DPP2D1iKPkK6lBPujLx836lz6XGuNo"
			"Dgr_y-vZ90Xjh_xTeUs3O_NGjKE30vb3qPq85PvyPC5ekEHw7ABUPk\",\"dq\":\"RipU"
			"KefkA9967O1JtYPI2G3DvDs2OxqvQXhZWz6rnD_yMBZAM5HLleXHk_9v9TjHPqy5eTMWhM"
			"WoZqB2Ssc66eCPslSfmnlvYpIiSGBOODLq5ghLScnX2q5eORyQOg2k300jVlNktKl-pjlM"
			"HwXcmKAsjuctSi_bVqd_Zt3Scgk\",\"qi\":\"JWvEuWge1CB6lrFsBHtco3pfC-xUOBt"
			"QArH7H3bGH5I_bEwxqvtnau3WH89DOXDoZsKBIuuoIl_rW9640pRpp9UOoLrE7jGqevDjm"
			"cq2ZwKMIGp9XeAs2zMm08-sQmFp6NAfhjFhBhvH2ITqrLs49cHNvtLg8WVpiDJRnHEgKSQ\"}",
		.pem = "-----BEGIN PUBLIC KEY-----\n" \
			"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgX6/IfGjjHZozSzXlGPT\n" \
			"woEE6v/zTyDGB/Xc1P6aAZUHFe1gV8pD/6c6+i6HeWR79zbtL6QGH6OCQdnn/pkV\n" \
			"h7zmxS4yMfsz6NmqLS5NftG+Uw1tRhxMG+nypPRyPd6IO4ozeujAt25/htnfOdMl\n" \
			"Qp+uAJc5Lu7pM/8qr+g9O+Q1ih+FBhGp8xbyEvDw4VRtr1OyZsHDPV9f35QXynyP\n" \
			"qO+oeCEqqDoWEnwSgbDRek93m3gnsYjvti/3VsaH1YtjfU6K+ZXhbCxNxhhOo8Zr\n" \
			"+ZxEVIs/Ck6dXttuCPA5enf0fREsw4fP/gY2RR5b6Lv7EmdR2MjOB9Pg87RUYaQ6\n" \
			"sQIDAQAB\n" \
			"-----END PUBLIC KEY-----\n", },
#ifdef HAVE_X25519
		{ .json_in = "{\"kty\":\"OKP\","
			  "\"crv\":\"Ed25519\","
			  "\"x\":\"xq1Sh-6NVxbYbfZFKMkMUnH10oNzTml2urMMm7vTOpQ\","
			  "\"use\":\"sig\","
			  "\"kid\":\"123\","
			  "\"d\":\"8oIOduAeYeMtuM1Vd0Iu4Hd9ymFyTfOqpRtsFDWmlOU\"}",
		.json_out = "{\"kty\":\"OKP\","
			  "\"crv\":\"Ed25519\","
			  "\"x\":\"xq1Sh-6NVxbYbfZFKMkMUnH10oNzTml2urMMm7vTOpQ\","
			  "\"use\":\"sig\","
			  "\"kid\":\"123\","
			  "\"d\":\"8oIOduAeYeMtuM1Vd0Iu4Hd9ymFyTfOqpRtsFDWmlOU\"}",
		  .pem = "-----BEGIN PUBLIC KEY-----\n"
			 "MCowBQYDK2VwAyEAxq1Sh+6NVxbYbfZFKMkMUnH10oNzTml2urMMm7vTOpQ=\n"
			 "-----END PUBLIC KEY-----\n" },
#endif
	};

	test_begin("test_jwk_keys");

	for (size_t i = 0; i < N_ELEMENTS(cases); i++)
		test_jwk_key(cases[i].json_in, cases[i].json_out, cases[i].pem);

	test_end();
}

static void test_static_verify_rsa(void)
{
	const char *error = NULL;
	bool valid;
	struct dcrypt_public_key *pub_key = NULL;

	test_begin("static verify (rsa)");
	const char *data = "test signature input\n";
	const unsigned char sig[] = {
		0x6f,0x1b,0xfb,0xdd,0xdb,0xb1,0xcd,0x6f,0xf1,0x1b,
		0xb8,0xad,0x71,0x75,0x6c,0x87,0x22,0x11,0xe4,0xc3,
		0xe7,0xca,0x15,0x04,0xda,0x98,0xab,0x07,0x27,0xcc,
		0x5a,0x4d,0xab,0xac,0x37,0x7a,0xff,0xd2,0xdf,0x37,
		0x58,0x37,0x53,0x46,0xd5,0x6d,0x9d,0x73,0x83,0x90,
		0xea,0x5e,0x2c,0xc7,0x51,0x9e,0xc4,0xda,0xc5,0x7d,
		0xa5,0xcd,0xb7,0xd7,0x41,0x23,0x6d,0xb9,0x6d,0xe0,
		0x99,0xa1,0x63,0x6b,0x60,0x5f,0x15,0x5b,0xda,0x21,
		0x17,0x4c,0x37,0x68,0x67,0x7f,0x8e,0x02,0x93,0xd2,
		0x86,0xdd,0xe5,0xa7,0xc3,0xd9,0x93,0x8b,0x0c,0x56,
		0x1d,0x5c,0x60,0x63,0x3e,0x8b,0xbe,0x1f,0xb2,0xe7,
		0x7f,0xe5,0x66,0x6f,0xcd,0x2b,0x0c,0x02,0x2a,0x12,
		0x96,0x86,0x66,0x00,0xff,0x12,0x8a,0x79
	};
	const char *key =
"-----BEGIN PUBLIC KEY-----\n"
"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC89q02I9NezBLQ+otn5XLYE7S+\n"
"GsKUz59ogr45DA/6MI9jey0W56SeWQ1FJD1vDhAx/TRBMfOmhcIPsBjc5sakYOaw\n"
"PdoiqLjOIlO+iHwnbbmLuMsque09vgvZsKjuTr2F5DOFQY43Bq/Nd+4bjHJItdOM\n"
"58+xwA2I/8vDbtI8jwIDAQAB\n"
"-----END PUBLIC KEY-----";

	test_assert(dcrypt_key_load_public(&pub_key, key, &error));
	if (pub_key == NULL)
		i_fatal("%s", error);
	test_assert(dcrypt_verify(pub_key, "sha256", DCRYPT_SIGNATURE_FORMAT_DSS,
		data, strlen(data),
		sig, sizeof(sig), &valid, DCRYPT_PADDING_RSA_PKCS1, &error) &&
		valid);
	dcrypt_key_unref_public(&pub_key);

	test_end();
}

/* Sample values from RFC8292 */
static void test_static_verify_ecdsa_x962(void)
{
	const char *error = NULL;
	bool valid;
	struct dcrypt_public_key *pub_key = NULL;

	test_begin("static verify (ecdsa x9.62)");
	const char *data =
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c"
		"2guZXhhbXBsZS5uZXQiLCJleHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzp"
		"wdXNoQGV4YW1wbGUuY29tIn0";
	const unsigned char sig[] = {
		0x8b,0x70,0x98,0x6f,0xbb,0x78,0xc5,0xfc,0x42,0x0e,0xab,
		0xa9,0xb4,0x53,0x9e,0xa4,0x2f,0x46,0x02,0xef,0xc7,0x2c,
		0x69,0x0c,0x94,0xcb,0x82,0x19,0x22,0xb6,0xae,0x98,0x94,
		0x7e,0x72,0xbd,0xa2,0x31,0x70,0x0d,0x76,0xf5,0x26,0xb1,
		0x2b,0xb6,0x6c,0xac,0x6b,0x33,0x63,0x8e,0xf5,0xb6,0x2f,
		0xd3,0xa4,0x49,0x21,0xf3,0xbe,0x80,0xf5,0xa0
	};
	const char *key =
"-----BEGIN PUBLIC KEY-----\n"
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDUfHPKLVFQzVvnCPGyfucbECzPDa\n"
"7rWbXriLcysAjEcXpgrmHhINiJz51G5T9EI8J8Dlqr2iNLCTljYSYKUE+w==\n"
"-----END PUBLIC KEY-----";

	test_assert(dcrypt_key_load_public(&pub_key, key, &error));
	if (pub_key == NULL)
		i_fatal("%s", error);
	test_assert(dcrypt_verify(pub_key, "sha256", DCRYPT_SIGNATURE_FORMAT_X962,
		data, strlen(data),
		sig, sizeof(sig), &valid, DCRYPT_PADDING_RSA_PKCS1, &error) &&
		valid);
	dcrypt_key_unref_public(&pub_key);

	test_end();
}

#ifdef HAVE_X25519
static void test_sign_verify_ed25519(void)
{
	const char *error = NULL;
	bool valid, ret;
	struct dcrypt_keypair pair;
	buffer_t *signature =
		buffer_create_dynamic(pool_datastack_create(), 128);
	const char *data = "signed data";

	test_begin("sign and verify (ed25519)");

	ret = dcrypt_keypair_generate(&pair, DCRYPT_KEY_EC, 0, "ED25519", &error);
	if (!ret)
		i_panic("%s", error);

	test_assert(dcrypt_sign(pair.priv, "sha256", DCRYPT_SIGNATURE_FORMAT_DSS,
		 data, strlen(data), signature, 0, &error));
	/* verify signature */
	test_assert(dcrypt_verify(pair.pub, "sha256", DCRYPT_SIGNATURE_FORMAT_DSS,
		 data, strlen(data),
		 signature->data, signature->used, &valid, 0, &error) && valid);

	dcrypt_keypair_unref(&pair);

	test_end();
}

static void test_static_verify_ed25519(void)
{
	const char *error = NULL;
	bool valid, ret;
	struct dcrypt_public_key *pub;
	const char *data = "signed data";
	const unsigned char sig[] = {
		0xf6,0xc5,0xf9,0x6e,0x6c,0x42,0x6d,0xa8,0xbc,0x9f,0xc8,0xbe,
		0x87,0x17,0x38,0x40,0xd9,0x5b,0x4b,0xee,0xba,0x64,0x1a,0xba,
		0xb2,0xac,0x94,0x8c,0x25,0xd5,0x2b,0x1f,0x98,0x73,0x98,0x40,
		0x85,0x33,0xfa,0xb9,0x40,0xd6,0x75,0x61,0x29,0xaa,0xcb,0xf7,
		0x69,0xa4,0x93,0x21,0xa2,0x64,0x9b,0xc2,0xcd,0x62,0x95,0x42,
		0xea,0x93,0x6f,0x07,
	};
	const char *key =
"-----BEGIN PUBLIC KEY-----\n"
"MCowBQYDK2VwAyEAPfeu6ItbVmVPUV/nYYHvV/aVheD7iVUWO9/POgcCyYM=\n"
"-----END PUBLIC KEY-----";
	test_begin("static verify (ed25519)");

	ret = dcrypt_key_load_public(&pub, key, &error);
	if (!ret)
		i_panic("%s", error);

	/* verify signature */
	test_assert(dcrypt_verify(pub, "sha256", DCRYPT_SIGNATURE_FORMAT_DSS,
		 data, strlen(data),
		 sig, sizeof(sig), &valid, 0, &error) && valid);
	dcrypt_key_unref_public(&pub);

	test_end();
}

static void test_static_verify_ed448(void)
{
	const char *error = NULL;
	bool valid, ret;
	struct dcrypt_public_key *pub;
	const char *data = "signed data";
	const unsigned char sig[] = {
		0x9d,0x90,0x9b,0xe9,0x40,0xf5,0xee,0x4e,0x42,0x34,0xa5,0x90,
		0x85,0x0d,0x6a,0xea,0x60,0xae,0xd2,0x49,0x39,0x5f,0x61,0x64,
		0x16,0x22,0x36,0xa4,0x14,0x8b,0x61,0x4e,0x4e,0xfa,0x74,0x45,
		0xcb,0xf8,0x8b,0x15,0xc1,0x59,0x99,0xaa,0x26,0x20,0x45,0x32,
		0x8a,0xa0,0xed,0x21,0xce,0x39,0xa4,0x06,0x00,0x75,0xb1,0x70,
		0x6e,0xe6,0xb6,0x89,0x94,0x72,0xcb,0x3a,0xe8,0x1d,0xaf,0x18,
		0x01,0xde,0x58,0xbe,0x1f,0x72,0x5b,0x0c,0xc4,0x98,0xfb,0xba,
		0x51,0x26,0x89,0x01,0xc3,0xea,0xa7,0xe6,0xb2,0xf6,0xe5,0xee,
		0xa2,0x5a,0x72,0x84,0xc4,0xfc,0x81,0x1f,0x48,0x45,0x9f,0xd1,
		0x44,0x1f,0x77,0x5c,0x3b,0x00,
	};
	const char *key =
"-----BEGIN PUBLIC KEY-----\n"
"MEMwBQYDK2VxAzoAnWMyXj/1VTCDWIyx0IKbezYsUI0dl80fAkQ3IK+U5+SqR2gw\n"
"zhHZ7ewPFgiEiP/KY3qKLWJHSDcA\n"
"-----END PUBLIC KEY-----";
	test_begin("static verify (ed448)");

	ret = dcrypt_key_load_public(&pub, key, &error);
	if (!ret)
		i_panic("%s", error);

	/* verify signature */
	test_assert(dcrypt_verify(pub, "sha256", DCRYPT_SIGNATURE_FORMAT_DSS,
		 data, strlen(data),
		 sig, sizeof(sig), &valid, 0, &error) && valid);
	dcrypt_key_unref_public(&pub);

	test_end();
}

static void test_sign_verify_ed448(void)
{
	const char *error = NULL;
	bool valid, ret;
	struct dcrypt_keypair pair;
	buffer_t *signature =
		buffer_create_dynamic(pool_datastack_create(), 128);
	const char *data = "signed data";

	test_begin("sign and verify (ed448)");

	ret = dcrypt_keypair_generate(&pair, DCRYPT_KEY_EC, 0, "ED448", &error);
	if (!ret)
		i_panic("%s", error);

	test_assert(dcrypt_sign(pair.priv, "sha256", DCRYPT_SIGNATURE_FORMAT_DSS,
		 data, strlen(data), signature, 0, &error));
	/* verify signature */
	test_assert(dcrypt_verify(pair.pub, "sha256", DCRYPT_SIGNATURE_FORMAT_DSS,
		 data, strlen(data),
		 signature->data, signature->used, &valid, 0, &error) && valid);

	dcrypt_keypair_unref(&pair);

	test_end();
}

static void test_xd_keypair(struct dcrypt_keypair *pair)
{
	const char *error = NULL;
	bool ret;

	/* perform ecdh */
	buffer_t *R = t_buffer_create(64), *S = t_buffer_create(64);
	buffer_t *S2 = t_buffer_create(64);
	test_assert(dcrypt_ecdh_derive_secret_peer(pair->pub, R, S, &error));
	test_assert(dcrypt_ecdh_derive_secret_local(pair->priv, R, S2, &error));
	test_assert(S->used > 0);
	test_assert(R->used > 0);
	test_assert(buffer_cmp(S, S2));

	/* try to store it as dovecot key */
	string_t *pub = t_str_new(64);
	string_t *priv = t_str_new(64);

	ret = dcrypt_key_store_public(pair->pub, DCRYPT_FORMAT_DOVECOT, pub, &error);
	test_assert(ret == TRUE);
	ret = dcrypt_key_store_private(pair->priv, DCRYPT_FORMAT_DOVECOT, NULL, priv, NULL, NULL, &error);
	test_assert(ret == TRUE);

	struct dcrypt_keypair pair2;

	ret = dcrypt_key_load_public(&pair2.pub, str_c(pub), &error);
	test_assert(ret == TRUE);

	ret = dcrypt_key_load_private(&pair2.priv, str_c(priv), NULL, NULL, &error);
	test_assert(ret == TRUE);

	struct dcrypt_public_key *pub2;
	dcrypt_key_convert_private_to_public(pair2.priv, &pub2);

	str_truncate(pub, 0);
	ret = dcrypt_key_store_public(pub2, DCRYPT_FORMAT_DOVECOT, pub, &error);
	test_assert(ret == TRUE);

	dcrypt_key_unref_public(&pub2);
	dcrypt_keypair_unref(pair);
	dcrypt_keypair_unref(&pair2);
}

static void test_xd25519_keypair(void)
{
	test_begin("X25519 key exchange");
	struct dcrypt_keypair pair;
	const char *error = NULL;

	if (!dcrypt_keypair_generate(&pair, DCRYPT_KEY_EC, 0, "X25519", &error))
		i_panic("%s", error);

	test_xd_keypair(&pair);

	test_end();
}

static void test_xd448_keypair(void)
{
	test_begin("X448 key exchange");
	struct dcrypt_keypair pair;
	const char *error = NULL;

	if (!dcrypt_keypair_generate(&pair, DCRYPT_KEY_EC, 0, "X448", &error))
		i_panic("%s", error);

	test_xd_keypair(&pair);

	test_end();
}
#endif

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

	static void (*const test_functions[])(void) = {
		test_cipher_test_vectors,
		test_cipher_aead_test_vectors,
		test_hmac_test_vectors,
		test_load_v1_keys,
		test_load_v1_key,
		test_load_v1_public_key,
		test_load_v2_key,
		test_load_v2_public_key,
		test_get_info_v2_key,
		test_gen_and_get_info_rsa_pem,
		test_get_info_rsa_private_key,
		test_get_info_invalid_keys,
		test_get_info_key_encrypted,
		test_get_info_pw_encrypted,
		test_password_change,
		test_load_invalid_keys,
		test_raw_keys,
		test_jwk_keys,
		test_sign_verify_rsa,
		test_sign_verify_ecdsa,
		test_sign_verify_x962,
		test_static_verify_ecdsa,
		test_static_verify_rsa,
		test_static_verify_ecdsa_x962,
#ifdef HAVE_X25519
		test_sign_verify_ed25519,
		test_sign_verify_ed448,
		test_static_verify_ed25519,
		test_static_verify_ed448,
		test_xd25519_keypair,
		test_xd448_keypair,
#endif
		NULL
	};

	int ret = test_run(test_functions);

	dcrypt_deinitialize();

	return ret;
}
