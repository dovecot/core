/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "randgen.h"
#include "array.h"
#include "dcrypt.h"
#include "hex-binary.h"

#include "mail-crypt-common.h"
#include "mail-crypt-key.h"
#include "fs-crypt-settings.h"

#include "mail-crypt-pluginenv.c"

static struct fs_crypt_settings fs_set;

static const char *settings[] = {
	"mail_crypt_global_private_key",
	"LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ1lJdWZKWlplMlk2aUZ6NXgKa29Jb3lzYjNkWkxaV3N5ZWtqT2MvR2pzTGQyaFJBTkNBQVNuSVdnUXVoRThqcUFMY21maXVuUnlFazd2a3EveQphOXZZSzUwYjNjRmhDc0xVNHRmVlRMa0IxWS82VmxaajYzUUtNelhOdms1RzVPRDFvZkVsY3B5agotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==",
	"mail_crypt_global_public_key",
	"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFcHlGb0VMb1JQSTZnQzNKbjRycDBjaEpPNzVLdgo4bXZiMkN1ZEc5M0JZUXJDMU9MWDFVeTVBZFdQK2xaV1krdDBDak0xemI1T1J1VGc5YUh4SlhLY293PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
	"mail_crypt_global_private_key2",
	"LS0tLS1CRUdJTiBFTkNSWVBURUQgUFJJVkFURSBLRVktLS0tLQpNSUhlTUVrR0NTcUdTSWIzRFFFRkRUQThNQnNHQ1NxR1NJYjNEUUVGRERBT0JBaXA2cUpja1FET3F3SUNDQUF3CkhRWUpZSVpJQVdVREJBRXFCQkFXN09oUFRlU0xSOExLcGYwZjZHa3ZCSUdRZk5rYUpodnM2VWVWS2RkN2NzdFMKMURSNXJYTWtON09FbVNjTTljRlk2UDVrMzdnY1VJUFZudTQrOTFYZUE1MTU2cnBpUEpycEdkZnprcjhPNVFqZApsMWRycmR6Z0hqZHE4T2VmbUR1MEEzMjRZd25SS3hGRExUcjlHMkxVMkhoYmV6a0xjV1FwMVJISDZsNXRRcUtwCjZid05iMnc3OXhCb01YSjN6MVZqcElOZk9wRnJ6M3lucVlqUXhseTIrQjg2Ci0tLS0tRU5EIEVOQ1JZUFRFRCBQUklWQVRFIEtFWS0tLS0tCg==",
	"mail_crypt_global_private_key2_password",
	"password",
};

int
mail_crypt_load_global_private_keys(const struct fs_crypt_settings *set,
				    const char *set_prefix,
				    struct mail_crypt_global_keys *global_keys,
				    const char **error_r);

static void test_setup(void)
{
	struct dcrypt_settings set = {
		.module_dir = top_builddir "/src/lib-dcrypt/.libs"
	};
	if (!dcrypt_initialize(NULL, &set, NULL)) {
		i_info("No functional dcrypt backend found - skipping tests");
		test_exit(0);
	}
	i_array_init(&fs_set.plugin_envs, 8);
	array_append(&fs_set.plugin_envs, settings, N_ELEMENTS(settings));
}

static void test_try_load_keys(void)
{
	const char *pubid1 = "c79e262924842de291a8bcd413f4122a570abd033adeff7c1cdfdc9d05998c75";
	const char *pubid2 = "aaf927444bff8b63425e852c6b3f769e8221b952b42cf886fae7d326c5be098e";
	buffer_t *key_id = t_buffer_create(128);

	const char *error = NULL;
	test_begin("try_load_keys");

	struct mail_crypt_global_keys keys;
	i_zero(&keys);
	mail_crypt_global_keys_init(&keys);

	const char *set_prefix = "mail_crypt_global";
	const char *set_key = t_strconcat(set_prefix, "_public_key", NULL);
	const char *key_data = mail_crypt_plugin_getenv(&fs_set, set_key);

	test_assert(key_data != NULL);

	if (key_data != NULL) {
		test_assert(mail_crypt_load_global_public_key(set_key, key_data,
							      &keys, &error) == 0);
		test_assert(mail_crypt_load_global_private_keys(&fs_set, set_prefix,
								&keys, &error) == 0);
		/* did we get two private keys? */
		test_assert(array_count(&keys.private_keys) == 2);

		/* public key id checks */

		buffer_set_used_size(key_id, 0);
		test_assert(dcrypt_key_id_public(keys.public_key, MAIL_CRYPT_KEY_ID_ALGORITHM, key_id, &error) == TRUE);
		test_assert(strcmp(binary_to_hex(key_id->data, key_id->used), pubid1) == 0);

		const struct mail_crypt_global_private_key *key =
			array_front(&keys.private_keys);

		buffer_set_used_size(key_id, 0);
		test_assert(dcrypt_key_id_private(key->key, MAIL_CRYPT_KEY_ID_ALGORITHM, key_id, &error) == TRUE);
		test_assert(strcmp(binary_to_hex(key_id->data, key_id->used), pubid1) == 0);

		key = array_idx(&keys.private_keys, 1);
		buffer_set_used_size(key_id, 0);
		test_assert(dcrypt_key_id_private(key->key, MAIL_CRYPT_KEY_ID_ALGORITHM, key_id, &error) == TRUE);
		test_assert(strcmp(binary_to_hex(key_id->data, key_id->used), pubid2) == 0);

	}

	mail_crypt_global_keys_free(&keys);

	test_end();
}

static void test_empty_keyset(void)
{
	test_begin("test_empty_keyset");

	/* this should not crash */
	struct mail_crypt_global_keys keys;
	i_zero(&keys);
	test_assert(mail_crypt_global_key_find(&keys, "423423423423") == NULL);

	test_end();
}

static void test_teardown(void)
{
	array_free(&fs_set.plugin_envs);
	dcrypt_deinitialize();
}

int main(void)
{
	void (*tests[])(void)  = {
		test_setup,
		test_try_load_keys,
		test_empty_keyset,
		test_teardown,
		NULL
	};

	int ret = test_run(tests);
	return ret;
}
