#include "lib.h"
#include "test-common.h"
#include "str.h"
#include "var-expand.h"
#include "randgen.h"
#include "dcrypt.h"

struct module;

extern void var_expand_crypt_init(struct module *module);
extern void var_expand_crypt_deinit(void);

static void test_var_expand_crypt(void)
{
	struct var_expand_table table[] = {
		{ '\0', "98b3b40a48ca40f998b3b40a48ca40f9", "iv" },
		{ '\0', "cc2981c8f38aea59cc2981c8f38aea59", "key" },
		{ '\0', "46b58741763fe22598014be26331a082", "encrypted_noiv" },
		{ '\0', "98b3b40a48ca40f998b3b40a48ca40f9$46b58741763fe22598014be26331a082$", "encrypted" },
		{ '\0', "hello, world", "decrypted" },
		{ '\0', NULL, "encrypted2" },
		{ '\0', NULL, NULL }
	};

	static struct {
		const char *input;
		const char *output;
		int expect_ret;
	} test_cases[] = {
		{ "%{encrypt;algo=null:decrypted}", "", -1 },
		{ "%{encrypt;algo=aes-128-cbc,iv=98b3b40a48ca40f998b3b40a48ca40f9,key=cc2981c8f38aea59cc2981c8f38aea59:decrypted}", "98b3b40a48ca40f998b3b40a48ca40f9$46b58741763fe22598014be26331a082$", 1 },
		{ "%{encrypt;noiv=yes,algo=aes-128-cbc,iv=98b3b40a48ca40f998b3b40a48ca40f9,key=cc2981c8f38aea59cc2981c8f38aea59:decrypted}", "46b58741763fe22598014be26331a082", 1 },
		{ "%{encrypt;algo=aes-128-cbc,iv=%{iv},key=%{key}:decrypted}", "98b3b40a48ca40f998b3b40a48ca40f9$46b58741763fe22598014be26331a082$", 1 },
		{ "%{decrypt;algo=null:encrypted}", "", -1 },
		{ "%{decrypt;algo=aes-128-cbc,key=%{key}:encrypted}", "hello, world", 1 },
		{ "%{decrypt;algo=aes-128-cbc,iv=%{iv},key=%{key}:encrypted_noiv}", "hello, world", 1 },
		{ "%{decrypt;algo=aes-128-cbc,iv=98b3b40a48ca40f998b3b40a48ca40f9,key=cc2981c8f38aea59cc2981c8f38aea59:encrypted_noiv}", "hello, world", 1 },
	};

	unsigned int i;

	test_begin("var_expand_crypt");
	var_expand_crypt_init(NULL);
	random_init();

	for(i=0; i < N_ELEMENTS(test_cases); i++) T_BEGIN {
		const char *error;
		string_t *dest = t_str_new(32);
		int ret = var_expand(dest, test_cases[i].input, table, &error);
		if (ret < 0) {
			if (test_cases[i].expect_ret == -1)
				i_info("Expected: var_expand(%s): %s", test_cases[i].input, error);
			else
				i_error("var_expand(%s): %s", test_cases[i].input, error);
		}
		test_assert_idx(strcmp(str_c(dest), test_cases[i].output)==0, i);
		test_assert_idx(ret == test_cases[i].expect_ret, i);
	} T_END;

	test_end();

	test_begin("var_expand_crypt_random");

	string_t *input = t_str_new(32);
	string_t *output = t_str_new(32);

	for(i=0;i<1000;i++) {
		const char *error;
		str_truncate(input, 0);
		str_truncate(output, 0);

		test_assert_idx(var_expand(input, "%{encrypt;algo=aes-128-cbc,key=%{key}:decrypted}", table, &error) == 1, i);
		table[5].value = str_c(input);
		test_assert_idx(var_expand(output, "%{decrypt;algo=aes-128-cbc,key=%{key}:encrypted2}", table, &error) == 1, i);
		test_assert_idx(strcmp(str_c(output), table[4].value)==0, i);
	};

	random_deinit();
	var_expand_crypt_deinit();
	test_end();
}

int main(void)
{
	int ret = 0;
	static void (*const test_functions[])(void) = {
		test_var_expand_crypt,
		NULL
	};
	struct dcrypt_settings set = {
		.module_dir = DCRYPT_BUILD_DIR"/.libs"
	};

	if (!dcrypt_initialize(NULL, &set, NULL))
		return 0;

	ret = test_run(test_functions);

	dcrypt_deinitialize();

	return ret;
}
