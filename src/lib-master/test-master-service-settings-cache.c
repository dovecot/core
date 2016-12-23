/* Copyright (c) 2014-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "settings-parser.h"
#include "master-service-private.h"
#include "master-service-settings.h"
#include "master-service-settings-cache.h"


struct master_service *master_service;

static struct master_service test_master_service;
static struct master_service_settings set;
static struct master_service_settings_input input;
static struct master_service_settings_output output;
static struct master_service_settings_cache *cache;

struct test_service_settings {
	const char *foo;
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct test_service_settings, name), NULL }

static const struct setting_define test_setting_defines[] = {
	DEF(SET_STR, foo),
	SETTING_DEFINE_LIST_END
};

static const struct test_service_settings test_default_settings = {
	.foo = ""
};

static const struct setting_parser_info test_setting_parser_info = {
	.module_name = "module",
	.defines = test_setting_defines,
	.defaults = &test_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct test_service_settings),

	.parent_offset = (size_t)-1
};

int master_service_settings_read(struct master_service *service ATTR_UNUSED,
				 const struct master_service_settings_input *input ATTR_UNUSED,
				 struct master_service_settings_output *output_r,
				 const char **error_r ATTR_UNUSED)
{
	*output_r = output;
	return 0;
}

const struct master_service_settings *
master_service_settings_get(struct master_service *service ATTR_UNUSED)
{
	return &set;
}

static void test_master_service_settings_cache_once(void)
{
	const struct setting_parser_context *parser;
	const char *error;

	output.used_local = output.service_uses_local && (rand() % 2) != 0;
	if (output.used_local) {
		input.local_ip.family = AF_INET;
		input.local_ip.u.ip4.s_addr = 100 + rand() % 100;
	}
	output.used_remote = output.service_uses_remote && (rand() % 2) != 0;
	if (output.used_remote) {
		input.remote_ip.family = AF_INET;
		input.remote_ip.u.ip4.s_addr = 100 + rand() % 100;
	}
	test_assert(master_service_settings_cache_read(cache, &input, NULL, &parser, &error) == 0);
}

static void test_master_service_settings_cache(void)
{
	int i, j;

	for (i = 1; i < 4; i++) {
		cache = master_service_settings_cache_init(master_service,
							   "module", "service_name");
		output.service_uses_local = (i & 1) != 0;
		output.service_uses_remote = (i & 2) != 0;
		for (j = 0; j < 1000; j++)
			test_master_service_settings_cache_once();
		master_service_settings_cache_deinit(&cache);
	}
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_master_service_settings_cache,
		NULL
	};
	pool_t pool;
	int ret;

	memset(&input, 0, sizeof(input));
	input.module = "module";
	input.service = "service_name";

	set.config_cache_size = 1024*4;
	pool = pool_alloconly_create("set pool", 1024);
	test_master_service.set_parser =
		settings_parser_init(pool, &test_setting_parser_info, 0);
	master_service = &test_master_service;
	ret = test_run(test_functions);
	settings_parser_deinit(&test_master_service.set_parser);
	pool_unref(&pool);
	return ret;
}
