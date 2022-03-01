/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "env-util.h"

void test_env_util(void)
{
	test_begin("env util");

	env_put("ENVUTIL_BACKUP", "saved");
	struct env_backup *backup = env_backup_save();

	/* test env_clean() */
	env_clean();
	char ***env = env_get_environ_p();
	test_assert(*env == NULL || **env == NULL);
	test_assert(getenv("ENVUTIL_BACKUP") == NULL);

	/* test env_put_array() */
	const char *add_env[] = { "a=1", "b=1", "c=1", "d=1", NULL };
	env_put_array(add_env);
	test_assert_strcmp(getenv("a"), "1");
	test_assert_strcmp(getenv("b"), "1");
	test_assert_strcmp(getenv("c"), "1");
	test_assert_strcmp(getenv("d"), "1");
	test_assert(getenv("e") == NULL);
	const char *add_env2[] = { "b=", "e=2", NULL };
	env_put_array(add_env2);
	test_assert_strcmp(getenv("a"), "1");
	test_assert_strcmp(getenv("b"), "");
	test_assert_strcmp(getenv("c"), "1");
	test_assert_strcmp(getenv("d"), "1");
	test_assert_strcmp(getenv("e"), "2");

	/* test env_clean_except() */
	const char *preserve_env[] = { "a", "c", NULL };
	env_clean_except(preserve_env);
	test_assert_strcmp(getenv("a"), "1");
	test_assert(getenv("b") == NULL);
	test_assert_strcmp(getenv("c"), "1");
	test_assert(getenv("d") == NULL);
	test_assert(*env != NULL &&
		    (null_strcmp((*env)[0], "a=1") == 0 ||
		     null_strcmp((*env)[0], "c=1") == 0));
	test_assert(*env != NULL &&
		    (null_strcmp((*env)[1], "a=1") == 0 ||
		     null_strcmp((*env)[1], "c=1") == 0));

	/* test env_remove() */
	env_remove("a");
	test_assert(getenv("a") == NULL);
	test_assert(getenv("c") != NULL);
	env_remove("a");
	test_assert(getenv("a") == NULL);
	test_assert(getenv("c") != NULL);
	env_remove("c");
	test_assert(getenv("c") == NULL);
	test_assert(*env == NULL || **env == NULL);

	/* test restoring */
	env_backup_restore(backup);
	test_assert_strcmp(getenv("ENVUTIL_BACKUP"), "saved");
	env_put("ENVUTIL_BACKUP", "overwrite");
	test_assert_strcmp(getenv("ENVUTIL_BACKUP"), "overwrite");

	/* test restoring again */
	env_backup_restore(backup);
	test_assert_strcmp(getenv("ENVUTIL_BACKUP"), "saved");
	env_backup_free(&backup);

	test_end();
}

enum fatal_test_state fatal_env_util(unsigned int stage)
{
	switch (stage) {
	case 0:
		test_begin("env util fatals");

		test_expect_fatal_string("strchr(name, '=') == NULL");
		env_put("key=bad", "value");
		return FATAL_TEST_FAILURE;
	case 1:
		test_expect_fatal_string("value != NULL");
		const char *const envs[] = { "key", NULL };
		env_put_array(envs);
		return FATAL_TEST_FAILURE;
	default:
		test_end();
		return FATAL_TEST_FINISHED;
	}
}
