/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "hex-binary.h"
#include "randgen.h"
#include "test-common.h"
#include "master-service.h"
#include "mail-storage-service.h"
#include "mail-storage-private.h"

static void test_init_storage(struct mail_storage *storage_r)
{
	i_zero(storage_r);
	storage_r->user = t_new(struct mail_user, 1);
	storage_r->user->event = event_create(NULL);
	storage_r->event = event_create(storage_r->user->event);
}

static void test_deinit_storage(struct mail_storage *storage)
{
	mail_storage_clear_error(storage);
	if (array_is_created(&storage->error_stack)) {
		mail_storage_clear_error(storage);
		i_assert(array_count(&storage->error_stack) == 0);
		array_free(&storage->error_stack);
	}
	event_unref(&storage->event);
	event_unref(&storage->user->event);
}

struct test_mail_storage_ctx {
	pool_t pool;
	struct mail_storage_service_ctx *storage_service;
	struct mail_user *user;
	struct mail_storage_service_user *service_user;
	struct ioloop *ioloop;
	const char *mail_home;
};

static void test_mail_storage_errors(void)
{
	struct mail_storage storage;
	enum mail_error mail_error;
	const char *errstr;

	test_begin("mail storage errors");
	test_init_storage(&storage);

	/* try a regular error */
	mail_storage_set_error(&storage, MAIL_ERROR_PERM, "error1");
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error), "error1") == 0);
	test_assert(mail_error == MAIL_ERROR_PERM);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "error1") == 0);
	test_assert(mail_error == MAIL_ERROR_PERM);
	test_assert(!storage.last_error_is_internal);

	/* set the error to itself */
	mail_storage_set_error(&storage, MAIL_ERROR_PARAMS,
		mail_storage_get_last_error(&storage, &mail_error));
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error), "error1") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "error1") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(!storage.last_error_is_internal);

	/* clear the error - asking for it afterwards is a bug */
	mail_storage_clear_error(&storage);
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error), "BUG: Unknown internal error") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "BUG: Unknown internal error") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(!storage.last_error_is_internal);

	/* set internal error in preparation for the next test */
	test_expect_error_string("critical0");
	mail_storage_set_critical(&storage, "critical0");
	test_expect_no_more_errors();
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error), MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "critical0") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* internal error without specifying what it is. this needs to clear
	   the previous internal error. */
	mail_storage_set_internal_error(&storage);
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error), MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strstr(mail_storage_get_last_internal_error(&storage, &mail_error), MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(!storage.last_error_is_internal);

	/* proper internal error */
	test_expect_error_string("critical1");
	mail_storage_set_critical(&storage, "critical1");
	test_expect_no_more_errors();
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error), MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "critical1") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* use it in the following internal error */
	test_expect_error_string("critical2: critical1");
	mail_storage_set_critical(&storage, "critical2: %s",
		mail_storage_get_last_internal_error(&storage, &mail_error));
	test_expect_no_more_errors();
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error), MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "critical2: critical1") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* use the previous non-internal error as part of the internal error */
	test_expect_error_string("critical3: "MAIL_ERRSTR_CRITICAL_MSG);
	mail_storage_set_critical(&storage, "critical3: %s",
		mail_storage_get_last_error(&storage, &mail_error));
	test_expect_no_more_errors();
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error), MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	errstr = mail_storage_get_last_internal_error(&storage, &mail_error);
	test_assert(str_begins(errstr, "critical3: "));
	test_assert(strstr(errstr+11, MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* clear the error again and check that all is as expected */
	mail_storage_clear_error(&storage);
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error), "BUG: Unknown internal error") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "BUG: Unknown internal error") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(!storage.last_error_is_internal);

	/* use internal error as a regular error (although that really
	   shouldn't be done) */
	test_expect_error_string("critical4");
	mail_storage_set_critical(&storage, "critical4");
	mail_storage_set_error(&storage, MAIL_ERROR_PARAMS,
		mail_storage_get_last_internal_error(&storage, &mail_error));
	test_expect_no_more_errors();
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error), "critical4") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "critical4") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(!storage.last_error_is_internal);

	test_deinit_storage(&storage);
	test_end();
}

static void test_mail_storage_last_error_push_pop(void)
{
	struct mail_storage storage;
	enum mail_error mail_error;

	test_begin("mail_storage_last_error_push/pop()");
	test_init_storage(&storage);

	/* regular error 1 */
	mail_storage_set_error(&storage, MAIL_ERROR_PERM, "regular error 1");
	mail_storage_last_error_push(&storage);

	/* critical error 1 */
	test_expect_error_string("critical error 1");
	mail_storage_set_critical(&storage, "critical error 1");
	test_expect_no_more_errors();
	mail_storage_last_error_push(&storage);

	/* regular error 2 */
	mail_storage_set_error(&storage, MAIL_ERROR_PARAMS, "regular error 2");
	mail_storage_last_error_push(&storage);

	/* critical error 2 */
	test_expect_error_string("critical error 2");
	mail_storage_set_critical(&storage, "critical error 2");
	test_expect_no_more_errors();
	mail_storage_last_error_push(&storage);

	/* -- clear all errors -- */
	mail_storage_clear_error(&storage);

	/* critical error 2 pop */
	mail_storage_last_error_pop(&storage);
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error), MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "critical error 2") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* regular error 2 pop */
	mail_storage_last_error_pop(&storage);
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error), "regular error 2") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "regular error 2") == 0);
	test_assert(mail_error == MAIL_ERROR_PARAMS);
	test_assert(!storage.last_error_is_internal);

	/* critical error 1 pop */
	mail_storage_last_error_pop(&storage);
	test_assert(strstr(mail_storage_get_last_error(&storage, &mail_error), MAIL_ERRSTR_CRITICAL_MSG) != NULL);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "critical error 1") == 0);
	test_assert(mail_error == MAIL_ERROR_TEMP);
	test_assert(storage.last_error_is_internal);

	/* regular error 1 pop */
	mail_storage_last_error_pop(&storage);
	test_assert(strcmp(mail_storage_get_last_error(&storage, &mail_error), "regular error 1") == 0);
	test_assert(mail_error == MAIL_ERROR_PERM);
	test_assert(strcmp(mail_storage_get_last_internal_error(&storage, &mail_error), "regular error 1") == 0);
	test_assert(mail_error == MAIL_ERROR_PERM);
	test_assert(!storage.last_error_is_internal);

	test_deinit_storage(&storage);
	test_end();
}

static void test_mail_init(struct test_mail_storage_ctx *ctx)
{
	const char *error;
	char path_buf[4096];
	unsigned char rand[4];

	ctx->pool = pool_allocfree_create("test pool");

	if (getcwd(path_buf, sizeof(path_buf)) == NULL)
		i_fatal("getcwd() failed: %m");

	random_fill(rand, sizeof(rand));
	ctx->mail_home = p_strdup_printf(ctx->pool, "%s/.test-dir%s/", path_buf,
					 binary_to_hex(rand, sizeof(rand)));

	if (unlink_directory(ctx->mail_home, UNLINK_DIRECTORY_FLAG_RMDIR, &error) < 0 &&
	    errno != ENOENT)
		i_warning("unlink_directory(%s) failed: %s", ctx->mail_home, error);

	ctx->ioloop = io_loop_create();

	ctx->storage_service = mail_storage_service_init(master_service, NULL,
		MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS |
		MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT |
		MAIL_STORAGE_SERVICE_FLAG_NO_PLUGINS);
}

static void test_mail_deinit(struct test_mail_storage_ctx *ctx)
{
	const char *error;
	mail_storage_service_deinit(&ctx->storage_service);

	if (chdir(ctx->mail_home) < 0)
		i_fatal("chdir(%s) failed: %m", ctx->mail_home);
	if (chdir("..") < 0)
		i_fatal("chdir(..) failed: %m");

	if (unlink_directory(ctx->mail_home, UNLINK_DIRECTORY_FLAG_RMDIR,
			     &error) < 0)
		i_error("unlink_directory(%s) failed: %s", ctx->mail_home, error);

	io_loop_destroy(&ctx->ioloop);

	pool_unref(&ctx->pool);

	i_zero(ctx);
}

static int test_mail_init_user(const char *user, const char *driver,
			       const char *driver_opts, const char *sep,
			       const char *const *extra_input,
			       struct test_mail_storage_ctx *ctx)
{
	const char *error, *home;
	ARRAY_TYPE(const_string) opts;

	home = t_strdup_printf("%s%s", ctx->mail_home, user);

	const char *const default_input[] = {
		t_strdup_printf("mail=%s:~/%s", driver, driver_opts),
		"postmaster_address=postmaster@localhost",
		"namespace=inbox",
		"namespace/inbox/prefix=",
		"namespace/inbox/inbox=yes",
		t_strdup_printf("namespace/inbox/separator=%s", sep),
		t_strdup_printf("home=%s/%s", home, user),
	};

	i_assert(mkdir_parents(home, S_IRWXU)==0 || errno == EEXIST);

	t_array_init(&opts, 20);
	array_append(&opts, default_input, N_ELEMENTS(default_input));
	if (extra_input != NULL)
		while(*extra_input != NULL)
			array_append(&opts, extra_input++, 1);

	array_append_zero(&opts);
	struct mail_storage_service_input input = {
		.userdb_fields = array_idx(&opts, 0),
		.username = user,
		.no_userdb_lookup = TRUE,
		.debug = FALSE,
	};

	if (mail_storage_service_lookup_next(ctx->storage_service, &input,
					     &ctx->service_user, &ctx->user,
					     &error) < 0) {
		 i_error("mail_storage_service_lookup_next(%s) failed: %s",
			 user, error);
		 return -1;
	}

	return 0;
}

#define test_mail_init_maildir_user(user) test_mail_init_user(user,"maildir","",NULL)
static void test_mail_deinit_user(struct test_mail_storage_ctx *ctx)
{
	mail_user_unref(&ctx->user);
	mail_storage_service_user_unref(&ctx->service_user);
}

int main(int argc, char **argv)
{
	int ret;
	void (*const tests[])(void) = {
		test_mail_storage_errors,
		test_mail_storage_last_error_push_pop,
		NULL
	};

	master_service = master_service_init("test-mail-storage",
					     MASTER_SERVICE_FLAG_STANDALONE |
					     MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS |
					     MASTER_SERVICE_FLAG_NO_SSL_INIT |
					     MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME,
					     &argc, &argv, "");

	ret = test_run(tests);

	master_service_deinit(&master_service);

	return ret;
}
