/* Copyright (c) 2017-2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "path-util.h"
#include "master-service.h"
#include "mail-storage-service.h"
#include "test-mail-storage-common.h"

struct test_mail_storage_ctx *test_mail_storage_init(void)
{
	struct test_mail_storage_ctx *ctx;
	const char *current_dir, *error;
	pool_t pool;

	pool = pool_allocfree_create("test pool");
	ctx = p_new(pool, struct test_mail_storage_ctx, 1);
	ctx->pool = pool;

	if (t_get_working_dir(&current_dir, &error) < 0)
		i_fatal("Failed to get current directory: %s", error);
	ctx->home_root = p_strdup_printf(ctx->pool, "%s/.test-home/",
					 current_dir);

	if (unlink_directory(ctx->home_root, UNLINK_DIRECTORY_FLAG_RMDIR, &error) < 0 &&
	    errno != ENOENT)
		i_warning("unlink_directory(%s) failed: %s", ctx->home_root, error);

	ctx->ioloop = io_loop_create();

	ctx->storage_service = mail_storage_service_init(master_service, NULL,
		MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS |
		MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT |
		MAIL_STORAGE_SERVICE_FLAG_NO_PLUGINS);
	return ctx;
}

void test_mail_storage_deinit(struct test_mail_storage_ctx **_ctx)
{
	struct test_mail_storage_ctx *ctx = *_ctx;
	const char *error;
	mail_storage_service_deinit(&ctx->storage_service);

	*_ctx = NULL;

	if (chdir(ctx->home_root) < 0)
		i_fatal("chdir(%s) failed: %m", ctx->home_root);
	if (chdir("..") < 0)
		i_fatal("chdir(..) failed: %m");

	if (unlink_directory(ctx->home_root, UNLINK_DIRECTORY_FLAG_RMDIR,
			     &error) < 0)
		i_error("unlink_directory(%s) failed: %s", ctx->home_root, error);

	io_loop_destroy(&ctx->ioloop);

	pool_unref(&ctx->pool);
}

void test_mail_storage_init_user(struct test_mail_storage_ctx *ctx,
				 const struct test_mail_storage_settings *set)
{
	const char *username = set->username != NULL ?
		set->username : "testuser";
	const char *error, *home;
	ARRAY_TYPE(const_string) opts;

	home = t_strdup_printf("%s%s", ctx->home_root, username);

	const char *const default_input[] = {
		t_strdup_printf("mail=%s:~/%s", set->driver,
				set->driver_opts == NULL ? "" : set->driver_opts),
		"postmaster_address=postmaster@localhost",
		"namespace=inbox",
		"namespace/inbox/prefix=",
		"namespace/inbox/inbox=yes",
		t_strdup_printf("home=%s/%s", home, username),
	};

	if (unlink_directory(home, UNLINK_DIRECTORY_FLAG_RMDIR, &error) < 0)
		i_error("%s", error);
	i_assert(mkdir_parents(home, S_IRWXU)==0 || errno == EEXIST);

	t_array_init(&opts, 20);
	array_append(&opts, default_input, N_ELEMENTS(default_input));
	if (set->hierarchy_sep != NULL) {
		const char *opt =
			t_strdup_printf("namespace/inbox/separator=%s",
					set->hierarchy_sep);
		array_push_back(&opts, &opt);
	}
	if (set->extra_input != NULL)
		array_append(&opts, set->extra_input,
			     str_array_length(set->extra_input));

	array_append_zero(&opts);
	struct mail_storage_service_input input = {
		.userdb_fields = array_front(&opts),
		.username = username,
		.no_userdb_lookup = TRUE,
		.debug = FALSE,
	};

	if (mail_storage_service_lookup_next(ctx->storage_service, &input,
					     &ctx->user, &error) < 0) {
		 i_fatal("mail_storage_service_lookup_next(%s) failed: %s",
			 username, error);
	}
}

void test_mail_storage_deinit_user(struct test_mail_storage_ctx *ctx)
{
	mail_user_deinit(&ctx->user);
}
