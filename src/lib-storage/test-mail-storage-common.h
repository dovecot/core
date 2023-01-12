#ifndef TEST_MAIL_STORAGE_H
#define TEST_MAIL_STORAGE_H

#include "mail-storage-private.h"

struct test_mail_storage_ctx {
	pool_t pool;
	struct mail_storage_service_ctx *storage_service;
	struct mail_user *user;
	struct ioloop *ioloop;
	const char *home_root;
};

struct test_mail_storage_settings {
	const char *username;
	const char *driver;
	const char *driver_opts;
	const char *hierarchy_sep;
	const char *const *extra_input;
};

struct test_mail_storage_ctx *test_mail_storage_init(void);
void test_mail_storage_deinit(struct test_mail_storage_ctx **ctx);

void test_mail_storage_init_user(struct test_mail_storage_ctx *ctx,
				 const struct test_mail_storage_settings *set);
void test_mail_storage_deinit_user(struct test_mail_storage_ctx *ctx);

#endif
