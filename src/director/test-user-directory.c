/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "mail-user-hash.h"
#include "mail-host.h"
#include "user-directory.h"
#include "test-common.h"

#include <stdlib.h>

#define USER_DIR_TIMEOUT 1000000

unsigned int mail_user_hash(const char *username ATTR_UNUSED,
			    const char *format ATTR_UNUSED) { return 0; }

static void
verify_user_directory(struct user_directory *dir, unsigned int user_count)
{
	struct user_directory_iter *iter;
	struct user *user, *prev = NULL;
	unsigned int prev_stamp = 0, iter_count = 0;

	iter = user_directory_iter_init(dir);
	while ((user = user_directory_iter_next(iter)) != NULL) {
		test_assert(prev_stamp <= user->timestamp);
		test_assert(user->prev == prev);
		test_assert(prev == NULL || user->prev->next == user);

		iter_count++;
		prev = user;
	}
	test_assert(prev == NULL || prev->next == NULL);
	user_directory_iter_deinit(&iter);
	test_assert(iter_count == user_count);
}

static void test_user_directory_ascending(void)
{
	const unsigned int count = 100000;
	struct user_directory *dir;
	struct mail_host *host = t_new(struct mail_host, 1);
	unsigned int i;

	test_begin("user directory ascending");
	dir = user_directory_init(USER_DIR_TIMEOUT, "%u");
	user_directory_add(dir, 1, host, ioloop_time + count+1);

	for (i = 0; i < count; i++)
		user_directory_add(dir, i+2, host, ioloop_time + i);
	verify_user_directory(dir, count+1);
	user_directory_deinit(&dir);
	test_end();
}

static void test_user_directory_descending(void)
{
	const unsigned int count = 1000;
	struct user_directory *dir;
	struct mail_host *host = t_new(struct mail_host, 1);
	unsigned int i;

	test_begin("user directory descending");
	dir = user_directory_init(USER_DIR_TIMEOUT, "%u");

	for (i = 0; i < count; i++)
		user_directory_add(dir, i+1, host, ioloop_time - i);
	verify_user_directory(dir, count);
	user_directory_deinit(&dir);
	test_end();
}

static void test_user_directory_random(void)
{
	struct user_directory *dir;
	struct mail_host *host = t_new(struct mail_host, 1);
	time_t timestamp;
	unsigned int i, count = 10000 + rand()%10000;

	test_begin("user directory random");
	dir = user_directory_init(USER_DIR_TIMEOUT, "%u");
	for (i = 0; i < count; i++) {
		if (rand() % 10 == 0)
			timestamp = ioloop_time;
		else
			timestamp = ioloop_time-rand()%100;
		user_directory_add(dir, i+1, host, timestamp);
	}
	verify_user_directory(dir, count);
	user_directory_deinit(&dir);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_user_directory_ascending,
		test_user_directory_descending,
		test_user_directory_random,
		NULL
	};
	ioloop_time = 1234567890;
	return test_run(test_functions);
}
