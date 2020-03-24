#ifndef TEST_MAIL_INDEX_H
#define TEST_MAIL_INDEX_H

#include "ioloop.h"
#include "unlink-directory.h"
#include "mail-index-private.h"

#define TESTDIR_NAME ".dovecot.test"

static inline struct mail_index *test_mail_index_open(void)
{
	struct mail_index *index;

	index = mail_index_alloc(NULL, TESTDIR_NAME, "test.dovecot.index");
	test_assert(mail_index_open_or_create(index, MAIL_INDEX_OPEN_FLAG_CREATE) == 0);
	return index;
}

static inline struct mail_index *test_mail_index_init(void)
{
	const char *error;

	(void)unlink_directory(TESTDIR_NAME, UNLINK_DIRECTORY_FLAG_RMDIR, &error);
	if (mkdir(TESTDIR_NAME, 0700) < 0)
		i_error("mkdir(%s) failed: %m", TESTDIR_NAME);

	ioloop_time = 1;

	return test_mail_index_open();
}

static inline void test_mail_index_close(struct mail_index **index)
{
	mail_index_close(*index);
	mail_index_free(index);
}

static inline void test_mail_index_delete(void)
{
	const char *error;

	(void)unlink_directory(TESTDIR_NAME, UNLINK_DIRECTORY_FLAG_RMDIR, &error);
}

static inline void test_mail_index_deinit(struct mail_index **index)
{
	test_mail_index_close(index);
	test_mail_index_delete();
}

#endif
