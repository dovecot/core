/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "buffer.h"
#include "write-full.h"
#include "test-common.h"
#include "test-dir.h"
#include "test-corruption.h"
#include "mailbox-log.h"

#include <fcntl.h>
#include <unistd.h>

#define TEST_LOG_FNAME "dovecot.mailbox.log"
/* Number of records that fit into struct mailbox_log_iter.buf[] */
#define TEST_LOG_BUFFER_RECORDS 128

static void
test_log_write(const char *path, unsigned int first_id, unsigned int count,
	       unsigned int partial_bytes)
{
	struct mailbox_log_record rec;
	buffer_t *buf;
	unsigned int i;
	int fd;

	i_assert(partial_bytes < sizeof(rec));

	buf = t_buffer_create(count * sizeof(rec) + partial_bytes);
	for (i = 0; i <= count; i++) {
		i_zero(&rec);
		rec.type = MAILBOX_LOG_RECORD_DELETE_MAILBOX;
		rec.mailbox_guid[0] = (uint8_t)(first_id + i);
		if (i < count)
			buffer_append(buf, &rec, sizeof(rec));
		else
			buffer_append(buf, &rec, partial_bytes);
	}

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		i_fatal("creat(%s) failed: %m", path);
	if (write_full(fd, buf->data, buf->used) < 0)
		i_fatal("write(%s) failed: %m", path);
	i_close_fd(&fd);
}

static void
test_log_iter_verify(const char *path, const uint8_t *ids, unsigned int count)
{
	struct mailbox_log *log;
	struct mailbox_log_iter *iter;
	const struct mailbox_log_record *rec;
	unsigned int i = 0;

	log = mailbox_log_alloc(NULL, path);
	iter = mailbox_log_iter_init(log);
	while ((rec = mailbox_log_iter_next(iter)) != NULL) {
		if (i < count) {
			test_assert_idx(rec->type ==
					MAILBOX_LOG_RECORD_DELETE_MAILBOX, i);
			test_assert_idx(rec->mailbox_guid[0] == ids[i], i);
		}
		if (++i > count) {
			/* iteration isn't stopping - don't loop forever */
			break;
		}
	}
	test_assert(i == count);
	test_assert(mailbox_log_iter_deinit(&iter) == 0);
	mailbox_log_free(&log);
}

static void test_log_unlink(const char *path)
{
	i_unlink_if_exists(path);
	i_unlink_if_exists(t_strconcat(path, ".2", NULL));
}

static void test_mailbox_log_iter(void)
{
	uint8_t ids[3] = { 1, 2, 3 };
	const char *path;

	test_begin("mailbox log iter");
	path = test_dir_prepend(TEST_LOG_FNAME);

	test_log_write(path, 1, N_ELEMENTS(ids), 0);
	test_log_iter_verify(path, ids, N_ELEMENTS(ids));

	test_log_unlink(path);
	test_end();
}

static void test_mailbox_log_iter_partial_record(void)
{
	uint8_t ids[TEST_LOG_BUFFER_RECORDS];
	const char *path;
	unsigned int i;

	test_begin("mailbox log iter partial record");
	path = test_dir_prepend(TEST_LOG_FNAME);
	for (i = 0; i < N_ELEMENTS(ids); i++)
		ids[i] = (uint8_t)(i + 1);

	/* partial record within the first read */
	test_log_write(path, 1, 3, 10);
	test_log_iter_verify(path, ids, 3);

	/* the file contains only a partial record */
	test_log_write(path, 1, 0, 10);
	test_log_iter_verify(path, ids, 0);

	/* partial record at the read buffer boundary */
	test_log_write(path, 1, N_ELEMENTS(ids), 10);
	test_log_iter_verify(path, ids, N_ELEMENTS(ids));

	test_log_unlink(path);
	test_end();
}

static void test_mailbox_log_iter_rotated(void)
{
	uint8_t ids[4] = { 1, 2, 11, 12 };
	const char *path;

	test_begin("mailbox log iter rotated");
	path = test_dir_prepend(TEST_LOG_FNAME);

	/* the rotated log is iterated first */
	test_log_write(t_strconcat(path, ".2", NULL), 1, 2, 10);
	test_log_write(path, 11, 2, 10);
	test_log_iter_verify(path, ids, N_ELEMENTS(ids));

	test_log_unlink(path);
	test_end();
}

static void test_mailbox_log_iter_all_types(void)
{
	struct mailbox_log *log;
	struct mailbox_log_iter *iter;
	struct mailbox_log_record rec;
	const struct mailbox_log_record *iter_rec;
	enum mailbox_log_record_type type;
	const char *path;

	test_begin("mailbox log iter all types");
	path = test_dir_prepend(TEST_LOG_FNAME);
	test_log_unlink(path);

	log = mailbox_log_alloc(NULL, path);
	for (type = MAILBOX_LOG_RECORD_DELETE_MAILBOX;
	     type <= MAILBOX_LOG_RECORD_CREATE_DIR; type++) {
		i_zero(&rec);
		rec.type = type;
		test_assert(mailbox_log_append(log, &rec) == 0);
	}

	type = MAILBOX_LOG_RECORD_DELETE_MAILBOX;
	iter = mailbox_log_iter_init(log);
	while ((iter_rec = mailbox_log_iter_next(iter)) != NULL) {
		test_assert(iter_rec->type == type);
		type++;
	}
	test_assert(type == MAILBOX_LOG_RECORD_CREATE_DIR + 1);
	test_assert(mailbox_log_iter_deinit(&iter) == 0);
	mailbox_log_free(&log);

	test_log_unlink(path);
	test_end();
}

static failure_callback_t *orig_error_callback;

static void
test_ignore_errors_handler(const struct failure_context *ctx,
			   const char *format, va_list args)
{
	/* Corruption is expected to be logged as errors */
	if (ctx->type == LOG_TYPE_ERROR || ctx->type == LOG_TYPE_WARNING)
		return;
	orig_error_callback(ctx, format, args);
}

static void
test_mailbox_log_corruption_callback(const unsigned char *data, size_t size,
				     const char *path)
{
	struct mailbox_log *log;
	struct mailbox_log_iter *iter;
	struct mailbox_log_record rec;
	int fd;

	test_log_unlink(path);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		i_fatal("creat(%s) failed: %m", path);
	if (write_full(fd, data, size) < 0)
		i_fatal("write(%s) failed: %m", path);
	i_close_fd(&fd);

	log = mailbox_log_alloc(NULL, path);
	for (unsigned int i = 0; i < 2; i++) {
		iter = mailbox_log_iter_init(log);
		while (mailbox_log_iter_next(iter) != NULL) ;
		(void)mailbox_log_iter_deinit(&iter);

		/* appending must work after iterating */
		i_zero(&rec);
		rec.type = MAILBOX_LOG_RECORD_DELETE_MAILBOX;
		test_assert(mailbox_log_append(log, &rec) == 0);
	}
	mailbox_log_free(&log);
}

static void test_mailbox_log_corruption(void)
{
	struct mailbox_log_record rec;
	failure_callback_t *fatal_callback, *info_callback, *debug_callback;
	const struct test_corruption_settings set = {
		.name = "mailbox log",
	};
	enum mailbox_log_record_type type;
	buffer_t *buf;
	const char *path;

	test_begin("mailbox log corruption");
	path = test_dir_prepend(TEST_LOG_FNAME);

	buf = t_buffer_create(256);
	for (type = MAILBOX_LOG_RECORD_DELETE_MAILBOX;
	     type <= MAILBOX_LOG_RECORD_CREATE_DIR; type++) {
		i_zero(&rec);
		rec.type = type;
		rec.mailbox_guid[0] = type;
		mailbox_log_record_set_timestamp(&rec, 1000 + type);
		buffer_append(buf, &rec, sizeof(rec));
	}

	i_get_failure_handlers(&fatal_callback, &orig_error_callback,
			       &info_callback, &debug_callback);
	i_set_error_handler(test_ignore_errors_handler);
	test_corruption_run(&set, buf->data, buf->used,
			    test_mailbox_log_corruption_callback, path);
	i_set_error_handler(orig_error_callback);

	test_log_unlink(path);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mailbox_log_iter,
		test_mailbox_log_iter_partial_record,
		test_mailbox_log_iter_rotated,
		test_mailbox_log_iter_all_types,
		test_mailbox_log_corruption,
		NULL
	};

	test_dir_init("test-mailbox-log");
	return test_run(test_functions);
}
