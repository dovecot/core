/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "buffer.h"
#include "write-full.h"
#include "test-common.h"
#include "test-dir.h"
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

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mailbox_log_iter,
		test_mailbox_log_iter_partial_record,
		test_mailbox_log_iter_rotated,
		NULL
	};

	test_dir_init("test-mailbox-log");
	return test_run(test_functions);
}
