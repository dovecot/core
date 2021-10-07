/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "mail-index-private.h"
#include "mail-transaction-log-private.h"

#define TEST_INDEX_FNAME ".test.index.write"
#define TEST_INDEXID 123456
#define LOG_FILE1_HEAD_OFFSET 200

static bool expect_index_rewrite;
static bool rotate_fail;

static struct mail_transaction_log_file log_file = {
	.hdr = {
		.indexid = TEST_INDEXID,
		.file_seq = 1,
	},
};
static struct mail_transaction_log_file log_file2 = {
	.hdr = {
		.indexid = TEST_INDEXID,
		.file_seq = 2,
		.prev_file_seq = 1,
		.prev_file_offset = LOG_FILE1_HEAD_OFFSET,
	},
};

void mail_index_set_error(struct mail_index *index ATTR_UNUSED,
			  const char *fmt ATTR_UNUSED, ...)
{
}

void mail_index_set_syscall_error(struct mail_index *index ATTR_UNUSED,
				  const char *function)
{
	i_error("%s() failed: %m", function);
}

void mail_index_file_set_syscall_error(struct mail_index *index ATTR_UNUSED,
				       const char *filepath,
				       const char *function)
{
	i_error("%s(%s) failed: %m", function, filepath);
}

int mail_index_create_tmp_file(struct mail_index *index ATTR_UNUSED,
			       const char *path_prefix, const char **path_r)
{
	const char *path;
	int fd;

	test_assert(expect_index_rewrite);

	path = *path_r = t_strconcat(path_prefix, ".tmp", NULL);
	fd = open(path, O_RDWR|O_CREAT, 0600);
	if (fd == -1) {
		i_error("creat() failed: %m");
		return -1;
	}
	return fd;
}

int mail_index_move_to_memory(struct mail_index *index ATTR_UNUSED)
{
	return -1;
}

int mail_transaction_log_rotate(struct mail_transaction_log *log, bool reset)
{
	i_assert(!reset);

	if (rotate_fail)
		return -1;

	log_file.next = &log_file2;
	log->head = &log_file2;
	return 0;
}

static void test_mail_index_write(void)
{
	struct mail_transaction_log log = {
		.head = &log_file,
		.files = &log_file,
	};
	struct mail_index_record_map rec_map = {
		.records_count = 0,
	};
	buffer_t hdr_copy;
	struct mail_index_map map = {
		.hdr = {
			.indexid = TEST_INDEXID,
			.log_file_seq = 1,
			.log_file_tail_offset = 100,
			.log_file_head_offset = LOG_FILE1_HEAD_OFFSET,
		},
		.hdr_copy_buf = &hdr_copy,
		.rec_map = &rec_map,
	};
	buffer_create_from_const_data(&hdr_copy, &map.hdr, sizeof(map.hdr));
	struct mail_index index = {
		.event = event_create(NULL),
		.log = &log,
		.map = &map,
		.dir = ".",
		.fd = -1,
		.indexid = TEST_INDEXID,
		.filepath = TEST_INDEX_FNAME,
		.log_sync_locked = TRUE,
	};

	test_begin("test_mail_index_write()");

	/* test failed rotation, no index rewrite */
	rotate_fail = TRUE;
	expect_index_rewrite = FALSE;
	test_assert(!index.reopen_main_index);
	index.fd = 1; /* anything but -1 */
	mail_index_write(&index, TRUE, "testing");
	test_assert(log.head == log.files);
	test_assert(index.reopen_main_index);

	/* test failed rotation, with index rewrite */
	expect_index_rewrite = TRUE;
	index.reopen_main_index = FALSE;
	index.fd = -1;
	mail_index_write(&index, TRUE, "testing");
	test_assert(log.head == log.files);
	test_assert(!index.reopen_main_index);

	/* test successful rotation, with index rewrite */
	rotate_fail = FALSE;
	mail_index_write(&index, TRUE, "testing");
	test_assert(log.head != log.files && log.head == &log_file2);
	test_assert(!index.reopen_main_index);

	event_unref(&index.event);
	i_unlink(TEST_INDEX_FNAME);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_index_write,
		NULL
	};
	return test_run(test_functions);
}
