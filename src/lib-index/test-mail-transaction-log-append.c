/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "test-common.h"
#include "mail-index-private.h"
#include "mail-transaction-log-private.h"

#include <stdlib.h>
#include <sys/stat.h>

static bool log_lock_failure = FALSE;

int mail_index_file_set_syscall_error(struct mail_index *index ATTR_UNUSED,
				      const char *filepath ATTR_UNUSED,
				      const char *function ATTR_UNUSED)
{
	return -1;
}

int mail_transaction_log_lock_head(struct mail_transaction_log *log ATTR_UNUSED)
{
	return log_lock_failure ? -1 : 0;
}

void mail_transaction_log_file_unlock(struct mail_transaction_log_file *file ATTR_UNUSED) {}

void mail_transaction_update_modseq(const struct mail_transaction_header *hdr,
				    const void *data ATTR_UNUSED,
				    uint64_t *cur_modseq)
{
	if ((hdr->type & MAIL_TRANSACTION_EXPUNGE) != 0)
		*cur_modseq += 1;
}

int mail_index_move_to_memory(struct mail_index *index ATTR_UNUSED)
{
	return -1;
}

static void test_append_expunge(struct mail_transaction_log *log)
{
	static unsigned int buf[] = { 0x12345678, 0xabcdef09 };
	struct mail_transaction_log_file *file = log->head;
	struct mail_transaction_log_append_ctx *ctx;
	const struct mail_transaction_header *hdr;
	const unsigned int *bufp;

	test_assert(mail_transaction_log_append_begin(log->index, TRUE, &ctx) == 0);
	mail_transaction_log_append_add(ctx, MAIL_TRANSACTION_APPEND,
					&buf[0], sizeof(buf[0]));
	test_assert(ctx->new_highest_modseq == 0);
	mail_transaction_log_append_add(ctx, MAIL_TRANSACTION_EXPUNGE,
					&buf[1], sizeof(buf[1]));
	test_assert(ctx->new_highest_modseq == 1);

	test_assert(mail_transaction_log_append_commit(&ctx) == 0);
	test_assert(file->sync_highest_modseq == 1);
	test_assert(file->sync_offset == file->buffer_offset + file->buffer->used);

	hdr = file->buffer->data;
	test_assert(hdr->type == (MAIL_TRANSACTION_APPEND |
				  MAIL_TRANSACTION_EXTERNAL));
	test_assert(mail_index_offset_to_uint32(hdr->size) == sizeof(*hdr) + sizeof(buf[0]));
	bufp = (const void *)(hdr + 1);
	test_assert(*bufp == buf[0]);

	hdr = (const void *)(bufp + 1);
	test_assert(hdr->type == (MAIL_TRANSACTION_EXPUNGE |
				  MAIL_TRANSACTION_EXPUNGE_PROT |
				  MAIL_TRANSACTION_EXTERNAL));
	test_assert(mail_index_offset_to_uint32(hdr->size) == sizeof(*hdr) + sizeof(buf[0]));
	bufp = (const void *)(hdr + 1);
	test_assert(*bufp == buf[1]);

	test_assert(file->buffer->used == (size_t)((const char *)(bufp+1) - (const char *)file->buffer->data));

	buffer_set_used_size(file->buffer, 0);
	file->buffer_offset = 0;
	test_end();
}

static void test_append_sync_offset(struct mail_transaction_log *log)
{
	struct mail_transaction_log_file *file = log->head;
	struct mail_transaction_log_append_ctx *ctx;
	const struct mail_transaction_header *hdr;
	const struct mail_transaction_header_update *u;
	const uint32_t *offsetp;

	test_begin("transaction log append: append_sync_offset only");
	test_assert(mail_transaction_log_append_begin(log->index, FALSE, &ctx) == 0);
	ctx->append_sync_offset = TRUE;
	file->max_tail_offset = 123;
	test_assert(mail_transaction_log_append_commit(&ctx) == 0);

	test_assert(file->buffer->used == sizeof(*hdr) + sizeof(*u) + sizeof(*offsetp));
	hdr = file->buffer->data;
	test_assert(hdr->type == MAIL_TRANSACTION_HEADER_UPDATE);
	test_assert(mail_index_offset_to_uint32(hdr->size) == file->buffer->used);
	u = (const void *)(hdr + 1);
	test_assert(u->offset == offsetof(struct mail_index_header, log_file_tail_offset));
	test_assert(u->size == sizeof(*offsetp));
	offsetp = (const void *)(u+1);
	test_assert(*offsetp == 123);

	test_end();
}

static void test_mail_transaction_log_append(void)
{
	struct mail_transaction_log *log;
	struct mail_transaction_log_file *file;
	struct mail_transaction_log_append_ctx *ctx;
	char tmp_path[] = "/tmp/dovecot.test.XXXXXX";
	struct stat st;
	int fd;

	fd = mkstemp(tmp_path);
	if (fd == -1)
		i_fatal("mkstemp(%s) failed: %m", tmp_path);

	test_begin("transaction log append");
	log = i_new(struct mail_transaction_log, 1);
	log->index = i_new(struct mail_index, 1);
	log->index->log = log;
	log->head = file = i_new(struct mail_transaction_log_file, 1);
	file->fd = -1;

	test_append_expunge(log);

	test_begin("transaction log append: lock failure");
	log_lock_failure = TRUE;
	test_assert(mail_transaction_log_append_begin(log->index, FALSE, &ctx) < 0);
	log_lock_failure = FALSE;
	test_end();

	test_append_sync_offset(log);

	/* do this after head->buffer has already been initialized */
	test_begin("transaction log append: garbage truncation");
	file->sync_offset = 1;
	file->buffer_offset = 1;
	file->last_size = 3;
	file->fd = fd;
	test_assert(mail_transaction_log_append_begin(log->index, FALSE, &ctx) == 0);
	test_assert(mail_transaction_log_append_commit(&ctx) == 0);
	if (fstat(fd, &st) < 0) i_fatal("fstat() failed: %m");
	test_assert(st.st_size == 1);
	file->fd = -1;
	test_end();

	unlink(tmp_path);
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_mail_transaction_log_append,
		NULL
	};
	return test_run(test_functions);
}
