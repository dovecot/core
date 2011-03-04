/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "test-common.h"
#include "mail-index-private.h"
#include "mail-transaction-log-view-private.h"

static struct mail_transaction_log *log;
static struct mail_transaction_log_view *view;

void mail_transaction_log_file_set_corrupted(struct mail_transaction_log_file *file ATTR_UNUSED,
					     const char *fmt ATTR_UNUSED, ...)
{
}

void mail_transaction_logs_clean(struct mail_transaction_log *log ATTR_UNUSED)
{
}

int mail_transaction_log_find_file(struct mail_transaction_log *log,
				   uint32_t file_seq, bool nfs_flush ATTR_UNUSED,
				   struct mail_transaction_log_file **file_r)
{
	struct mail_transaction_log_file *file;

	for (file = log->files; file != NULL; file = file->next) {
		if (file->hdr.file_seq == file_seq) {
			*file_r = file;
			return 1;
		}
	}
	return 0;
}

int mail_transaction_log_file_map(struct mail_transaction_log_file *file ATTR_UNUSED,
				  uoff_t start_offset ATTR_UNUSED, uoff_t end_offset ATTR_UNUSED)
{
	return 1;
}

int mail_transaction_log_file_get_highest_modseq_at(
		struct mail_transaction_log_file *file ATTR_UNUSED,
		uoff_t offset ATTR_UNUSED, uint64_t *highest_modseq_r)
{
	*highest_modseq_r = 0;
	return 0;
}

void mail_transaction_update_modseq(const struct mail_transaction_header *hdr ATTR_UNUSED,
				    const void *data ATTR_UNUSED,
				    uint64_t *cur_modseq)
{
	*cur_modseq += 1;
}

static void
test_transaction_log_file_add(uint32_t file_seq)
{
	struct mail_transaction_log_file **p, *file;

	file = i_new(struct mail_transaction_log_file, 1);
	file->hdr.file_seq = file_seq;
	file->hdr.hdr_size = file->sync_offset = sizeof(file->hdr);
	file->hdr.prev_file_seq = file_seq - 1;
	file->log = log;
	file->fd = -1;
	file->buffer = buffer_create_dynamic(default_pool, 256);
	file->buffer_offset = file->hdr.hdr_size;

	/* files must be sorted by file_seq */
	for (p = &log->files; *p != NULL; p = &(*p)->next) {
		if ((*p)->hdr.file_seq > file->hdr.file_seq)
			break;
	}
	*p = file;
	log->head = file;
}

static bool view_is_file_refed(uint32_t file_seq)
{
	struct mail_transaction_log_file *const *files;
	unsigned int i, count;
	bool ret = FALSE;

	files = array_get(&view->file_refs, &count);
	for (i = 0; i < count; i++) {
		if (files[i]->hdr.file_seq == file_seq) {
			i_assert(!ret); /* could be a test too.. */
			ret = TRUE;
		}
	}
	return ret;
}

static size_t
add_append_record(struct mail_transaction_log_file *file,
		  const struct mail_index_record *rec)
{
	struct mail_transaction_header hdr;
	size_t size;

	memset(&hdr, 0, sizeof(hdr));
	hdr.type = MAIL_TRANSACTION_APPEND | MAIL_TRANSACTION_EXTERNAL;
	hdr.size = mail_index_uint32_to_offset(sizeof(hdr) + sizeof(*rec));

	buffer_append(file->buffer, &hdr, sizeof(hdr));
	buffer_append(file->buffer, rec, sizeof(*rec));

	size = sizeof(hdr) + sizeof(*rec);
	file->sync_offset += size;
	return size;
}

static void test_mail_transaction_log_view(void)
{
	const struct mail_transaction_header *hdr;
	const struct mail_index_record *rec;
	struct mail_index_record append_rec;
	const void *data;
	uint32_t seq;
	uoff_t offset, last_log_size;
	bool reset;

	test_begin("init");
	log = i_new(struct mail_transaction_log, 1);
	log->index = i_new(struct mail_index, 1);
	log->index->log = log;
	log->index->log_sync_locked = TRUE;
	test_transaction_log_file_add(1);
	test_transaction_log_file_add(2);
	test_transaction_log_file_add(3);

	/* add an append record to the 3rd log file */
	memset(&append_rec, 0, sizeof(append_rec));
	append_rec.uid = 1;

	last_log_size = sizeof(struct mail_transaction_log_header) +
		add_append_record(log->head, &append_rec);

	view = mail_transaction_log_view_open(log);
	i_assert(view != NULL);
	test_assert(log->views == view &&
		    !view_is_file_refed(1) && !view_is_file_refed(2) &&
		    view_is_file_refed(3));
	test_end();

	/* we have files 1-3 opened */
	test_begin("set all");
	test_assert(mail_transaction_log_view_set(view, 0, 0, (uint32_t)-1, (uoff_t)-1, &reset) == 1 &&
		    reset && view_is_file_refed(1) && view_is_file_refed(2) &&
		    view_is_file_refed(3) &&
		    !mail_transaction_log_view_is_corrupted(view));
	mail_transaction_log_view_get_prev_pos(view, &seq, &offset);
	test_assert(seq == 1 && offset == sizeof(struct mail_transaction_log_header));
	test_assert(mail_transaction_log_view_next(view, &hdr, &data) == 1);
	test_assert(hdr->type == (MAIL_TRANSACTION_APPEND | MAIL_TRANSACTION_EXTERNAL));
	rec = data;
	test_assert(memcmp(rec, &append_rec, sizeof(*rec)) == 0);
	test_assert(mail_transaction_log_view_next(view, &hdr, &data) == 0);
	test_assert(mail_transaction_log_view_is_last(view));
	mail_transaction_log_view_get_prev_pos(view, &seq, &offset);
	test_assert(seq == 3 && offset == last_log_size);
	test_end();

	test_begin("set first");
	test_assert(mail_transaction_log_view_set(view, 0, 0, 0, 0, &reset) == 1);
	mail_transaction_log_view_get_prev_pos(view, &seq, &offset);
	test_assert(seq == 1 && offset == sizeof(struct mail_transaction_log_header));
	test_assert(mail_transaction_log_view_next(view, &hdr, &data) == 0);
	mail_transaction_log_view_get_prev_pos(view, &seq, &offset);
	test_assert(seq == 1 && offset == sizeof(struct mail_transaction_log_header));
	test_end();

	test_begin("set end");
	test_assert(mail_transaction_log_view_set(view, 3, last_log_size, (uint32_t)-1, (uoff_t)-1, &reset) == 1);
	mail_transaction_log_view_get_prev_pos(view, &seq, &offset);
	test_assert(seq == 3 && offset == last_log_size);
	test_assert(mail_transaction_log_view_next(view, &hdr, &data) == 0);
	mail_transaction_log_view_get_prev_pos(view, &seq, &offset);
	test_assert(seq == 3 && offset == last_log_size);
	test_end();

	test_begin("log clear");
	mail_transaction_log_view_clear(view, 2);
	test_assert(!view_is_file_refed(1) && view_is_file_refed(2) &&
		    view_is_file_refed(3));
	log->files = log->files->next;
	test_assert(log->files->hdr.file_seq == 2);
	test_end();

	/* --- first file has been removed --- */

	test_begin("set 2-3");
	test_assert(mail_transaction_log_view_set(view, 2, 0, (uint32_t)-1, (uoff_t)-1, &reset) == 1);
	test_end();

	test_begin("missing log handing");
	test_assert(mail_transaction_log_view_set(view, 0, 0, (uint32_t)-1, (uoff_t)-1, &reset) == 0);
	test_end();

	test_begin("closed log handling");
	view->log = NULL;
	test_assert(mail_transaction_log_view_set(view, 0, 0, (uint32_t)-1, (uoff_t)-1, &reset) == -1);
	view->log = log;
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_mail_transaction_log_view,
		NULL
	};
	return test_run(test_functions);
}
