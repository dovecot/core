/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "test-common.h"
#include "mail-transaction-log-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-index-modseq.h"

static void test_lookup_seq_range(struct mail_index_view *view ATTR_UNUSED,
				  uint32_t first_uid, uint32_t last_uid,
				  uint32_t *first_seq_r, uint32_t *last_seq_r)
{
	*first_seq_r = first_uid;
	*last_seq_r = last_uid;
}

static void test_mail_index_sync_ext_atomic_inc(void)
{
	struct mail_index_sync_map_ctx ctx;
	struct mail_transaction_ext_atomic_inc u;
	struct mail_index_ext *ext;
	void *ptr;

	test_begin("mail index sync ext atomic inc");

	i_zero(&ctx);
	ctx.view = t_new(struct mail_index_view, 1);
	ctx.view->log_view = t_new(struct mail_transaction_log_view, 1);
	ctx.view->index = t_new(struct mail_index, 1);
	ctx.view->index->fsck_log_head_file_seq = 10; /* silence errors */
	ctx.view->v.lookup_seq_range = test_lookup_seq_range;
	ctx.view->map = t_new(struct mail_index_map, 1);
	ctx.view->map->hdr.next_uid = 2;
	ctx.view->map->hdr.record_size = sizeof(struct mail_index_record) + 16;
	ctx.view->map->rec_map = t_new(struct mail_index_record_map, 1);
	ctx.view->map->rec_map->records =
		t_malloc0(ctx.view->map->hdr.record_size);
	t_array_init(&ctx.view->map->extensions, 4);
	ext = array_append_space(&ctx.view->map->extensions);
	ext->record_offset = sizeof(struct mail_index_record);
	ptr = PTR_OFFSET(ctx.view->map->rec_map->records, ext->record_offset);

	i_zero(&u);
	test_assert(mail_index_sync_ext_atomic_inc(&ctx, &u) == -1);

	u.uid = 2;
	test_assert(mail_index_sync_ext_atomic_inc(&ctx, &u) == -1);

	u.uid = 1;
#define TEST_ATOMIC(_type, _value, _diff, _ret) \
	{ _type *n = ptr; *n = _value; } \
	ctx.cur_ext_record_size = sizeof(_type); \
	u.diff = _diff; \
	test_assert(mail_index_sync_ext_atomic_inc(&ctx, &u) == _ret);

#define TEST_ATOMIC_BLOCK(_type, _max) \
	TEST_ATOMIC(_type, 1, -1, 1); \
	TEST_ATOMIC(_type, 1, -2, -1); \
	TEST_ATOMIC(_type, 0, -1, -1); \
	TEST_ATOMIC(_type, 0, _max, 1); \
	TEST_ATOMIC(_type, 1, _max, -1); \
	TEST_ATOMIC(_type, 0, (_max+1), -1); \
	TEST_ATOMIC(_type, _max, 1, -1); \
	TEST_ATOMIC(_type, _max, -_max, 1); \
	TEST_ATOMIC(_type, _max, -(_max+1), -1);

	TEST_ATOMIC_BLOCK(uint8_t, 255);
	TEST_ATOMIC_BLOCK(uint16_t, 65535);

	ctx.cur_ext_record_size = 5;
	u.diff = 0;
	test_assert(mail_index_sync_ext_atomic_inc(&ctx, &u) == -1);

	i_free(ctx.view->index->need_recreate);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_index_sync_ext_atomic_inc,
		NULL
	};
	return test_run(test_functions);
}
