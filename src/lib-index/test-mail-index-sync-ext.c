/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "test-common.h"
#include "mail-index-sync-private.h"
#include "mail-index-modseq.h"

#include <stdlib.h>

void mail_index_sync_set_corrupted(struct mail_index_sync_map_ctx *ctx ATTR_UNUSED,
				   const char *fmt ATTR_UNUSED, ...) {}
struct mail_index_map *
mail_index_sync_get_atomic_map(struct mail_index_sync_map_ctx *ctx) { return ctx->view->map; }
uint32_t
mail_index_map_register_ext(struct mail_index_map *map ATTR_UNUSED,
			    const char *name ATTR_UNUSED, uint32_t ext_offset ATTR_UNUSED,
			    const struct mail_index_ext_header *ext_hdr ATTR_UNUSED) { return 0; }
bool mail_index_ext_lookup(struct mail_index *index ATTR_UNUSED,
			   const char *name ATTR_UNUSED,
			   uint32_t *ext_id_r ATTR_UNUSED) { return FALSE; }
bool mail_index_map_lookup_ext(struct mail_index_map *map ATTR_UNUSED,
			       const char *name ATTR_UNUSED,
			       uint32_t *idx_r ATTR_UNUSED) { return FALSE; }
int mail_index_map_ext_hdr_check(const struct mail_index_header *hdr ATTR_UNUSED,
				 const struct mail_index_ext_header *ext_hdr ATTR_UNUSED,
				 const char *name ATTR_UNUSED,
				 const char **error_r ATTR_UNUSED) { return -1; }
void mail_index_modseq_hdr_update(struct mail_index_modseq_sync *ctx ATTR_UNUSED) {}
bool mail_index_lookup_seq(struct mail_index_view *view ATTR_UNUSED,
			   uint32_t uid, uint32_t *seq_r) {
	*seq_r = uid;
	return TRUE;
}
void mail_index_sync_write_seq_update(struct mail_index_sync_map_ctx *ctx ATTR_UNUSED,
				      uint32_t seq1 ATTR_UNUSED,
				      uint32_t seq2 ATTR_UNUSED) {}

static void test_mail_index_sync_ext_atomic_inc(void)
{
	struct mail_index_sync_map_ctx ctx;
	struct mail_transaction_ext_atomic_inc u;
	struct mail_index_ext *ext;
	void *ptr;

	test_begin("mail index sync ext atomic inc");

	memset(&ctx, 0, sizeof(ctx));
	ctx.view = t_new(struct mail_index_view, 1);
	ctx.view->map = t_new(struct mail_index_map, 1);
	ctx.view->map->hdr.next_uid = 2;
	ctx.view->map->hdr.record_size = sizeof(struct mail_index_record) + 16;
	ctx.view->map->rec_map = t_new(struct mail_index_record_map, 1);
	ctx.view->map->rec_map->records =
		t_malloc(ctx.view->map->hdr.record_size);
	t_array_init(&ctx.view->map->extensions, 4);
	ext = array_append_space(&ctx.view->map->extensions);
	ext->record_offset = sizeof(struct mail_index_record);
	ptr = PTR_OFFSET(ctx.view->map->rec_map->records, ext->record_offset);

	memset(&u, 0, sizeof(u));
	test_assert(mail_index_sync_ext_atomic_inc(&ctx, &u) == -1);

	u.uid = 2;
	test_assert(mail_index_sync_ext_atomic_inc(&ctx, &u) == -1);

	u.uid = 1;
#define TEST_ATOMIC(_type, _value, _diff, _ret) \
	{ _type *n = ptr; *n = _value; } \
	ext->record_size = sizeof(_type); \
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

	ext->record_size = 5;
	u.diff = 0;
	test_assert(mail_index_sync_ext_atomic_inc(&ctx, &u) == -1);

	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_mail_index_sync_ext_atomic_inc,
		NULL
	};
	return test_run(test_functions);
}
